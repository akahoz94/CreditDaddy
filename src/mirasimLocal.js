/**
 * mirasim（原生 AI 编程开发环境）本机凭据与切号引擎。
 *
 * 凭据存储：
 *   ~/.mirasim/setting.json        auth: { token, refreshToken, userId, name, exp }（mrs1: 加密）
 *   ~/.mirasim/secret.key          DPAPI 加密的 master key（Windows 上是 hex 字符串）
 *
 * 加密格式：
 *   mrs1:<base64(12B IV + 16B tag + ciphertext)>，AES-256-GCM，
 *   key = DPAPI Unprotect(secret.key) → utf16le 字符串（64 字符 hex）→ Buffer
 *
 * 账号切换：
 *   - mirasim 正在运行时可提示或强制退出
 *   - 切换前先把当前登录同步进 CreditDaddy 账号库（防丢号）
 *   - 将目标账号的 auth 替换写回 setting.json（保留其他所有配置，如 models、workspaces 等）
 *   - 桌面端切号成功后可一键拉起 Mirasim.exe
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFile, execFileSync, execSync } from 'node:child_process';

const ENC_PREFIX = 'mrs1:';

export function mirasimHome() {
  return process.env.MIRASIM_HOME || path.join(os.homedir(), '.mirasim');
}

export function mirasimPaths() {
  const h = mirasimHome();
  return {
    home: h,
    setting: path.join(h, 'setting.json'),
    secretKey: path.join(h, 'secret.key'),
    insights: path.join(h, 'insights'),
  };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function atomicWriteJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${crypto.randomUUID()}`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmp, file);
}

// ── DPAPI 解密 master key ──

let masterKeyCache = null;

function persistMasterKey(paths, key) {
  try {
    fs.mkdirSync(paths.home, { recursive: true, mode: 0o700 });
    if (process.platform === 'win32') {
      const script = 'Add-Type -AssemblyName System.Security;'
        + '$b=[Convert]::FromBase64String([Console]::In.ReadToEnd());'
        + "[Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))";
      const encoded = Buffer.from(script, 'utf16le').toString('base64');
      const encrypted = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
        input: Buffer.from(key.toString('hex'), 'utf16le').toString('base64'), windowsHide: true, timeout: 15_000, encoding: 'utf8',
      }).trim();
      fs.writeFileSync(paths.secretKey, Buffer.from(encrypted, 'base64').toString('hex'), { mode: 0o600 });
    } else {
      fs.writeFileSync(paths.secretKey, key.toString('hex'), { mode: 0o600 });
    }
    return true;
  } catch { return false; }
}

function readEnvironmentMasterKey() {
  const value = process.env.MIRASIM_SECRET_KEY || process.env.MIRASIM_APP_SECRET_KEY;
  if (!value) return null;
  const hex = value.trim();
  if (!/^[0-9a-f]{64}$/i.test(hex)) return null;
  masterKeyCache = Buffer.from(hex, 'hex');
  return masterKeyCache;
}

function dpapiUnprotect(buf) {
  const script = 'Add-Type -AssemblyName System.Security;'
    + '$b=[Convert]::FromBase64String([Console]::In.ReadToEnd());'
    + "[Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser'))";
  // 使用 -EncodedCommand 传入 UTF-16LE Base64，避免命令行参数中包含敏感 API 关键字被杀毒软件误报
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  return new Promise((resolve, reject) => {
    const child = execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { windowsHide: true, timeout: 15_000 }, (err, stdout) => {
        if (err) return reject(new Error('DPAPI 解密失败：' + err.message));
        resolve(Buffer.from(String(stdout).trim(), 'base64'));
      });
    child.stdin.end(buf.toString('base64'));
  });
}

/** 取得解开后的 32 字节 master key Buffer（未配置或解密失败返回 null） */
export async function getMasterKey() {
  const p = mirasimPaths();
  // 客户端可能在进程内沿用已缓存的密钥：磁盘文件被删除时，仍可用缓存解密，
  // 并将密钥原样写回，修复「setting.json 是 mrs1:、secret.key 缺失」的状态。
  if (masterKeyCache) {
    if (!fs.existsSync(p.secretKey)) persistMasterKey(p, masterKeyCache);
    return masterKeyCache;
  }
  if (!fs.existsSync(p.secretKey)) return readEnvironmentMasterKey();

  try {
    const raw = fs.readFileSync(p.secretKey, 'utf8').trim();
    if (process.platform === 'win32') {
      const bin = /^[0-9a-f]+$/i.test(raw) ? Buffer.from(raw, 'hex') : Buffer.from(raw, 'base64');
      const unprotected = await dpapiUnprotect(bin);
      // Windows 存放的是 utf16le 编码的 64 字符 hex 密钥
      const hex = unprotected.toString('utf16le').trim();
      if (/^[0-9a-f]{64}$/i.test(hex)) {
        masterKeyCache = Buffer.from(hex, 'hex');
        return masterKeyCache;
      }
      if (/^[0-9a-f]{64}$/i.test(unprotected.toString('utf8').trim())) {
        masterKeyCache = Buffer.from(unprotected.toString('utf8').trim(), 'hex');
        return masterKeyCache;
      }
    } else {
      // macOS / Linux 下如果有直接存 hex 或钥匙串导出
      if (/^[0-9a-f]{64}$/i.test(raw)) {
        masterKeyCache = Buffer.from(raw, 'hex');
        return masterKeyCache;
      }
    }
  } catch {}
  return null;
}

export function isEncrypted(v) {
  return typeof v === 'string' && v.startsWith(ENC_PREFIX);
}

/** 解密 mrs1: 字符串 */
export function decryptWithKey(value, key) {
  if (!isEncrypted(value)) return value;
  if (!key) throw new Error('缺少 mirasim master key，无法解密');
  const raw = Buffer.from(value.slice(ENC_PREFIX.length), 'base64');
  if (raw.length < 28) throw new Error('mrs1 格式长度不正确');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const ct = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/** 加密成 mrs1: 字符串（切号写回时保证与客户端格式一致） */
export function encryptWithKey(plain, key) {
  if (!key) return plain;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ENC_PREFIX + Buffer.concat([iv, tag, ct]).toString('base64');
}

// ── 本机探测 ──

export function detectMirasim() {
  const p = mirasimPaths();
  const exists = fs.existsSync(p.setting);
  let signedIn = false;
  if (exists) {
    const s = readJson(p.setting);
    signedIn = Boolean(s && s.auth && (s.auth.token || s.auth.userId));
  }
  const clientPath = candidateClientPath();
  return {
    dataDir: p.home,
    exists,
    signedIn,
    clientInstalled: Boolean(clientPath),
    clientPath,
    running: mirasimRunning(),
  };
}

export function candidateClientPath() {
  const home = os.homedir();
  if (process.platform === 'win32') {
    const local = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    const p1 = path.join(local, 'Programs', '@mirasimdesktop', 'Mirasim.exe');
    if (fs.existsSync(p1)) return p1;
    const p2 = path.join(process.env.ProgramFiles || 'C:\\Program Files', '@mirasimdesktop', 'Mirasim.exe');
    if (fs.existsSync(p2)) return p2;
  } else if (process.platform === 'darwin') {
    const p = '/Applications/Mirasim.app/Contents/MacOS/Mirasim';
    if (fs.existsSync(p)) return p;
  }
  return null;
}

export function mirasimRunning() {
  if (process.platform !== 'win32') return false;
  try {
    const out = execSync('tasklist /FI "IMAGENAME eq Mirasim.exe" /NH', { windowsHide: true, encoding: 'utf8' });
    return /mirasim\.exe/i.test(out);
  } catch { return false; }
}

const nap = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

export function terminateMirasim({ timeoutMs = 8000 } = {}) {
  if (process.platform !== 'win32') return { closed: false, supported: false };
  if (!mirasimRunning()) return { closed: false, running: false };
  try { execSync('taskkill /IM Mirasim.exe /T', { windowsHide: true, stdio: 'ignore' }); } catch {}
  let deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline && mirasimRunning()) nap(250);
  if (mirasimRunning()) {
    try { execSync('taskkill /IM Mirasim.exe /T /F', { windowsHide: true, stdio: 'ignore' }); } catch {}
    deadline = Date.now() + 3000;
    while (Date.now() < deadline && mirasimRunning()) nap(250);
  }
  return { closed: !mirasimRunning(), running: mirasimRunning() };
}

// ── 当前会话读取与切换 ──

/** 读取当前登录的 mirasim 账号，返回标准化账号对象（供 addAccount / scan） */
export async function liveToAccount() {
  const p = mirasimPaths();
  const s = readJson(p.setting);
  if (!s || !s.auth || !s.auth.token) return null;

  const key = await getMasterKey();
  let token = s.auth.token;
  let refreshToken = s.auth.refreshToken;
  if (isEncrypted(token)) {
    if (!key) {
      // 明确区分「密钥缺失」和「解密失败」两种状态，方便用户理解并设置环境变量
      const envName = process.platform === 'win32' ? 'MIRASIM_SECRET_KEY' : 'MIRASIM_APP_SECRET_KEY';
      const hint = `未找到 ${p.secretKey}，请先完整重启 Mirasim 客户端生成；或临时设置环境变量 ${envName} 绕过`;
      const err = new Error(hint);
      err.code = 'MISSING_SECRET_KEY';
      throw err;
    }
    try {
      token = decryptWithKey(token, key);
      refreshToken = refreshToken ? decryptWithKey(refreshToken, key) : null;
    } catch (e) {
      const err = new Error(`解密凭据失败：${e.message}`);
      err.code = 'DECRYPT_FAILED';
      throw err;
    }
  }

  const userId = s.auth.userId || (token.includes('.') ? (() => {
    try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')).sub; } catch { return null; }
  })() : null);

  const expiresAt = s.auth.exp ? new Date(s.auth.exp * 1000).toISOString() : null;

  return {
    provider: 'mirasim',
    token,
    refreshToken,
    uid: userId,
    name: s.auth.name || null,
    expiresAt,
    source: 'local-app',
    meta: {
      encryptedAuth: s.auth, // 原始密文备份，切换时可原样写回
      capturedAt: new Date().toISOString(),
    },
  };
}

export function currentMirasimUid() {
  const p = mirasimPaths();
  const s = readJson(p.setting);
  return s?.auth?.userId || null;
}

/**
 * 把刷新后的凭据写回 ~/.mirasim/setting.json（仅当该账号正是客户端当前登录时调用，
 * 避免 mirasim 客户端拿着被轮换掉的旧 token 掉线）。保留 setting.json 其余字段原样。
 * @returns {boolean} 是否发生了写回
 */
export async function writeMirasimAuth(account) {
  const p = mirasimPaths();
  const s = readJson(p.setting);
  if (!s || !s.auth) return false;
  if (!account?.uid || s.auth.userId !== account.uid) return false;
  const key = await getMasterKey();
  const enc = (v) => (key ? encryptWithKey(String(v), key) : String(v));
  s.auth = {
    ...s.auth,
    token: enc(account.token),
    refreshToken: account.refreshToken ? enc(account.refreshToken) : s.auth.refreshToken,
    exp: account.expiresAt ? Math.floor(new Date(account.expiresAt).getTime() / 1000) : s.auth.exp,
  };
  atomicWriteJson(p.setting, s);
  return true;
}

/**
 * 切换 mirasim 当前登录账号
 * @param {object} account 目标账号
 * @param {{ force?: boolean }} opts
 */
export async function switchTo(account, { force = false } = {}) {
  const p = mirasimPaths();
  const s = readJson(p.setting) || {};
  const currentUid = s.auth?.userId || null;
  if (account.uid && currentUid && account.uid === currentUid) {
    return { switched: false, alreadyActive: true };
  }

  if (!force && mirasimRunning()) {
    const err = new Error('Mirasim 客户端正在运行，请先退出后再切换（或强制切换，切换后将自动重新拉起客户端）');
    err.mirasimRunning = true;
    throw err;
  }

  const key = await getMasterKey();
  let authToWrite = null;

  if (account.meta?.encryptedAuth) {
    // 优先原样使用抓取到的加密密文
    authToWrite = account.meta.encryptedAuth;
  } else if (key) {
    // 新增或从外部导入的账号：使用当前 master key 加密写回
    authToWrite = {
      token: encryptWithKey(account.token, key),
      refreshToken: account.refreshToken ? encryptWithKey(account.refreshToken, key) : null,
      userId: account.uid,
      name: account.name || null,
      exp: account.expiresAt ? Math.floor(new Date(account.expiresAt).getTime() / 1000) : null,
    };
  } else {
    // 没有 master key 时明文写入（mirasim 支持 unencrypted fallback）
    authToWrite = {
      token: account.token,
      refreshToken: account.refreshToken || null,
      userId: account.uid,
      name: account.name || null,
      exp: account.expiresAt ? Math.floor(new Date(account.expiresAt).getTime() / 1000) : null,
    };
  }

  s.auth = authToWrite;
  atomicWriteJson(p.setting, s);
  return { switched: true, alreadyActive: false };
}
