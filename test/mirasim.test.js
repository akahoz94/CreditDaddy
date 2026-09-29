import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const MHOME = fs.mkdtempSync(path.join(os.tmpdir(), 'mirasim-test-'));
process.env.MIRASIM_HOME = MHOME;
process.env.MIRASIM_DESKTOP_DATA_DIR = MHOME;
// 在 Mirasim 里跑测试时客户端会注入真实 master key，隔离掉
delete process.env.MIRASIM_SECRET_KEY;
delete process.env.MIRASIM_APP_SECRET_KEY;

const ml = await import('../src/mirasimLocal.js');
const mc = await import('../src/mirasimClient.js');

test('mirasim 加密与解密互逆', () => {
  const key = crypto.randomBytes(32);
  const plain = 'jwt-token-sample-1234567890';
  const enc = ml.encryptWithKey(plain, key);
  assert.ok(enc.startsWith('mrs1:'), '密文应带 mrs1: 前缀');
  const dec = ml.decryptWithKey(enc, key);
  assert.equal(dec, plain);
});

test('normalizeMirasimLimits：正确解析 5h、7d 窗口及模型上限', () => {
  const mockLimits = {
    subject: 'usr_test123',
    suspended: false,
    windows: [
      { name: '5h', used: 1000, budget: 10000, reset_at: 1790500000 },
      { name: '7d', used: 50000, budget: 100000, reset_at: 1790700000 },
      { name: '7d_claude', used: 25000, budget: 50000, reset_at: 1790700000 },
    ],
  };
  const mockProfile = {
    id: 'usr_test123',
    name: '测试用户',
    email: 'test@example.com',
    plan: 'plus',
    plan_exp: 1791500000,
  };

  const q = mc.normalizeMirasimLimits(mockLimits, mockProfile);
  assert.equal(q.plan, 'PLUS');
  assert.ok(q.planExpiresAt);
  assert.equal(q.unit, '%');
  assert.equal(q.parts.length, 3);
  assert.equal(q.parts[0].name, '5小时窗口');
  assert.equal(q.parts[0].percent, 10);
  assert.equal(q.parts[0].remaining, 9000);
  assert.equal(q.parts[1].name, '7天全局窗口');
  assert.equal(q.parts[1].percent, 50);
  assert.equal(q.parts[2].name, '7天 Claude 上限');
  assert.equal(q.parts[2].percent, 50);
  assert.equal(q.used, 50, '瓶颈短板原则：7d 剩余更少，已用取短板 50%');
  assert.equal(q.remaining, 50);
  assert.equal(q.exceeded, false);
});

test('mirasim switchTo：保留其他配置，原子替换 auth', async () => {
  const p = ml.mirasimPaths();
  fs.mkdirSync(path.dirname(p.setting), { recursive: true });
  fs.writeFileSync(p.setting, JSON.stringify({
    version: 1,
    workspaces: ['/repo/a', '/repo/b'],
    models: { default: 'claude' },
    auth: { userId: 'usr_old', name: '旧用户', token: 'old-token' },
  }, null, 2));

  const targetAccount = {
    id: 'acc_new',
    provider: 'mirasim',
    uid: 'usr_new',
    name: '新用户',
    token: 'new-token-123',
    refreshToken: 'new-rt-456',
    expiresAt: '2026-10-01T00:00:00.000Z',
  };

  const r = await ml.switchTo(targetAccount, { force: true });
  assert.equal(r.switched, true);
  assert.equal(r.alreadyActive, false);

  const updated = JSON.parse(fs.readFileSync(p.setting, 'utf8'));
  assert.equal(updated.version, 1);
  assert.deepEqual(updated.workspaces, ['/repo/a', '/repo/b'], '工作区配置不能丢');
  assert.equal(updated.models.default, 'claude');
  assert.equal(updated.auth.userId, 'usr_new');
  assert.equal(updated.auth.name, '新用户');

  // 再次切同一账号判定为 alreadyActive
  const r2 = await ml.switchTo(targetAccount, { force: true });
  assert.equal(r2.switched, false);
  assert.equal(r2.alreadyActive, true);
});

test('writeMirasimAuth：刷新后凭据回写 setting.json，其余字段保留', async () => {
  const p = ml.mirasimPaths();
  fs.mkdirSync(path.dirname(p.setting), { recursive: true });
  fs.writeFileSync(p.setting, JSON.stringify({
    version: 1,
    workspaces: ['/repo/x'],
    auth: { userId: 'usr_sync', name: '同步测试', token: 'old-token', refreshToken: 'old-rt', exp: 1000 },
  }, null, 2));

  const synced = await ml.writeMirasimAuth({
    uid: 'usr_sync',
    token: 'new-token',
    refreshToken: 'new-rt',
    expiresAt: '2026-10-01T00:00:00.000Z',
  });
  assert.equal(synced, true);
  const s = JSON.parse(fs.readFileSync(p.setting, 'utf8'));
  assert.equal(s.auth.token, 'new-token');
  assert.equal(s.auth.refreshToken, 'new-rt');
  assert.equal(s.auth.exp, Math.floor(new Date('2026-10-01T00:00:00.000Z').getTime() / 1000));
  assert.deepEqual(s.workspaces, ['/repo/x'], '其余字段不能丢');

  // uid 不匹配（不是客户端当前登录）时不写回
  const skipped = await ml.writeMirasimAuth({ uid: 'usr_other', token: 'x', refreshToken: 'y', expiresAt: null });
  assert.equal(skipped, false);
});

test('fetchMirasimQuota：401 后自动刷新并重试，经 ctx.onRefresh 回写凭据', async () => {
  const realFetch = globalThis.fetch;
  const zcNet = await import('../src/zcodeClient.js');
  let calls = 0;
  globalThis.fetch = async (url, opts = {}) => {
    const auth = String(opts.headers?.Authorization || '');
    calls++;
    if (String(url).includes('/auth/refresh')) {
      return new Response(JSON.stringify({ access_token: 'fresh-token', refresh_token: 'fresh-rt' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (auth.endsWith('stale-token')) return new Response('unauthorized', { status: 401 });
    return new Response(JSON.stringify({ subject: 'usr_x', windows: [{ name: '5h', used: 10, budget: 100, reset_at: 1790700000 }] }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    zcNet._setViaProxyForTests(() => { throw new Error('no proxy in test'); });
    const account = { token: 'stale-token', refreshToken: 'rt-1' };
    const refreshed = [];
    const quota = await mc.fetchMirasimQuota(account, { onRefresh: async (c) => refreshed.push(c) });
    assert.equal(quota.parts.length, 1);
    assert.equal(account.token, 'fresh-token', '内存中的 token 应已换新');
    assert.equal(account.refreshToken, 'fresh-rt', '轮换后的 refreshToken 应已保存');
    assert.equal(refreshed.length, 1, 'onRefresh 应收到新凭据');
  } finally {
    globalThis.fetch = realFetch;
    zcNet._setViaProxyForTests(null);
  }
});

test('新版桌面端 secret-key.enc（safeStorage v10）：无 secret.key 也能解出 master key', { skip: process.platform !== 'win32' }, async () => {
  const { execFileSync } = await import('node:child_process');
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mirasim-v10-'));
  const prev = { h: process.env.MIRASIM_HOME, d: process.env.MIRASIM_DESKTOP_DATA_DIR };
  process.env.MIRASIM_HOME = home;
  process.env.MIRASIM_DESKTOP_DATA_DIR = home;
  try {
    // 构造 Chromium os_crypt：Local State 里存 "DPAPI" + DPAPI(aesKey)
    const aesKey = crypto.randomBytes(32);
    const script = 'Add-Type -AssemblyName System.Security;$b=[Convert]::FromBase64String([Console]::In.ReadToEnd());'
      + "[Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser'))";
    const protectedKey = Buffer.from(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { input: aesKey.toString('base64'), encoding: 'utf8', windowsHide: true }).trim(), 'base64');
    fs.writeFileSync(path.join(home, 'Local State'), JSON.stringify({ os_crypt: { encrypted_key: Buffer.concat([Buffer.from('DPAPI'), protectedKey]).toString('base64') } }));
    // secret-key.enc = "v10" + nonce + AES-GCM(64 字符 hex master key) + tag
    const master = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
    const ct = Buffer.concat([c.update(master.toString('hex'), 'utf8'), c.final()]);
    fs.writeFileSync(path.join(home, 'secret-key.enc'), Buffer.concat([Buffer.from('v10'), nonce, ct, c.getAuthTag()]));
    fs.writeFileSync(path.join(home, 'setting.json'), JSON.stringify({ auth: { userId: 'usr_v10', token: ml.encryptWithKey('a.b.c', master), refreshToken: ml.encryptWithKey('rt', master) } }));

    const ml2 = await import('../src/mirasimLocal.js?v10');
    const acc = await ml2.liveToAccount();
    assert.equal(acc.token, 'a.b.c');
    assert.equal(acc.refreshToken, 'rt');
    assert.ok(!fs.existsSync(path.join(home, 'secret.key')), '不应往 mirasim 目录写旧版 secret.key');
  } finally {
    process.env.MIRASIM_HOME = prev.h;
    process.env.MIRASIM_DESKTOP_DATA_DIR = prev.d;
    fs.rmSync(home, { recursive: true, force: true });
  }
});
