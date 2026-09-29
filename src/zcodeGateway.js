/**
 * ZCode 免费额度网关 — Start Plan 体验包（GLM-5.3-Flash）的本地补全代理。
 *
 * 数据面：POST /gateway/v1/messages（Anthropic /v1/messages 形态，10router
 * 建一个 anthropic-compatible 自定义节点指向这里即可）。
 *
 * 链路：账号轮换（store 里 provider=zcode、可解析出 zcodejwttoken 的账号）
 *   → 验证码（复用桌面版注册的隐藏窗口 provider，与活动领取共用同一个求解器）
 *   → POST zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages
 *   → SSE / JSON 原样流式回传。
 *
 * 失败分类：3007/3012（验证码）→ 作废 token 重解重试；401（JWT 失效）→ 拉黑账号；
 * 402/额度不足 → 标记耗尽；429 → 冷却 5 分钟。全部失败返回 502 + 各账号结论。
 *
 * 仅限本机回路使用：daemon 只绑 127.0.0.1，网关不做鉴权（跨机场景需要先给
 * daemon 加绑定/密钥，见 README）。NAS/纯 CLI 环境没有验证码提供者，网关开不了。
 */

import { claimToken, zaiHeaders, fetchCaptchaConfig, fetchJsonRace } from './zcodeClient.js';
import { getZcodeCaptchaProvider } from './zcodeAutoClaim.js';

// 整链补全提供者（桌面版注册）：隐藏窗口内「真 Chromium 求解验证码 + 同源发起补全」，
// 规避 Node fetch 的 TLS 指纹风控。签名 ({ captchaCfg, jwt, rawBody }) → { status, contentType, body }。
let completionProvider = null;
export function setZcodeCompletionProvider(fn) { completionProvider = typeof fn === 'function' ? fn : null; }
export function getZcodeCompletionProvider() { return completionProvider; }
import { loadAccounts, loadSettings, saveSettings } from './store.js';
import crypto from 'node:crypto';
import { logger } from './logger.js';

const PLAN_MESSAGES_URL = 'https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages';
const CAPTCHA_CACHE_TTL_MS = 30_000;
const ACCOUNT_COOLING_MS = 5 * 60_000;
const MAX_ATTEMPTS = 6;
const UPSTREAM_TIMEOUT_MS = 600_000;

// ── 开关（持久化在 settings.zcodeGateway） ──

export async function gatewayEnabled() {
  return (await loadSettings()).zcodeGateway === true;
}

export async function setGatewayEnabled(v) {
  await saveSettings({ zcodeGateway: v === true });
}

// ── 账号轮换状态（进程内；重启即清零） ──

let rrIndex = 0;
const cooling = new Map();  // accountId → 冷却截止(ms)
const dead = new Set();     // JWT 失效的账号

function markCooling(id, ms = ACCOUNT_COOLING_MS) { cooling.set(id, Date.now() + ms); }
function markDead(id) { dead.add(id); cooling.set(id, Number.MAX_SAFE_INTEGER); }

/** 可参与轮换的账号（有可解析 plan JWT、未冷却/未拉黑），按轮转序排列 */
async function rotationQueue() {
  const all = (await loadAccounts()).filter((a) => a.provider === 'zcode');
  const now = Date.now();
  const ready = [];
  for (const a of all) {
    if (dead.has(a.id)) continue;
    if ((cooling.get(a.id) || 0) > now) continue;
    try { claimToken(a); ready.push(a); } catch { /* 快照里没有 plan JWT，跳过 */ }
  }
  if (!ready.length) return [];
  rrIndex = ((rrIndex % ready.length) + ready.length) % ready.length;
  return [...ready.slice(rrIndex), ...ready.slice(0, rrIndex)];
}

// ── 验证码（与活动领取共用桌面版隐藏窗口求解器；30s 内复用同一 token） ──

let captchaCache = null; // { param, region, at }

async function ensureCaptcha(force = false) {
  if (!force && captchaCache && Date.now() - captchaCache.at < CAPTCHA_CACHE_TTL_MS) return captchaCache;
  const provider = getZcodeCaptchaProvider();
  if (!provider) {
    throw Object.assign(new Error('本环境没有验证码提供者（网关补全需要桌面版 CreditDaddy 运行）'), { code: 'NO_CAPTCHA_PROVIDER' });
  }
  const cfg = await fetchCaptchaConfig();
  if (!cfg.enabled || !cfg.sceneId) {
    throw Object.assign(new Error('验证码配置不可用'), { code: 'NO_CAPTCHA_CONFIG' });
  }
  const { captchaParam, region } = await provider(cfg);
  captchaCache = { param: captchaParam, region, at: Date.now() };
  return captchaCache;
}

function invalidateCaptcha() { captchaCache = null; }

// ── 数据面 ──

function readRawBody(req, limitBytes = 20 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) { reject(Object.assign(new Error('request body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const isCaptchaError = (status, text) =>
  status === 405 || /3007|3012|captcha|unusual activity/i.test(text);

const isAuthError = (status, text) => status === 401 || /令牌已过期|验证不正确/.test(text);

const isExhausted = (status, text) =>
  status === 402 || /1113|余额不足|无可用资源包|insufficient/i.test(text);

/**
 * 网关数据面入口。返回 true 表示响应已写出（含失败结论）。
 */
export async function handleGateway(req, res) {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'POST /gateway/v1/messages（Anthropic /v1/messages 形态）' }));
  }
  if (!(await gatewayEnabled())) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'ZCode 免费额度网关未开启（面板 → ZCode → 网关开关）' }));
  }
  const completionProvider = getZcodeCompletionProvider();
  const provider = completionProvider || getZcodeCaptchaProvider();
  if (!provider) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '本环境没有验证码提供者：网关补全需要桌面版 CreditDaddy（隐藏窗口静默过验证码）' }));
  }

  let rawBody;
  try { rawBody = await readRawBody(req); } catch (e) {
    res.writeHead(e.status || 400, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: e.message }));
  }

  const queue = await rotationQueue();
  if (!queue.length) {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: '没有可用的 ZCode 账号（需要账号快照里有 zcodejwttoken：在 ZCode 重新登录后本机导入）' }));
  }

  const attempted = [];
  for (let i = 0; i < Math.min(MAX_ATTEMPTS, queue.length * 2); i++) {
    const account = queue[i % queue.length];
    const label = account.name || account.uid || account.id;
    let captcha;
    try {
      // 验证码被拒的分支会 invalidateCaptcha()——缓存为空时这里自然重解新 token
      captcha = await ensureCaptcha(false);
    } catch (e) {
      logger.warn('ZCODE-GW', `验证码获取失败：${e.message}`);
      res.writeHead(503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: `验证码获取失败：${e.message}` }));
    }

    let token;
    try { token = claimToken(account); } catch (e) {
      attempted.push({ account: label, ok: false, error: e.message });
      markDead(account.id);
      continue;
    }

    // 整链委托：真 Chromium 页内「求解 + 同源补全」一条龙（优先）
    if (completionProvider) {
      const cfg = await fetchCaptchaConfig().catch(() => null);
      if (!cfg || !cfg.enabled) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: '验证码配置不可用' }));
      }
      let token;
      try { token = claimToken(account); } catch (e) {
        attempted.push({ account: label, ok: false, error: e.message });
        markDead(account.id);
        continue;
      }
      // 客户端身份面：ZCode/{ver} + SDK UA 后缀 + 全套 X-ZCode/X-Client 头 + 会话追踪
      const identity = await zaiHeaders(token, account.meta?.deviceMid);
      identity['User-Agent'] = `${identity['User-Agent']} ai-sdk/anthropic/3.0.81`;
      identity['anthropic-version'] = '2023-06-01';
      identity['accept-encoding'] = 'gzip';
      identity['x-zcode-session-type'] = 'main';
      identity['x-zcode-trace-id'] = crypto.randomUUID();
      identity['X-Aliyun-Captcha-Verify-Region'] = cfg.region || '';
      let r;
      try {
        r = await completionProvider({ captchaCfg: cfg, jwt: token, rawBody, headers: identity });
      } catch (e) {
        if (controller.signal.aborted) return;
        attempted.push({ account: label, ok: false, error: e.message });
        continue;
      }
      if (r.status >= 400 && isCaptchaError(r.status, r.body)) {
        attempted.push({ account: label, ok: false, error: `验证码被拒（${r.status}）`, captcha: true });
        logger.warn('ZCODE-GW', `${label} 页内整链被拒（${r.status}），重试`);
        continue;
      }
      if (r.status >= 400 && isAuthError(r.status, r.body)) {
        markDead(account.id);
        attempted.push({ account: label, ok: false, error: 'JWT 已失效，账号拉黑' });
        continue;
      }
      if (r.status >= 400 && (isExhausted(r.status, r.body) || r.status === 429)) {
        markCooling(account.id);
        attempted.push({ account: label, ok: false, error: r.status === 429 ? '429 冷却' : '额度不足' });
        continue;
      }
      logger.info('ZCODE-GW', `${label} 页内整链补全成功（${r.status}）`);
      cooling.delete(account.id);
      res.writeHead(r.status, { 'Content-Type': r.contentType || 'application/json', 'Cache-Control': 'no-cache' });
      res.end(r.body);
      return true;
    }

    let upstream;
    const controller = new AbortController();
    req.on('close', () => controller.abort());
    try {
      // 请求面完全镜像 ZCode 客户端的 anthropic 形态：identity 头之外，
      // plan 端点还要求 SDK UA 后缀 / anthropic-version / 会话追踪头，缺了会被风控 405/3012
      const identity = await zaiHeaders(token, account.meta?.deviceMid);
      const headers = {
        ...identity,
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01',
        'accept-encoding': 'gzip',
        'User-Agent': `${identity['User-Agent']} ai-sdk/anthropic/3.0.81`,
        'x-zcode-session-type': 'main',
        'x-zcode-trace-id': crypto.randomUUID(),
        'X-Aliyun-Captcha-Verify-Param': captcha.param,
        'X-Aliyun-Captcha-Verify-Region': captcha.region,
      };
      upstream = await fetchJsonRace(PLAN_MESSAGES_URL, {
        method: 'POST',
        headers,
        body: rawBody,
        timeoutMs: UPSTREAM_TIMEOUT_MS,
        signal: controller.signal,
      });
    } catch (e) {
      if (controller.signal.aborted) return; // 客户端先断了
      attempted.push({ account: label, ok: false, error: e.message });
      continue;
    }

    if (upstream.ok) {
      logger.info('ZCODE-GW', `${label} 补全成功（${upstream.status}）`);
      cooling.delete(account.id);
      const out = { 'Content-Type': upstream.headers.get('content-type') || 'application/json', 'Cache-Control': 'no-cache' };
      res.writeHead(upstream.status, out);
      try {
        const reader = upstream.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!res.write(Buffer.from(value))) {
            await new Promise((r) => res.once('drain', r));
          }
        }
      } catch (e) {
        logger.warn('ZCODE-GW', `流式转发中断：${e.message}`);
      }
      res.end();
      return true;
    }

    const text = await upstream.text().catch(() => '');
    // 验证码类失败：作废 token，换号/重解再来
    if (isCaptchaError(upstream.status, text)) {
      invalidateCaptcha();
      attempted.push({ account: label, ok: false, error: `验证码被拒（${upstream.status}）`, captcha: true });
      logger.warn('ZCODE-GW', `${label} 验证码被拒（${upstream.status}），重解重试`);
      continue;
    }
    if (isAuthError(upstream.status, text)) {
      markDead(account.id);
      attempted.push({ account: label, ok: false, error: 'JWT 已失效，账号拉黑（重新登录后再导入）' });
      logger.warn('ZCODE-GW', `${label} JWT 失效，拉黑`);
      continue;
    }
    if (isExhausted(upstream.status, text)) {
      markCooling(account.id, 30 * 60_000);
      attempted.push({ account: label, ok: false, error: '额度不足/无资源包' });
      logger.info('ZCODE-GW', `${label} 额度不足，本轮跳过`);
      continue;
    }
    if (upstream.status === 429) {
      markCooling(account.id);
      attempted.push({ account: label, ok: false, error: '429 限流，冷却 5 分钟' });
      logger.info('ZCODE-GW', `${label} 429，冷却 5 分钟`);
      continue;
    }
    // 其他错误：原样透传给客户端
    logger.warn('ZCODE-GW', `${label} 上游错误 ${upstream.status}：${text.slice(0, 120)}`);
    res.writeHead(upstream.status, { 'Content-Type': 'application/json' });
    res.end(text);
    return true;
  }

  logger.warn('ZCODE-GW', `全部 ${attempted.length} 次尝试失败`);
  res.writeHead(502, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'ZCode 网关：所有账号尝试均失败', attempts: attempted }));
  return true;
}

// ── 面板状态 ──

export async function gatewayStatus() {
  const enabled = await gatewayEnabled();
  const hasCaptcha = Boolean(getZcodeCaptchaProvider());
  const all = (await loadAccounts()).filter((a) => a.provider === 'zcode');
  let withJwt = 0;
  for (const a of all) { try { claimToken(a); withJwt++; } catch { /* 无 plan JWT */ } }
  const now = Date.now();
  return {
    enabled,
    hasCaptcha,
    accounts: all.length,
    accountsWithJwt: withJwt,
    cooling: all.filter((a) => (cooling.get(a.id) || 0) > now).map((a) => a.name || a.uid || a.id),
    dead: [...dead],
    endpoint: '/gateway/v1/messages',
    note: hasCaptcha ? null : '需要桌面版 CreditDaddy（隐藏窗口验证码），纯 CLI / NAS 环境不可用',
  };
}
