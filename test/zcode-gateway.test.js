/**
 * zcodeGateway — 开关门 / 验证码缓存与失效 / 账号轮换与失败分类。
 * fetch 与验证码提供者全部注入，无网络。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { EventEmitter } from 'node:events';

const MHOME = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-gw-test-'));
process.env.CREDITDADDY_HOME = MHOME;

const store = await import('../src/store.js');
const zauto = await import('../src/zcodeAutoClaim.js');
const zc = await import('../src/zcrypto.js');
const gw = await import('../src/zcodeGateway.js');
const zclient = await import('../src/zcodeClient.js');
// 版本探测走网络，会打乱 mock 队列 —— 直接预置缓存
zclient._resetAppVersionCache('3.14.0');

// 与 zcodeClient.safeDecrypt 同款密钥派生（zcrypto.defaultSecret(os.homedir())）
const secret = zc.defaultSecret(os.homedir());
const encForStore = (plain) => zc.encryptWithSecret(plain, secret);

let fetchCalls = [];
let captchaSolves = 0;
let captchaFail = false;
let upstreamQueue = [];

store.saveSettings({ zcodeGateway: true });
zauto.setZcodeCaptchaProvider(async () => {
  if (captchaFail) throw new Error('求解器故障');
  captchaSolves += 1;
  return { captchaParam: `{"sceneId":"11xygtvd","certifyId":"cert-${captchaSolves}","deviceToken":"dt"}`, region: 'cn' };
});

globalThis.fetch = async (url, init = {}) => {
  if (process.env.GW_DEBUG) console.log('[fetch]', String(url).slice(0, 80), '| queue[0] =', upstreamQueue[0] ? String(upstreamQueue[0].body).slice(0, 60) : '(empty)');
  fetchCalls.push({ url: String(url), method: init.method, headers: init.headers });
  const next = upstreamQueue.shift();
  if (!next) throw new Error('no queued upstream response');
  return {
    ok: (next.status || 200) < 400,
    status: next.status || 200,
    headers: { get: (k) => (k.toLowerCase() === 'content-type' ? (next.sse ? 'text/event-stream' : 'application/json') : null) },
    text: async () => next.body ?? '',
    body: new ReadableStream({
      start(c) { if (next.body) c.enqueue(Buffer.from(next.body)); c.close(); },
    }),
  };
};

async function seedAccount(id, name, withJwt = true) {
  const acc = {
    id, name, provider: 'zcode', uid: id,
    meta: { credentials: withJwt ? { zcodejwttoken: encForStore(`jwt-${id}-` + 'x'.repeat(200)) } : {} },
  };
  currentAccounts.push(acc);
  await store.saveAccounts(currentAccounts);
  return acc;
}

let currentAccounts = [];

async function resetState() {
  currentAccounts = [];
  await store.saveAccounts([]);
  fetchCalls = [];
  upstreamQueue = [];
}

function fakeReq(method, body) {
  const req = new EventEmitter();
  req.method = method;
  let started = false;
  req.on('newListener', (ev) => {
    if (ev === 'data' && !started) {
      started = true;
      process.nextTick(() => {
        if (body) req.emit('data', Buffer.from(body));
        req.emit('end');
      });
    }
  });
  return req;
}

function captureRes() {
  const res = {
    status: 0, body: '', headersSent: false, headers: null,
    writeHead(code, hdrs) { this.status = code; this.headers = hdrs; this.headersSent = true; return this; },
    end(chunk) { if (chunk) this.body += chunk.toString(); return this; },
    write(chunk) { this.body += chunk.toString(); return true; },
    once() {}, on() {},
  };
  return res;
}

const capCfg = () => ({ status: 200, body: JSON.stringify({ code: 0, data: { configs: { captcha: { enabled: true, region: 'cn', prefix: 'no8xfe', sceneId: '11xygtvd' } } } }) });
const sseBody = () => 'event: message_start\ndata: {"type":"message_start"}\n\n';
const completions = () => fetchCalls.filter((c) => c.url.includes('/zcode-plan/anthropic/v1/messages'));

test('网关未开启时返回 503', async () => {
  await resetState();
  await store.saveSettings({ zcodeGateway: false });
  await seedAccount('a1', '账号一');
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{}'), res);
  assert.equal(res.status, 503);
  assert.match(res.body, /网关未开启/);
  await store.saveSettings({ zcodeGateway: true });
});

test('无验证码提供者时返回 503（NAS/CLI 场景）', async () => {
  await resetState();
  zauto.setZcodeCaptchaProvider(null);
  await seedAccount('a1', '账号一');
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{}'), res);
  assert.equal(res.status, 503);
  assert.match(res.body, /验证码提供者/);
  zauto.setZcodeCaptchaProvider(async () => {
    captchaSolves += 1;
    return { captchaParam: `{"certifyId":"c${captchaSolves}"}`, region: 'cn' };
  });
});

test('无可用账号（快照里没有 zcodejwttoken）返回 503', async () => {
  await resetState();
  await seedAccount('a1', '账号一', false);
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{"model":"glm-5.3-flash"}'), res);
  assert.equal(res.status, 503);
  assert.match(res.body, /没有可用的 ZCode 账号/);
});

test('验证码 + 补全成功：SSE 透传，token 30s 内复用（一次求解）', async () => {
  await resetState();
  await seedAccount('a1', '账号一');
  upstreamQueue.push(capCfg(), { status: 200, sse: true, body: sseBody() });
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{"model":"glm-5.3-flash","stream":true}'), res);
  assert.equal(res.status, 200, res.body);
  assert.equal(res.body, sseBody());
  assert.equal(completions().length, 1);
  assert.ok(completions()[0].headers['X-Aliyun-Captcha-Verify-Param']);
  assert.match(completions()[0].headers.Authorization, /^Bearer jwt-a1-/);
  assert.equal(captchaSolves, 1);
});

test('3007 验证码被拒 → 每次尝试都强制重解新 token，全败 502 汇总', async () => {
  await resetState();
  await seedAccount('a1', '账号一');
  await seedAccount('a2', '账号二');
  upstreamQueue.push(
    { status: 400, body: '{"code":3007,"msg":"captcha verify failed"}' },
    capCfg(),
    { status: 400, body: '{"code":3007,"msg":"captcha verify failed"}' },
    capCfg(),
    { status: 400, body: '{"code":3007,"msg":"captcha verify failed"}' },
    capCfg(),
    { status: 400, body: '{"code":3007,"msg":"captcha verify failed"}' },
  );
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{}'), res);
  assert.equal(res.status, 502);
  const parsed = JSON.parse(res.body);
  assert.ok(parsed.attempts.length >= 2);
  assert.ok(parsed.attempts.some((a) => /验证码被拒/.test(a.error)));
  const params = completions().map((c) => JSON.parse(c.headers['X-Aliyun-Captcha-Verify-Param']).certifyId);
  assert.equal(new Set(params).size, params.length, '每次尝试都应有新验证码 token');
});

test('401 → 账号拉黑；额度不足/429 → 跳过换号；最终成功', async () => {
  await resetState();
  await seedAccount('dead', '失效号');
  await seedAccount('poor', '没额度号');
  await seedAccount('good', '好号');
  upstreamQueue.push(
    capCfg(),
    { status: 401, body: '{"code":401,"msg":"令牌已过期"}' },
    { status: 429, body: '{"error":{"code":"429"}}' },
    { status: 200, sse: true, body: sseBody() },
  );
  const res = captureRes();
  await gw.handleGateway(fakeReq('POST', '{}'), res);
  assert.equal(res.status, 200, res.body);
  const rows = completions();
  assert.equal(rows.length, 3);
  assert.match(rows[0].headers.Authorization, /^Bearer jwt-dead-/);
  assert.match(rows[1].headers.Authorization, /^Bearer jwt-poor-/);
  assert.match(rows[2].headers.Authorization, /^Bearer jwt-good-/);
});

test('GET 请求提示用法', async () => {
  const res = captureRes();
  await gw.handleGateway(fakeReq('GET', ''), res);
  assert.equal(res.status, 405);
});
