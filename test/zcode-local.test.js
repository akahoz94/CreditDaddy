import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// 必须在导入被测模块前设好 ZCODE_HOME（凭据目录与派生密钥都基于它）
const ZHOME = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-local-test-'));
process.env.ZCODE_HOME = ZHOME;
process.env.CREDITDADDY_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'creditdaddy-zlocal-'));

const zc = await import('../src/zcrypto.js');
const zl = await import('../src/zcodeLocal.js');

const credsFile = () => path.join(ZHOME, '.zcode', 'v2', 'credentials.json');

function writeCreds(obj) {
  fs.mkdirSync(path.dirname(credsFile()), { recursive: true });
  fs.writeFileSync(credsFile(), JSON.stringify(obj, null, 2));
}

function encCreds(provider, userInfo) {
  const secret = zc.defaultSecret(ZHOME);
  const enc = (v) => zc.encryptWithSecret(v, secret);
  return {
    'oauth:active_provider': enc(provider),
    [`oauth:${provider}:access_token`]: enc('x'.repeat(64)),
    [`oauth:${provider}:user_info`]: enc(JSON.stringify(userInfo)),
    zcodejwttoken: enc('j'.repeat(64)),
  };
}

test('currentZcodeIdentity：从加密凭据读出 uid / email / username', () => {
  writeCreds(encCreds('bigmodel', { id: '3851788492835867', username: 'vepxa715', displayName: 'vepxa715' }));
  const id = zl.currentZcodeIdentity();
  assert.equal(String(id.uid), '3851788492835867');
  assert.equal(id.username, 'vepxa715');
  assert.equal(id.email, null);
  assert.equal(zl.currentZcodeUid(), '3851788492835867');

  writeCreds(encCreds('zai', { id: 11839208, email: 'i@example.com' }));
  const id2 = zl.currentZcodeIdentity();
  assert.equal(String(id2.uid), '11839208', '数字 uid 也要可读');
  assert.equal(id2.email, 'i@example.com');
});

test('currentZcodeIdentity：未登录 / 凭据文件缺失返回 null', () => {
  writeCreds({ 'oauth:active_provider': 'zai' });
  assert.equal(zl.currentZcodeIdentity(), null);
  fs.rmSync(path.join(ZHOME, '.zcode'), { recursive: true, force: true });
  assert.equal(zl.currentZcodeIdentity(), null);
  assert.equal(zl.currentZcodeUid(), null);
});

test('terminateZcode 存在（不在测试中调用，会真的结束本机 ZCode）', () => {
  assert.equal(typeof zl.terminateZcode, 'function');
});

test('switchTo 还原 credentials、config 以及 setting.json', () => {
  const p = zl.zcodePaths();
  fs.mkdirSync(path.dirname(p.credentials), { recursive: true });
  fs.writeFileSync(p.credentials, JSON.stringify({ old: 'creds' }));
  fs.writeFileSync(p.setting, JSON.stringify({ modelProviderFamilySelectedKeys: { zai: 'old-key' } }));

  const targetAccount = {
    id: 'acc_target',
    provider: 'zcode',
    uid: 'new-uid',
    token: 'zcode-creds:new-uid',
    meta: {
      credentials: { 'oauth:active_provider': 'zai', zcodejwttoken: 'jwt-123' },
      config: { provider: { 'builtin:zai': { enabled: true } } },
      setting: { modelProviderFamilySelectedKeys: { zai: 'coding-plan:builtin:zai-start-plan' } },
    },
  };

  const r = zl.switchTo(targetAccount, { force: true });
  assert.equal(r.switched, true);
  const curSetting = JSON.parse(fs.readFileSync(p.setting, 'utf8'));
  assert.equal(curSetting.modelProviderFamilySelectedKeys.zai, 'coding-plan:builtin:zai-start-plan', 'setting.json 必须一同还原');
  const curCreds = JSON.parse(fs.readFileSync(p.credentials, 'utf8'));
  assert.equal(curCreds['oauth:active_provider'], 'zai');
});

test('switchTo 为 Coding Plan 补齐 identity 键并同步 defaultModelSelection', () => {
  const p = zl.zcodePaths();
  fs.mkdirSync(path.dirname(p.credentials), { recursive: true });
  fs.writeFileSync(p.providerConfig, JSON.stringify({ schemaVersion: 1, config: {} }));

  const secret = zc.defaultSecret(ZHOME);
  const enc = (v) => zc.encryptWithSecret(v, secret);
  const bigModelAccount = {
    id: 'acc_big',
    provider: 'zcode',
    uid: '3851788492835867',
    meta: {
      credentials: {
        'oauth:active_provider': enc('bigmodel'),
        'oauth:bigmodel:access_token': enc('x'.repeat(64)),
        'oauth:bigmodel:user_info': enc(JSON.stringify({ id: '3851788492835867' })),
        zcodejwttoken: enc('j'.repeat(64)),
      },
    },
  };

  zl.switchTo(bigModelAccount, { force: true });
  const creds = JSON.parse(fs.readFileSync(p.credentials, 'utf8'));
  const identityKey = 'account-provider:account:bigmodel-individual-coding-plan:identity';
  assert.ok(creds[identityKey], '必须补上 Coding Plan 的 identity 键，否则客户端判定未登录');
  assert.equal(zc.safeDecrypt(creds[identityKey], secret), '3851788492835867');

  const pcfg = JSON.parse(fs.readFileSync(p.providerConfig, 'utf8'));
  assert.equal(pcfg.config.defaultModelSelection.providerId, 'account:bigmodel-individual-coding-plan', 'defaultModelSelection 必须指向目标账号的套餐');
});
