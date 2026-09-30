/**
 * desktop/passwordStore.js 单测（注入假 cipher，纯 Node 可跑）。
 * 契约：只落密文、同 origin+username 幂等、origin 归一化去重、neverAsk 持久化、
 * 坏文件自愈、cipher 不可用时拒绝写入（绝不落明文）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createPasswordStore, normalizeOrigin } = require('../desktop/passwordStore.js');

// 假 cipher：base64 前缀标记，遇到非本格式 blob 直接抛（模拟 safeStorage 解密失败）
function fakeCipher({ available = true } = {}) {
  return {
    available: () => available,
    encrypt: (plain) => 'x1:' + Buffer.from(plain, 'utf8').toString('base64'),
    decrypt: (blob) => {
      const s = String(blob);
      if (!s.startsWith('x1:')) throw new Error('decrypt failed: bad blob');
      return Buffer.from(s.slice(3), 'base64').toString('utf8');
    },
  };
}

function tempFile(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qd-pwstore-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return path.join(dir, 'passwords.json');
}

let tick = 0;
const now = () => ++tick * 1000;

test('origin 归一化：裸域名默认 https，大小写/默认端口收敛', (t) => {
  const store = createPasswordStore({ file: tempFile(t), cipher: fakeCipher(), now });
  store.upsert({ origin: 'Example.com', username: 'u', password: 'p1' });
  store.upsert({ origin: 'https://example.com:443', username: 'u', password: 'p2' });
  const list = store.list();
  assert.equal(list.length, 1);
  assert.equal(list[0].origin, 'https://example.com');
  assert.equal(store.reveal(list[0].id), 'p2');
});

test('origin 归一化：保留非默认端口，拒绝非 http(s) 协议', () => {
  assert.equal(normalizeOrigin('http://x.com:8080'), 'http://x.com:8080');
  assert.equal(normalizeOrigin('router.lan'), 'https://router.lan');
  assert.equal(normalizeOrigin('ftp://x.com'), null);
  assert.equal(normalizeOrigin('javascript:alert(1)'), null);
  assert.equal(normalizeOrigin('file:///etc/passwd'), null);
  assert.equal(normalizeOrigin(''), null);
  assert.equal(normalizeOrigin('https://bad host'), null);
});

test('upsert：新增只落密文，列表不回显明文/密文', (t) => {
  const file = tempFile(t);
  const store = createPasswordStore({ file, cipher: fakeCipher(), now });
  const { entry, updated } = store.upsert({ origin: 'https://example.com', username: 'bob', password: 's3cret' });
  assert.equal(updated, true);
  assert.equal(entry.origin, 'https://example.com');
  assert.ok(!('passwordEnc' in entry));
  assert.ok(!('password' in entry));
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.match(raw.entries[0].passwordEnc, /^x1:/);
  assert.ok(!JSON.stringify(raw).includes('s3cret'));
});

test('upsert：同 origin+username 换密码原地更新；相同密码 no-op', (t) => {
  const file = tempFile(t);
  const store = createPasswordStore({ file, cipher: fakeCipher(), now });
  store.upsert({ origin: 'https://example.com', username: 'bob', password: 'one' });
  const firstUpdatedAt = JSON.parse(fs.readFileSync(file, 'utf8')).entries[0].updatedAt;
  const { updated } = store.upsert({ origin: 'https://example.com', username: 'bob', password: 'two' });
  assert.equal(updated, true);
  let raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(raw.entries.length, 1);
  assert.notEqual(raw.entries[0].updatedAt, firstUpdatedAt);
  assert.equal(store.reveal(raw.entries[0].id), 'two');
  const again = store.upsert({ origin: 'https://example.com', username: 'bob', password: 'two' });
  assert.equal(again.updated, false);
});

test('多用户名并存、origin 隔离（路径忽略）', (t) => {
  const store = createPasswordStore({ file: tempFile(t), cipher: fakeCipher(), now });
  store.upsert({ origin: 'https://a.com', username: 'u1', password: 'p1' });
  store.upsert({ origin: 'https://a.com', username: 'u2', password: 'p2' });
  store.upsert({ origin: 'https://b.com', username: 'u1', password: 'p3' });
  assert.equal(store.list().length, 3);
  assert.equal(store.listForOrigin('https://a.com/login').length, 2);
  assert.equal(store.listForOrigin('https://c.com').length, 0);
});

test('非法 origin / 空密码拒绝写入且不留文件', (t) => {
  const file = tempFile(t);
  const store = createPasswordStore({ file, cipher: fakeCipher(), now });
  assert.throws(() => store.upsert({ origin: 'https://bad host', username: 'u', password: 'p' }), /invalid origin/i);
  assert.throws(() => store.upsert({ origin: 'ftp://x.com', username: 'u', password: 'p' }), /invalid origin/i);
  assert.throws(() => store.upsert({ origin: 'https://ok.com', username: 'u', password: '' }), /empty password/i);
  assert.equal(store.list().length, 0);
  assert.equal(fs.existsSync(file), false);
});

test('管理：改用户名保持原密码；给新密码则重新加密', (t) => {
  const store = createPasswordStore({ file: tempFile(t), cipher: fakeCipher(), now });
  const { entry } = store.upsert({ origin: 'https://example.com', username: 'a', password: 'keep' });
  store.update(entry.id, { username: 'b', password: '' });
  assert.equal(store.list()[0].username, 'b');
  assert.equal(store.reveal(entry.id), 'keep');
  store.update(entry.id, { password: 'new' });
  assert.equal(store.reveal(entry.id), 'new');
});

test('删除两次：第二次报 false', (t) => {
  const store = createPasswordStore({ file: tempFile(t), cipher: fakeCipher(), now });
  const { entry } = store.upsert({ origin: 'https://example.com', username: 'u', password: 'p' });
  assert.equal(store.remove(entry.id), true);
  assert.equal(store.list().length, 0);
  assert.equal(store.remove(entry.id), false);
});

test('容量上限 200 条', (t) => {
  const store = createPasswordStore({ file: tempFile(t), cipher: fakeCipher(), now });
  for (let i = 0; i < 205; i++) store.upsert({ origin: `https://h${i}.example`, username: 'u', password: 'p' });
  assert.equal(store.list().length, 200);
});

test('重启后条目与 neverAsk 仍在（大小写不敏感匹配）', (t) => {
  const file = tempFile(t);
  const a = createPasswordStore({ file, cipher: fakeCipher(), now });
  a.upsert({ origin: 'https://example.com', username: 'bob', password: 'pw' });
  a.setNeverAsk('https://Spam.example');
  const b = createPasswordStore({ file, cipher: fakeCipher(), now });
  assert.equal(b.list().length, 1);
  assert.equal(b.reveal(b.list()[0].id), 'pw');
  assert.equal(b.isNeverAsk('https://SPAM.example'), true);
  assert.equal(b.isNeverAsk('https://other.example'), false);
});

test('坏文件自愈：无法解析从空库重来；畸形条目加载时丢弃', (t) => {
  const file = tempFile(t);
  fs.writeFileSync(file, '{not json');
  const store = createPasswordStore({ file, cipher: fakeCipher(), now });
  assert.equal(store.list().length, 0);
  store.upsert({ origin: 'https://example.com', username: 'u', password: 'p' });
  assert.equal(store.list().length, 1);

  fs.writeFileSync(file, JSON.stringify({
    version: 1,
    entries: [
      { id: 'ok-1', origin: 'https://good.example', username: 'u', passwordEnc: 'x1:cA==', createdAt: 1, updatedAt: 1 },
      { id: 'bad-1', origin: 'javascript:alert(1)', username: 'u', passwordEnc: 'x1:cA==' },
      { id: 'bad-2', origin: 'https://x.example', username: 'u' },
      'garbage',
    ],
    neverAsk: ['https://quiet.example', 42],
  }));
  const healed = createPasswordStore({ file, cipher: fakeCipher(), now });
  assert.equal(healed.list().length, 1);
  assert.equal(healed.list()[0].id, 'ok-1');
  assert.equal(healed.isNeverAsk('https://quiet.example'), true);
});

test('密文被篡改 → reveal 抛（fail closed）', (t) => {
  const file = tempFile(t);
  const store = createPasswordStore({ file, cipher: fakeCipher(), now });
  store.upsert({ origin: 'https://example.com', username: 'u', password: 'p' });
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  raw.entries[0].passwordEnc = 'garbage';
  fs.writeFileSync(file, JSON.stringify(raw));
  const reopened = createPasswordStore({ file, cipher: fakeCipher(), now });
  assert.throws(() => reopened.reveal(raw.entries[0].id), /bad blob/);
});

test('cipher 不可用 → 拒绝任何写入，绝不落明文', (t) => {
  const file = tempFile(t);
  const store = createPasswordStore({ file, cipher: fakeCipher({ available: false }), now });
  assert.equal(store.isAvailable(), false);
  assert.throws(() => store.upsert({ origin: 'https://example.com', username: 'u', password: 'p' }), /unavailable/i);
  assert.throws(() => store.reveal('whatever'), /unavailable/i);
  assert.equal(fs.existsSync(file), false);
});
