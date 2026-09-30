/**
 * 桌面壳密码库(userData/passwords.json)
 *
 * 壳子「容器」(主窗体加载外部网页)的已存密码,格式:
 *   { version: 1, entries: [{id, origin, username, passwordEnc, createdAt, updatedAt}], neverAsk: [origin] }
 *
 * 安全约定:
 *  - 只落密文:passwordEnc 由注入的 cipher 产出(main.js 传 Electron safeStorage,
 *    Windows 即 DPAPI,绑当前系统用户);cipher 不可用时拒绝写入,绝不落明文。
 *  - 本模块不 require('electron'):cipher 以参数注入,纯 Node 可测(vitest 用假 cipher)。
 *  - origin 归一化为 URL.origin(scheme+host+port,host 小写、默认端口剥离),做去重键。
 *  - 用户名不加密明文存(检索/列表要用,敏感度与浏览器密码管理器一致)。
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FORMAT_VERSION = 1;
const MAX_ENTRIES = 200;
const MAX_TEXT = 300;          // origin/username 截断
const MAX_NEVER_ASK = 100;

// "example.com" 也算数,默认按 https;只收 http(s),返回 URL.origin,非法返回 null。
// 显式给了非 http(s) scheme(ftp:/file:/javascript: 等)直接拒收——否则 "ftp://x.com"
// 会被拼成 "https://ftp://x.com" 存成 origin "https://ftp"。
function normalizeOrigin(raw) {
    let v = String(raw || '').trim();
    if (!v) return null;
    if (!/^https?:\/\//i.test(v)) {
        if (/^[a-z][a-z0-9+.-]*:/i.test(v)) return null;
        v = 'https://' + v;
    }
    try {
        const u = new URL(v);
        if (!u.hostname || !/^https?:$/.test(u.protocol)) return null;
        return u.origin;
    } catch { return null; }
}

function validEntry(e) {
    return !!(e && typeof e === 'object'
        && typeof e.id === 'string' && e.id
        && typeof e.origin === 'string' && normalizeOrigin(e.origin)
        && typeof e.username === 'string'
        && typeof e.passwordEnc === 'string' && e.passwordEnc);
}

/**
 * @param {object} opts
 * @param {string} opts.file    存储文件绝对路径(userData/passwords.json)
 * @param {{available:()=>boolean, encrypt:(plain:string)=>string, decrypt:(blob:string)=>string}} opts.cipher
 * @param {(msg:string)=>void} [opts.log]
 * @param {()=>number} [opts.now]
 */
function createPasswordStore({ file, cipher, log, now = () => Date.now() }) {
    let cache = null;

    function data() {
        if (cache) return cache;
        cache = { version: FORMAT_VERSION, entries: [], neverAsk: [] };
        try {
            const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
            if (raw && typeof raw === 'object') {
                if (Array.isArray(raw.entries)) cache.entries = raw.entries.filter(validEntry).slice(0, MAX_ENTRIES);
                if (Array.isArray(raw.neverAsk)) {
                    cache.neverAsk = raw.neverAsk
                        .filter((x) => typeof x === 'string' && x)
                        .map((x) => normalizeOrigin(x))
                        .filter(Boolean)
                        .slice(0, MAX_NEVER_ASK);
                }
            }
        } catch (e) {
            // 文件损坏/不可读:从空库重来(无法恢复的内容本来也读不出),下次 flush 覆盖
            if (e && e.code !== 'ENOENT' && log) log(`password store: unreadable, starting fresh (${e.message})`);
        }
        return cache;
    }

    function flush() {
        try {
            fs.mkdirSync(path.dirname(file), { recursive: true });
            fs.writeFileSync(file, JSON.stringify(data(), null, 2) + '\n', { mode: 0o600 });
        } catch (e) {
            if (log) log(`password store: save failed: ${e.message}`);
        }
    }

    // 对外不暴露 passwordEnc:列表/查询一律走 publicEntry
    function publicEntry(en) {
        return { id: en.id, origin: en.origin, username: en.username, createdAt: en.createdAt, updatedAt: en.updatedAt };
    }

    function sameOrigin(a, b) { return String(a).toLowerCase() === String(b).toLowerCase(); }

    return {
        isAvailable: () => {
            try { return cipher.available() === true; } catch { return false; }
        },

        // updatedAt 降序(管理窗/右键菜单顺序)
        list: () => data().entries.map(publicEntry)
            .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)),

        listForOrigin: (origin) => {
            const o = normalizeOrigin(origin);
            if (!o) return [];
            return data().entries.filter((en) => sameOrigin(en.origin, o))
                .map(publicEntry)
                .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
        },

        findEntry: (origin, username) => {
            const o = normalizeOrigin(origin);
            if (!o) return null;
            const user = String(username || '');
            const en = data().entries.find((x) => sameOrigin(x.origin, o) && x.username === user);
            return en ? publicEntry(en) : null;
        },

        // 同 origin+username 幂等:密码相同 → no-op(updated=false);不同 → 更新
        upsert({ origin, username, password }) {
            if (!this.isAvailable()) throw new Error('credential encryption unavailable');
            const o = normalizeOrigin(origin);
            if (!o) throw new Error('invalid origin');
            const pw = String(password || '');
            if (!pw) throw new Error('empty password');
            const user = String(username || '').slice(0, MAX_TEXT);
            const d = data();
            const en = d.entries.find((x) => sameOrigin(x.origin, o) && x.username === user);
            if (en) {
                let same = false;
                try { same = cipher.decrypt(en.passwordEnc) === pw; } catch { same = false; }
                if (same) return { entry: publicEntry(en), updated: false };
                en.passwordEnc = cipher.encrypt(pw);
                en.updatedAt = now();
                flush();
                return { entry: publicEntry(en), updated: true };
            }
            const fresh = {
                id: crypto.randomUUID(),
                origin: o,
                username: user,
                passwordEnc: cipher.encrypt(pw),
                createdAt: now(),
                updatedAt: now(),
            };
            d.entries.unshift(fresh);
            if (d.entries.length > MAX_ENTRIES) d.entries.length = MAX_ENTRIES;
            flush();
            return { entry: publicEntry(fresh), updated: true };
        },

        // 管理窗改用户名/密码;password 传空串 = 保持原密码
        update(id, { username, password } = {}) {
            if (!this.isAvailable()) throw new Error('credential encryption unavailable');
            const en = data().entries.find((x) => x.id === id);
            if (!en) throw new Error('entry not found');
            let touched = false;
            if (username !== undefined) {
                en.username = String(username || '').slice(0, MAX_TEXT);
                touched = true;
            }
            if (password) {
                en.passwordEnc = cipher.encrypt(String(password));
                touched = true;
            }
            if (touched) {
                en.updatedAt = now();
                flush();
            }
            return publicEntry(en);
        },

        // 明文只在调用方内存里过一手(填充/复制/比对),不落盘不进日志
        reveal(id) {
            if (!this.isAvailable()) throw new Error('credential encryption unavailable');
            const en = data().entries.find((x) => x.id === id);
            if (!en) throw new Error('entry not found');
            return cipher.decrypt(en.passwordEnc);
        },

        remove: (id) => {
            const d = data();
            const before = d.entries.length;
            d.entries = d.entries.filter((x) => x.id !== id);
            if (d.entries.length !== before) flush();
            return d.entries.length !== before;
        },

        setNeverAsk: (origin) => {
            const o = normalizeOrigin(origin);
            if (!o) return;
            const d = data();
            if (!d.neverAsk.some((x) => sameOrigin(x, o))) {
                d.neverAsk.unshift(o);
                d.neverAsk = d.neverAsk.slice(0, MAX_NEVER_ASK);
                flush();
            }
        },

        isNeverAsk: (origin) => {
            const o = normalizeOrigin(origin);
            return !!o && data().neverAsk.some((x) => sameOrigin(x, o));
        },
    };
}

module.exports = { createPasswordStore, normalizeOrigin };
