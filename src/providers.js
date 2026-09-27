/**
 * 产品线注册表 — 按账号 provider 分发签到 / 积分 / 校验。
 *
 * 每个产品实现（checkin 可缺省：该产品不参与每日签到，如 ZCode）：
 *   checkin(account, ctx) → { status: checked-in|already|limited|no-activity|failed, … }
 *   quota(account, ctx)   → { total, used, remaining, exceeded, parts: [{ name, total, used, remaining, expiresAt, recurring }] }
 *   verify(account)       → { name?, uid?, email? }（添加账号时补全资料，失败抛错）
 * ctx.onRefresh(creds)：产品在 token 刷新后回调，由调用方负责持久化。
 */

import { productOf } from './constants.js';
import { checkinOne as checkinQoder, fetchQuotaUsage, fetchUserinfo } from './qoderClient.js';
import { checkinWorkbuddy, checkinWorkbuddyIntl, fetchWorkbuddyQuota, inspectToken } from './workbuddyClient.js';
import { fetchZcodeQuota } from './zcodeClient.js';
import { fetchMirasimQuota, fetchMirasimProfile } from './mirasimClient.js';
import { fetchCatpawQuota, fetchCatpawProfile } from './catpawClient.js';
/** 从 userinfo 响应中挑一个可读的显示名 */
export function displayNameFrom(ui) {
  const pick = [ui?.nickname, ui?.name, ui?.username, ui?.email]
    .map((v) => (typeof v === 'string' ? v.trim() : ''))
    .find(Boolean);
  return pick || null;
}

/** Qoder /api/v2/quota/usage → 统一积分结构 */
export function normalizeQoderQuota(q) {
  const names = [['userQuota', '套餐额度', true], ['addOnQuota', '附加额度', false], ['orgResourcePackage', '组织资源包', false]];
  const expiresAt = Number(q?.expiresAt) > 0 && Number(q.expiresAt) < 253400000000000 ? new Date(Number(q.expiresAt)).toISOString() : null;
  const parts = names
    .map(([k, name, recurring]) => ({ x: q?.[k], name, recurring }))
    .filter(({ x }) => x && Number(x.total) > 0)
    .map(({ x, name, recurring }) => ({
      name, recurring,
      total: Number(x.total) || 0,
      used: Number(x.used) || 0,
      remaining: Number(x.remaining) || 0,
      expiresAt,
    }));
  const sum = (k) => Math.round(parts.reduce((s, p) => s + p[k], 0) * 100) / 100;
  return { total: sum('total'), used: sum('used'), remaining: sum('remaining'), parts, exceeded: Boolean(q?.isQuotaExceeded) };
}

const PRODUCTS = {
  qoder: {
    label: 'Qoder',
    checkin: (account) => checkinQoder(account),
    quota: async (account) => normalizeQoderQuota(await fetchQuotaUsage(account)),
    verify: async (account) => {
      const ui = await fetchUserinfo(account);
      return { name: displayNameFrom(ui), uid: typeof ui?.id === 'string' ? ui.id : null, email: ui?.email || null };
    },
  },
  workbuddy: {
    label: 'WorkBuddy',
    // 国内版走 billing daily-checkin 签到；国际版没有签到接口，走「活跃领取」（免费档对话探测）
    checkin: (account, ctx) => (account.provider === 'workbuddy-intl' ? checkinWorkbuddyIntl(account, ctx) : checkinWorkbuddy(account, ctx)),
    quota: (account, ctx) => fetchWorkbuddyQuota(account, ctx),
    verify: async (account) => {
      const info = inspectToken(account.token);
      if (!info.provider) throw new Error('不是 WorkBuddy / CodeBuddy 的登录 token');
      if (info.provider !== account.provider) throw new Error(`token 属于${info.provider === 'workbuddy' ? '国内版' : '国际版'}，与所选版本不符`);
      return { uid: info.uid, name: info.name };
    },
  },
  zcode: {
    label: 'ZCode',
    // 无 checkin：ZCode 积分来自活动领取（需阿里云验证码），不做后台自动签到
    quota: (account) => fetchZcodeQuota(account),
    verify: async () => {
      throw new Error('ZCode 账号请通过「本机导入」添加（需要客户端的完整登录快照才能查询额度与切换）');
    },
  },
  mirasim: {
    label: 'mirasim',
    // 无 checkin：mirasim 额度按 5h/7d 滚动窗口分配，不设签到。
    // token 约 1 小时过期：quota 内部 401 时自动用 refreshToken 续期，
    // ctx.onRefresh（refreshContext）回写账号库后，这里再把新凭据同步回 setting.json（若该账号是客户端当前登录）。
    quota: async (account, ctx = {}) => {
      const mirasimLocal = await import('./mirasimLocal.js');
      const wrapped = {
        ...ctx,
        onRefresh: async (creds) => {
          await ctx.onRefresh?.(creds);
          try {
            const synced = await mirasimLocal.writeMirasimAuth({ uid: account.uid, token: creds.token, refreshToken: creds.refreshToken, expiresAt: creds.expiresAt });
            if (synced) ctx.log?.('已同步新 token 到 mirasim 客户端');
          } catch (e) { ctx.log?.('同步到 mirasim 客户端失败：' + e.message); }
        },
      };
      return fetchMirasimQuota(account, wrapped);
    },
    verify: async (account) => {
      const p = await fetchMirasimProfile(account.token);
      return { name: p.name || p.email, uid: p.id, email: p.email };
    },
  },
  catpaw: {
    label: '妙手',
    // 无 checkin：妙手（美团 CatPaw）按套餐发放 Credits，无每日签到活动。
    // 凭据由妙手客户端登录管理（无对外 refresh）：401 时提示到客户端重新登录后重新本机导入。
    quota: (account) => fetchCatpawQuota(account),
    verify: async (account) => {
      const p = await fetchCatpawProfile(account.token);
      return { name: p.name, uid: p.userId, email: null };
    },
  },
};

export function productImpl(provider) {
  return PRODUCTS[productOf(provider)];
}
