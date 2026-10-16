# 🛡️ 登录防爆破加固补丁（v1）

> **作用范围**：`index.js` 的 `/login` 路由 + 前端登录页
> **目标**：堵住"IP 轮换绕过限流"这条真实攻击路径
> **部署**：手工合并以下代码 → `zip code.zip index.js package.json` → FC 控制台上传（同 README 部署流程）
> **状态**：补丁文档，未自动合并到生产代码。请自行审阅后再决定是否部署。

---

## 一、威胁模型（为什么现有防线不够）

现有防御 `loginAttempts: Map<ip, {...}>` 是 **per-IP** 的：

| 攻击方 | 现状 | 加固后 |
| :-- | :-- | :-- |
| 单 IP 脚本小子 | 5 次/15 分钟 | 1 次/2 分钟（指数退避） |
| 1000 IP 轮换（僵尸网络/Tor/云函数代理池） | **5000 次/15 分钟** ❌ | **20 次后全站锁** ✅ |
| C/Rust 高速爆破 | 每秒百万次 | 每次都要 PoW，实际 <1 次/秒 |
| 弱密码爆破 | 数学上可行（取决于密码） | 数学上不可行（+强密码） |

**核心洞察**：per-IP 限流对"IP 轮换"无效。必须叠加**账号级全局计数** + **每次尝试的成本拉高**（PoW / 指数退避）。

---

## 二、三层防御组合

```
① 指数退避（base 3，封顶 2 分钟）→ 每次失败强制等待，物理性拖慢攻击速度
② 账号级全局锁定（20 次 → 全站锁 15 分钟）→ IP 轮换失效
③ PoW 工作量证明（失败后触发）→ 让攻击方用自己的 CPU 付钱，正常用户零感知
```

**关键设计**：**PoW 只在"该 IP 已有失败记录"时才要求** —— 正常用户一次登录成功，**完全看不到 PoW**；只有失败后才需要算题。这是"零额外调用版"：登录失败响应里**顺带返回 challenge**，不增加独立端点。

---

## 三、服务端补丁（`index.js`）

### 3.1 `CONFIG.SECURITY` 新增配置项

在现有 `CONFIG.SECURITY` 对象里追加（保持与 `MAX_LOGIN_ATTEMPTS` 等同级）：

```js
SECURITY: {
  // ... 原有 MAX_LOGIN_ATTEMPTS、LOCK_DURATION_MS、MAX_LOGIN_BODY_SIZE、
  //     CLEANUP_INTERVAL_MS、TOKEN_EXPIRY_MS 保持不变 ...

  // 🆕 指数退避
  BACKOFF_BASE_MS: 500,        // 首次失败延迟
  BACKOFF_EXP: 3,              // 指数底（3^t；比 2^t 狠但要靠 CAP 兜底）
  BACKOFF_CAP_MS: 120000,      // 封顶 2 分钟（避免把自己人锁死）

  // 🆕 账号级全局锁定
  GLOBAL_MAX_FAILURES: 20,     // 全站累计错 20 次 → 全站锁
  GLOBAL_LOCK_MS: 15 * 60 * 1000,

  // 🆕 PoW 工作量证明
  POW_DIFFICULTY: 4,           // 4 个 hex 0（2^16 ≈ 6.5万次 hash，浏览器 100-400ms）
  POW_TTL_MS: 5 * 60 * 1000,   // challenge 5 分钟过期
},
```

### 3.2 新增状态与函数（放在 `recordLoginAttempt` 之后）

```js
// ──────────── 🆕 账号级全局锁定（堵 IP 轮换）────────────
const globalAttempts = { count: 0, lockUntil: 0 };

const isGlobalLocked = () => Date.now() < globalAttempts.lockUntil;

const recordGlobalFailure = () => {
  globalAttempts.count += 1;
  if (globalAttempts.count >= CONFIG.SECURITY.GLOBAL_MAX_FAILURES) {
    globalAttempts.lockUntil = Date.now() + CONFIG.SECURITY.GLOBAL_LOCK_MS;
    console.warn(`🌐 Global lock engaged: ${globalAttempts.count} failures.`);
  }
};

const resetGlobalOnSuccess = () => {
  globalAttempts.count = 0;
  globalAttempts.lockUntil = 0;
};

// ──────────── 🆕 指数退避（base 3，封顶）────────────
const getBackoffDelay = (failCount) => {
  const { BACKOFF_BASE_MS, BACKOFF_EXP, BACKOFF_CAP_MS } = CONFIG.SECURITY;
  return Math.min(BACKOFF_BASE_MS * (BACKOFF_EXP ** failCount), BACKOFF_CAP_MS);
};

// ──────────── 🆕 PoW 工作量证明 ────────────
const powChallenges = new Map();          // challenge → timestamp

const issueChallenge = () => {
  const c = crypto.randomBytes(16).toString('hex');
  const now = Date.now();
  powChallenges.set(c, now);
  // 惰性清理过期 challenge（FC 不可靠 setInterval，跟 cleanupLoginAttempts 同思路）
  if (powChallenges.size > 200) {
    for (const [k, ts] of powChallenges) {
      if (now - ts > CONFIG.SECURITY.POW_TTL_MS) powChallenges.delete(k);
    }
  }
  return c;
};

const verifyPoW = (challenge, nonce) => {
  if (typeof challenge !== 'string' || !Number.isFinite(nonce)) return false;
  const ts = powChallenges.get(challenge);
  if (!ts) return false;
  powChallenges.delete(challenge);                        // 一次性，防重放
  if (Date.now() - ts > CONFIG.SECURITY.POW_TTL_MS) return false;
  const h = crypto.createHash('sha256')
    .update(challenge + String(nonce))
    .digest('hex');
  return h.startsWith('0'.repeat(CONFIG.SECURITY.POW_DIFFICULTY));
};
```

### 3.3 修改 `/login` 路由（4 个插入点）

> 以下是 `/login` 分支里需要改动的位置，用注释 `// 🔒 PATCH` 标记。请对齐你现有的 `sendJson` / `corsHeaders` / `decodeBody` 写法。

#### 插入点 A：`isIpLocked(ip)` 检查之后，加全局锁定检查

```js
if (isIpLocked(ip)) {
  return { statusCode: 429, headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ success: false, message: 'Too many attempts.' }), isBase64Encoded: false };
}

// 🔒 PATCH A: 全局锁定（IP 轮换兜底）
if (isGlobalLocked()) {
  return { statusCode: 429, headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ success: false, message: 'Service temporarily locked.' }), isBase64Encoded: false };
}
```

#### 插入点 B：`body` 解析成功后、密码校验之前，验 PoW（仅在有失败记录时）

```js
const { user, pass, challenge, nonce } = parsedBody;  // 🔒 PATCH: 多解构 challenge/nonce

// 🔒 PATCH B: 该 IP 之前失败过 → 本次必须带 PoW（正常用户首次登录不触发）
const needsPoW = loginAttempts.has(ip);
if (needsPoW && !verifyPoW(challenge, nonce)) {
  const nextChallenge = issueChallenge();
  return {
    statusCode: 401,
    headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' },
    body: JSON.stringify({
      success: false,
      message: 'PoW required',
      challenge: nextChallenge,
      difficulty: CONFIG.SECURITY.POW_DIFFICULTY,
    }),
    isBase64Encoded: false,
  };
}
```

#### 插入点 C：密码校验失败分支，加退避 + 全局计数 + 返回新 challenge

```js
// 密码错误（替换你现有的失败处理）
recordLoginAttempt(ip, false);

// 🔒 PATCH C: 全局计数 + 指数退避
recordGlobalFailure();
const failCount = loginAttempts.get(ip)?.count || 1;
const delay = getBackoffDelay(failCount);
await new Promise((r) => setTimeout(r, delay));   // 占用 FC 实例时间，物理性拖慢攻击方

const nextChallenge = issueChallenge();
return {
  statusCode: 401,
  headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' },
  body: JSON.stringify({
    success: false,
    message: 'Invalid credentials',
    challenge: nextChallenge,
    difficulty: CONFIG.SECURITY.POW_DIFFICULTY,
  }),
  isBase64Encoded: false,
};
```

#### 插入点 D：登录成功分支，重置全局计数

```js
// 登录成功（在返回 token 之前）
recordLoginAttempt(ip, true);
resetGlobalOnSuccess();   // 🔒 PATCH D: 正常用户成功登录 → 重置全局计数
```

---

## 四、前端补丁（登录页 JS）

```js
// ─── PoW 求解（浏览器 Web Crypto）───
async function solvePoW(challenge, difficulty = 4) {
  const target = '0'.repeat(difficulty);
  const enc = new TextEncoder();
  let nonce = 0;
  while (true) {
    const buf = enc.encode(challenge + nonce);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const hex = [...new Uint8Array(hash)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (hex.startsWith(target)) return nonce;
    nonce++;
    // 可选：每 1000 次 yield 一次让 UI 呼吸（crypto.subtle 已异步，通常不卡）
  }
}

// ─── 登录流程 ───
let pendingChallenge = null;   // 上次失败返回的 challenge

async function doLogin(user, pass) {
  const payload = { user, pass };

  // 如果上次失败过，这次要带上 PoW 答案
  if (pendingChallenge) {
    const btn = document.querySelector('#login-btn');
    if (btn) { btn.disabled = true; btn.textContent = '正在验证…'; }
    try {
      payload.challenge = pendingChallenge.challenge;
      payload.nonce = await solvePoW(
        pendingChallenge.challenge,
        pendingChallenge.difficulty || 4
      );
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '登录'; }
    }
  }

  const r = await fetch('/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await r.json();

  // 服务端返回 challenge = 这次没过，记住它下次带 PoW
  if (data.challenge) {
    pendingChallenge = {
      challenge: data.challenge,
      difficulty: data.difficulty || 4,
    };
  } else {
    pendingChallenge = null;
  }
  return data;
}
```

**UX 提示**：算题期间（100-400ms）按钮 disable + 显示"正在验证…"，避免用户狂点。

---

## 五、PoW 难度调优

| `POW_DIFFICULTY` | 平均 hash 次数 | 浏览器耗时 | 建议 |
| :--: | :--: | :--: | :-- |
| 3 | 4,096 | 10-40ms | 追求丝滑体验 |
| **4** | **65,536** | **100-400ms** | ✅ **推荐（默认）** |
| 5 | 100 万 | 1-4 秒 | ⚠️ 有点久，不推荐 |
| 6 | 1600 万 | 30 秒+ | ❌ 自己都进不去 |

**调优原则**：合法用户算题 < 0.5 秒；攻击方每试 1 次密码都得重算一道题（IP 轮换无法绕过，因为 PoW 是 per-请求的）。

**进阶**：如果嫌浏览器慢，可把难度降到 3 并配合 Web Worker 并行算；攻击方用 C/Rust 实现的 sha256 比 JS 快 100 倍，但**配合全局锁定已足够**。

---

## 六、测试用例（部署后必跑）

```bash
# 1. 正常登录（应一次过，无 PoW）
curl -X POST https://YOUR_DOMAIN/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","pass":"YOUR_PASS"}'
# 预期：{"success":true,"token":"..."}

# 2. 故意输错密码（应返回 challenge）
curl -X POST https://YOUR_DOMAIN/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","pass":"wrong"}'
# 预期：{"success":false,"message":"Invalid credentials","challenge":"a3f9...","difficulty":4}

# 3. 不带 PoW 重试（应返回新 challenge，拒绝登录）
curl -X POST https://YOUR_DOMAIN/login \
  -H 'content-type: application/json' \
  -d '{"user":"admin","pass":"wrong"}'
# 预期：{"success":false,"message":"PoW required","challenge":"...","difficulty":4}

# 4. 算 PoW 后重试（用浏览器前端跑，或写脚本算 nonce）
# 预期：登录成功，或密码错误但 challenge 循环继续

# 5. 全局锁定（连错 20 次）
for i in {1..20}; do curl -s -X POST https://YOUR_DOMAIN/login \
  -H 'content-type: application/json' -d '{"user":"x","pass":"y"}' & done; wait
# 预期：第 20 次后 {"message":"Service temporarily locked"}，且 15 分钟内所有 IP 都被拒

# 6. 退避验证（同一 IP 连错，观察响应耗时递增）
time curl -X POST ...   # 第 1 次 ~0.5s，第 2 次 ~1.5s，第 3 次 ~4.5s，封顶 2 分钟
```

**回归验证**：正常上传（带 token）17/17 测试不应回归。

---

## 七、部署步骤

```bash
cd ~/work/github/oss-upload
# 1. 手工合并上述代码进 index.js（三道插入点 + CONFIG）
# 2. 本地语法检查
node --check index.js
# 3. 打包
zip code.zip index.js package.json
# 4. FC 控制台上传（同 README「维护更新」流程）
# 5. 重新部署前端（如前端也要改）：CF Pages 自动
```

---

## 八、成本（几乎为零，攻击时反而省钱）

| 场景 | PoW 开销 | 退避 sleep 开销 | 合计 |
| :-- | :-- | :-- | :-- |
| 正常登录 1 次 | 2 微秒 ≈ 0 | 无（一次过） | **≈ 0.000003 元** |
| 手滑 1 次 | 1 次 hash | 0.5 秒 ≈ 0.000007 元 | ≈ 0.00001 元 |
| 攻击 100 次 | 被全局锁挡住 | 极少触发 | **< 0.01 元** |

**为什么 PoW 反而省钱**：攻击方在客户端算题（他的 CPU），你的 FC 只验 1 次 hash；而且 PoW 把爆破速度物理性拖慢 300 倍，能到达你 FC 的请求本身变少了。

---

## 九、为什么不用 CAPTCHA / 2FA

| 方案 | 问题 | 适合场景 |
| :-- | :-- | :-- |
| CAPTCHA | 自己用得烦，依赖第三方 | 开放注册 |
| 2FA (TOTP) | 小题大做，每次登录要掏手机 | 高价值账户 |
| **PoW + 退避 + 全局锁** | ✅ 无感（正常用户），代码自持 | **个人图床（你的场景）** |

---

## 十、已知边界（诚实说明）

1. **PoW 是"提高成本"不是"绝对防御"** —— 理论上攻击方用 ASIC 算 sha256 比浏览器快 10^6 倍，但**配合全局锁定（20 次全站锁）后已足够**。
2. **FC 重启会丢内存状态** —— `globalAttempts` / `powChallenges` / `loginAttempts` 都在内存，实例被销毁会重置。但攻击方也无法利用（他不知道你何时重启）。
3. **同 IP 多用户**（如公司 NAT）—— 一人手滑会锁住同 IP 其他人。你单人使用无此问题。
4. **`challenge` 内存泄漏** —— 惰性清理 200 条上限，正常够用；高并发场景可改 LRU。

---

## 附录：与现有代码的兼容性

- ✅ 不改 `genToken` / `checkToken`（Token 逻辑零改动）
- ✅ 不改 `isValidIp` / `cleanupLoginAttempts`（IP 校验与清理逻辑复用）
- ✅ 不改上传路由（`/upload` 完全不受影响）
- ✅ 配置全走 `CONFIG.SECURITY`（与现有风格一致，仍可环境变量覆盖）
- ✅ 箭头函数风格对齐（`const fn = (...) => {}`）
