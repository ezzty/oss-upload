# Secure OSS Image Uploader

基于 **阿里云函数计算 (FC)** + **对象存储 (OSS)** 的自建图片上传服务。

浏览器登录 → 拿 token → 上传图片 → 返回 Markdown 图片语法。图片存进你自己的 Bucket，通过 CDN 域名对外访问，不依赖任何第三方图床。

- **单文件业务代码**：`index.js` 372 行，零框架、零硬编码，配置全部走环境变量
- **依赖走 Layer**：`ali-oss` SDK 独立打包，业务代码包仅 5.9 KB
- **生产级安全**：登录鉴权、Token 防篡改、IP 防爆破、MIME + 魔数双重校验、体积多重防线

---

## 📦 获取文件

| 文件 | 从哪来 |
| :--- | :--- |
| `layer.zip`（3.25 MB） | **[Releases 页](https://github.com/ezzty/oss-upload/releases/latest) 直接下载** |
| `oss-upload-code.zip`（5.9 KB） | **同上，Release 附件** |
| `index.js` / `package.json` | 本仓库，开发参考 / 自行打包 |

Release 附件即开即用，**不需要本地装 Node.js**。想自己构建依赖层见文末[「构建依赖层」](#构建依赖层)。

> `layer.zip` 内部结构为 FC 要求的 `nodejs/node_modules/`，含 `ali-oss@6.23.0` 及其依赖共 2338 个文件，**不含任何密钥**，只有 npm 包源码。

---

## 🚀 部署（5 步）

### 1. 创建依赖层（只需一次）

控制台 → **层管理** → **创建层**

- 名称：`oss-upload-dependencies`
- 运行时：**Node.js 18**
- 代码包：上传下载好的 `layer.zip`

记录层名称，第 2 步要绑定。

### 2. 创建函数

控制台 → **函数管理** → **创建函数**

- 函数类型：HTTP 函数
- 运行时：**Node.js 18**
- 处理程序（Handler）：`index.handler`
- 规格：**0.05 vCPU / 128 MB 内存 / 512 MB 磁盘**（最小规格，实测够用）
- **层配置**：绑定第 1 步创建的层

> 内存够用的前提是别传太大的图：代码把整个 body 读进内存，base64 解码还会再复制一份。128 MB 跑常规图片没问题；若你调高了上传上限并常传接近上限的大图，内存要跟着调。

### 3. 上传代码

函数代码页 → 上传 `oss-upload-code.zip` → 部署。

### 4. 配置环境变量 ⚠️

**8 个必填，缺任何一个函数启动即失败**（日志会打印 `❌ FATAL: Missing required environment variable: <KEY>`）：

| 变量名 | 示例值 | 说明 |
| :--- | :--- | :--- |
| `AUTH_USER` | `admin` | 登录用户名 |
| `AUTH_PASS` | `<your-strong-password>` | 登录密码，**必须自己生成**：`openssl rand -base64 24` |
| `JWT_SECRET` | `openssl rand -base64 32` | **签名密钥，32 字节 base64（256 bit）**。⚠️ **唯一能绕过全部防御的密钥**——泄露=攻击者可自己签发 token。必须用 `openssl rand -base64 32` 生成，< 32 字符等于裸奔 |
| `OSS_ACCESS_KEY_ID` | `LTAI...` | 阿里云 AccessKey ID |
| `OSS_ACCESS_KEY_SECRET` | `<your-accesskey-secret>` | 阿里云 AccessKey Secret |
| `OSS_BUCKET` | `ioss` | 目标 Bucket 名称 |
| `OSS_REGION` | `oss-cn-hangzhou` | Bucket 所在地域 ID |
| `CDN_DOMAIN` | `https://imageoss.com` | 图片访问域名，**必须带协议头**，结尾不要带 `/` |

外加 1 个**强烈建议**配置：

| 变量名 | 示例值 | 说明 |
| :--- | :--- | :--- |
| `ALLOWED_ORIGINS` | `your-site.com` | 允许跨域的来源域名，逗号分隔，**支持子域通配** |

> **`ALLOWED_ORIGINS` 只在「启用代码级 CORS」时才生效。** 默认 CORS 由 FC 控制台处理（见下方第 5 步），此时该变量**不参与任何逻辑**。若你选择启用代码级 CORS，就必须设它——代码里的兜底值是占位符 `example.com`，不配置会把浏览器上传全部拦死。

### 5. 创建 HTTP 触发器 + 绑定域名

- 创建 HTTP 触发器，鉴权方式选「免鉴权」（鉴权由代码自己做）
- 域名管理 → 绑定自定义域名 + HTTPS 证书

#### HTTP 触发器与 CORS

三种方式二选一，**默认就是「平台回显」**——网关直接把请求的 `Origin` 回显成 `Access-Control-Allow-Origin`，不校验来源：

| 方式 | 白名单 | 改代码 | 备注 |
| --- | --- | --- | --- |
| **API Configured CORS** | ✅ `allowOrigins` 数组 | 否 | **邀测**能力，需联系阿里云开通，走 API 配置，预检不计费 |
| **默认 CORS**（推荐，本项目默认） | ❌ 无，直接回显 | 否 | 平台默认行为 |
| **代码级 CORS** | ✅ 自己写判断 | 是（`index.js` 的 CORS 块） | 预检会调用函数并计费 |

⚠️ **FC 控制台里没有「勾选允许跨域 / 填白名单域名」这样的选项**——已核对官方文档，白名单只能通过 API Configured CORS 的 `allowOrigins` 或代码级 CORS 配置，**别照着某些教程去控制台里找这个开关**。

⚠️ **不要同时开默认回显和代码级 CORS**：函数返回的头会与平台回显合并，可能产生重复的 `Access-Control-Allow-Origin`，浏览器会直接报错。要么取消 `index.js` 里代码级 CORS 的注释、要么不动，**二选一**。

> 启用代码级 CORS 后**必须**设置 `ALLOWED_ORIGINS`，否则兜底值 `example.com` 会拦掉所有浏览器请求。

**个人图床的建议**：先用默认 CORS 就够。它确实放行任意 `Origin`，但那只是「浏览器放不放行」，真正的门是 token 鉴权——没 token 照样 `401`。要收紧就申请开通 API Configured CORS，配 `allowOrigins: ["https://your-site.com"]`（⚠️ 它**不支持子域通配**，要逐个枚举）。

---

## 🔌 API

| 方法 | 路径 | 说明 |
| :--- | :--- | :--- |
| GET | `/challenge` | 🆕 **发 PoW 题**，返回 `{challenge, difficulty}`。登录前必须先拿到 |
| POST | `/login` | 传 `{user, pass, challenge, nonce}`，返回 `{success, token}`（有效期 **2h**）。⚠️ **必须带 PoW 答案**，不带直接返回 `PoW required` + 新 challenge |
| POST | `/upload` | 需 Authorization Bearer token，body 为图片二进制 + `Content-Type: image/*`。🆕 **配额 299 次/天/token**，超限 429 |
| GET | `/verify` | 传 Bearer token，返回 `{success: true/false}`，用于刷新页面后校验 token |

上传成功返回：

```json
{
  "success": true,
  "markdown": "![image](https://img.example.com/m/26j13/ab12cd.jpg)",
  "direct": "https://img.example.com/m/26j13/ab12cd.jpg"
}
```

支持格式：JPEG / PNG / GIF / WebP / BMP。单文件上限 **20 MB**。

### 前端对接

前端页面（登录 + 拖拽上传 + Markdown 输出）需要自行准备，只需填你的 API 域名：

```javascript
const _FC_PARTS = ['https://', 'api.your-domain.com'];
```

注意：前端的体积校验要和服务端的 20 MB 对齐，**以小的为准**。

🆕 **登录必须走 PoW 流程**（否则服务端返回 `PoW required`）：

```javascript
// 1. 页面加载时拿 challenge
const { challenge, difficulty } = await (await fetch(`${FC_URL}/challenge`)).json();

// 2. 算 PoW（浏览器 Web Crypto）
async function solvePoW(challenge, difficulty = 4) {
  const target = '0'.repeat(difficulty);
  const enc = new TextEncoder();
  let nonce = 0;
  while (true) {
    const hash = await crypto.subtle.digest('SHA-256', enc.encode(challenge + nonce));
    const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
    if (hex.startsWith(target)) return nonce;
    nonce++;
  }
}
const nonce = await solvePoW(challenge, difficulty);

// 3. 带 PoW 登录
await fetch(`${FC_URL}/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ user, pass, challenge, nonce })
});
// 密码错时服务端会返回新 challenge，前端要记住它下次带
```

> **算题耗时**：difficulty=4 时浏览器约 100-400ms。正常用户一次登录只算 1 道题，**无感**；攻击方每次尝试都要算，爆破速度被物理性拖慢 300 倍。

---

## 📂 存储路径格式

```
m/YY{月字母}DD/{6位十六进制}.{扩展名}
```

例如 `m/26j13/ab12cd.jpg` = 2026 年 10 月 13 日上传。

| 月份 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| 字母 | a | b | c | d | e | f | g | h | i | **j** | k | l |

- **按北京时间生成**（代码里 `+8小时` 后取 UTC 分量），否则 FC 默认 UTC，北京时间 0:00–7:59 的上传会落到前一天的目录
- 文件名 `crypto.randomBytes(3)` = 6 位 hex，约 1677 万种组合，配合每日目录几乎不可能覆盖已有文件
- **不需要** `img/` 之类的额外层级，每省一个目录 URL 短一截

### OSS 图片处理（强烈推荐）

OSS 自带图片处理，URL 后面加参数即可实时生成缩略图，**不占用额外存储**：

```
https://img.example.com/m/26j13/ab12cd.jpg?x-oss-process=style/w950
```

先在 OSS 控制台创建样式 `w950`（宽 950px、自动转 WebP、质量自适应）。

**实测效果**（真实数据）：

|  | 大小 |
| --- | --- |
| 原图 | 1.89 MB |
| `?x-oss-process=style/w950` | **81 KB（省 96%）** |

网页里引用大图是浪费带宽的头号原因——**正文永远用样式 URL，点击看原图**。

---

## 🛡️ 安全设计

| 防线 | 做法 |
| :--- | :--- |
| **配置强校验** | 8 个环境变量缺一即 `exit(1)`，宁可启动失败也不带残缺配置对外服务 |
| **登录体体积限制** | `/login` body 超 4 KB 直接 413，**在 `JSON.parse` 之前**，且用未解码长度先判（不为垃圾请求分配 Buffer） |
| **Token 防伪** | HMAC-SHA256 签名，`crypto.timingSafeEqual` 常数时间比较（防时序攻击）；签名先校验 64 位 hex 再按 hex 解码 |
| **Token 有效期** | 内含过期时间且过期时间在签名内，**改不了**；**2 小时**后失效（缩短被盗窗口）。⚠️ **不防重放**——token 在有效期内可重复使用，见下方说明 |
| **IP 防爆破** | 登录失败 5 次锁 15 分钟，`Map` 计数，上限 1000 条 + 惰性清理 |
| **IP 可信来源** | 优先取 FC 平台注入的 `requestContext.http.sourceIp`，不信任客户端可伪造的 `X-Forwarded-For` 最左值 |
| **原型污染免疫** | 防爆破表用 `Map` + IP 格式校验，`X-Forwarded-For: __proto__` 之类特殊键直接失效 |
| **体积多重校验** | 全局未解码长度粗判 → `Content-Length` → 真实 body 长度兜底，三层 |
| **类型双重校验** | `Content-Type` 白名单（大小写归一）+ 魔数检测（JPEG/PNG/GIF/WebP/BMP） |
| **方法限制** | `/login` `/upload` 仅接受 POST，其余返回 405 |
| **惰性解码** | 鉴权通过后才把 body 解成 Buffer，未认证的大 body 不占用内存（适配 128 MB 小规格） |
| **来源白名单** | `ALLOWED_ORIGINS` 支持子域通配，**仅在启用代码级 CORS 时生效**；默认由 FC 控制台 CORS 负责 |
| 🆕 **强制 PoW** | 每次登录必须算 sha256 前 4 位 hex 0（≈6.5 万次 hash，浏览器 100-400ms）。**不看历史记录**（FC 多实例内存不共享，所以不依赖 `loginAttempts` 判断） |
| 🆕 **指数退避** | 登录失败 `500ms × 3^t`，封顶 2 分钟。**服务端 sleep**——攻击方算 PoW 多快都没用，硬延迟 |
| 🆕 **全局锁定** | 全站累计 20 次登录失败 → 全站锁 15 分钟（IP 轮换兜底） |
| 🆕 **PoW 防重放** | challenge 一次性，`powChallenges.delete()` 用过即废；5 分钟过期 |
| 🆕 **上传配额** | per-token 每日 **299 次**（按 jti 计），超限 429。防 token 被盗后滥用/塞满 OSS |
| **安全响应头** | `X-Content-Type-Options: nosniff` + HSTS + `Cache-Control: no-store`（token 响应不被中间层缓存） |

### ⚠️ 关于「防重放」—— 分清两种

**1. Token 不防重放**（登录后）
token 里的 `jti` 只是随机数，**没有服务端存储**：
- ✅ 防篡改（改一个字符签名就失效）
- ✅ 防过期（过期时间在签名里，**2 小时**）
- ❌ **不防重放**：同一个 token 在 2 小时内可以反复使用

要真正防重放需要外部存储（Redis / Tablestore）做 jti 黑名单，这会引入额外依赖，对个人图床不划算。**如果 token 泄露，立刻改 `JWT_SECRET` 并重启函数**，所有已发 token 立即作废。

**2. PoW challenge 防重放**（登录时）✅
登录流程的 PoW challenge **是一次性的**：
- `powChallenges.delete(challenge)` 验证后立即删除
- 5 分钟过期
- 同一个 `challenge+nonce` 二次使用 → `PoW required`

所以**登录爆破**这条路是防重放的；只有**登录后**的 token 是不防重放的。

### ⚠️ 两个已知的平台行为

1. **通过 FC 自定义域名访问时，`nosniff` / HSTS 响应头可能被平台层剥掉**，用 `curl -I` 看不到。这不是代码 bug。
2. **IP 锁定和全局锁定是单实例内存级的** —— FC 多实例间不共享，会被稀释。**但强制 PoW 不依赖内存状态**（每次请求都要算题），所以分布式撞库依然被拖慢 300 倍。PoW + 指数退避（服务端 sleep）共同弥补了多实例的稀释问题。

---

## 🧩 核心实现（代码级）

上一节是「有哪些防线」，这里是「怎么实现的」。

### Token 结构（自实现，不引第三方 JWT 库）

```
token = username . 过期时间戳 . jti . HMAC-SHA256(username.exp.jti, JWT_SECRET)
```

四个安全点：

1. `crypto.timingSafeEqual` **常数时间比较** —— 不用 `===`，避免通过响应耗时逐字节猜签名（时序攻击）
2. `jti`（`randomBytes(8)`，16 位 hex）保证每次签发不同 —— ⚠️ 但它**不防重放**，见上一节
3. **24 小时过期** —— 过期时间是签名的一部分，改不了
4. **校验用户名** —— token 必须对得上当前配置的 `AUTH_USER`，换密码/换用户后旧 token 自动失效

### MIME 白名单 + 魔数检测

```javascript
const ALLOWED_MIME_TYPES = new Set([
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'
]);
```

`Content-Type` 头由客户端说了算，所以还要读文件头字节判断真实类型：

| 类型 | 魔数 |
| --- | --- |
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38 39/61 61` |
| WebP | `RIFF....WEBP`（RIFF + 偏移 8 处 WEBP） |
| BMP | `42 4D` |

两道都过才存。这样即使有人把 `.php` 重命名为 `.jpg` 上传，服务端也会因为魔数对不上而拒绝。

### 体积校验：三道，一道比一道真

```javascript
// ① 全局兜底：未解码长度粗判（防伪造 Content-Length，且不分配 Buffer）
if (approxBytes > CONFIG.SECURITY.MAX_FILE_SIZE) return 413;

// ② 看客户端声明的 Content-Length 头
const cl = parseInt(hdrs['content-length'] || '0', 10);
if (cl > CONFIG.SECURITY.MAX_FILE_SIZE) return 413;

// ③ 真实 body 长度（兜底）
if (bodyBuf.length > CONFIG.SECURITY.MAX_FILE_SIZE) return 413;
```

只信 `Content-Length` 是危险的——它由客户端声明，可以伪造小数值绕过检查。**必须再量一次真实字节数**。

### 登录体 4KB 上限

```javascript
if (bodyBuf.length > CONFIG.SECURITY.MAX_LOGIN_BODY_SIZE) {  // 4KB
    return { statusCode: 413, ... };
}
```

**这是个容易被忽略的防护**：`/login` 只需要 `{user, pass}` 两个字段，但如果没有体积上限，攻击者可以 POST 一个 10MB 的 body 让服务端做 `JSON.parse`，用极小的代价打满内存。4KB 足够装下正常登录请求，超了直接 413，**连 JSON 解析都不进**。

> 这个检查必须放在 `JSON.parse` **之前**才有效。

### IP 防爆破：为什么必须用 `Map`

```javascript
const loginAttempts = new Map();      // ⚠️ 用 Map，不要用普通对象 {}
const isValidIp = (ip) =>
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[0-9a-fA-F:]{3,45}$/.test(ip);
```

防爆破表的键来自请求头。如果用 `{}` 而客户端送 `X-Forwarded-For: __proto__`，执行 `loginAttempts[ip].count += 1` 就会把 `count` 写进 `Object.prototype`，**污染进程里所有空对象**（实测 `{}.__proto__.count` 变成 `NaN`，且之后每个空对象都凭空多出 `count` 属性）。`Map` 天然免疫，再加 IP 格式校验把特殊键挡在门外。

**IP 从哪拿**：优先 `requestContext.http.sourceIp`（FC 平台注入、客户端改不了），`X-Forwarded-For` 最左值是客户端可控的，只能当兜底。


### 🆕 强制 PoW：让每次尝试都昂贵

登录必须带 `challenge + nonce`，服务端算 1 次 sha256 验证：

```js
const verifyPoW = (challenge, nonce) => {
    const ts = powChallenges.get(challenge);
    if (!ts) return false;
    powChallenges.delete(challenge);            // 一次性，防重放
    const h = crypto.createHash('sha256').update(challenge + String(nonce)).digest('hex');
    return h.startsWith('0'.repeat(4));         // 4 位 hex 0 ≈ 6.5 万次 hash
};
```

**为什么"强制"而不是"失败后才要求"**：FC 多实例内存不共享，`loginAttempts.has(ip)` 判断不可靠（可能刚好路由到没记录的实例）。所以**不看历史**，一律要求 PoW —— 攻击方换 IP、换实例、GPU 加速都无效（每次都要算）。

**为什么 GPU 加速没用**：攻击方可以用 ASIC 把 sha256 算快 10^6 倍，但**指数退避是服务端 sleep**（见下）——你算多快我都要等 2 分钟。

### 🆕 指数退避：服务端硬延迟

```js
const getBackoffDelay = (failCount) =>
    Math.min(500 * 3 ** failCount, 120000);   // 500ms 起，3 倍增长，封顶 2 分钟

// 失败分支
await new Promise((r) => setTimeout(r, getBackoffDelay(failCount)));
```

**关键**：`await sleep` 在**服务端**执行，攻击方的算力再强也没用。第 5 次失败后强制等 2 分钟（FC 实例空转，成本 0.0008 元）。

**为什么 base 3 而不是 base 2**：增长更狠（第 5 次就到顶），配合 `CAP_MS: 120000` 封顶防止把自己人锁死（不封顶 3^8 = 1.8 小时）。

### 🆕 上传配额：防滥用/塞满 OSS

```js
const checkUploadQuota = (jti) => {
    const today = new Date().toISOString().slice(0, 10);
    const rec = uploadQuota.get(jti);
    if (!rec || rec.date !== today) {
        uploadQuota.set(jti, { count: 1, date: today });
        return true;
    }
    return rec.count < 299;   // per-token 每日 299 次
};
```

**为什么按 jti 而不是 IP**：token 是按设备签发的（jti 唯一），按 jti 计数更精确；换 IP 不影响配额。

**为什么 299 次/天**：299 × 20MB = 6GB/天 ≈ 0.72 元/天 ≈ 22 元/月封顶。即使 token 被盗滥用，成本可控。

**已知局限**：FC 多实例内存不共享，配额计数会被稀释（N 实例 ÷ N）。**配合 OSS 生命周期规则**（自动清理旧对象）+ 账单告警更稳。


### 来源白名单（仅启用代码级 CORS 时生效）

```javascript
const ALLOWED_HOSTS = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : ['<你的域名>'];   // ⚠️ 代码里的兜底值，部署时务必用 ALLOWED_ORIGINS 覆盖

const isValidOrigin = (origin) => {
    const h = new URL(origin).hostname;
    return ALLOWED_HOSTS.some(domain => h === domain || h.endsWith('.' + domain));
};
```

- 支持**子域通配**：填 `example.com` 则 `www.example.com`、`blog.example.com` 都放行
- 没有 Origin 头的请求放行（服务端脚本、curl 调试场景）

### 安全响应头

```javascript
'x-content-type-options': 'nosniff',
'strict-transport-security': 'max-age=31536000; includeSubDomains',
'cache-control': 'no-store'          // 登录返回的 token 不许被中间层缓存
```

`nosniff` 阻止浏览器把 JSON 当脚本执行，HSTS 强制 HTTPS，`no-store` 防止 CDN/代理缓存住登录响应里的 token。

### FC 事件格式兼容与 body 解码（含两个坑）

```javascript
const path = parsedEvent.rawPath || parsedEvent.path || parsedEvent.pathName || '/';
const method = (((rc.http && rc.http.method) || parsedEvent.httpMethod
                 || hdrs['x-http-method-override'] || 'GET') + '').toUpperCase();

// 惰性解码：先用未解码长度粗判，鉴权通过后才真正分配 Buffer
const rawBody = parsedEvent.body || '';
const approxBytes = parsedEvent.isBase64Encoded
    ? Math.floor(String(rawBody).length * 3 / 4)
    : Buffer.byteLength(String(rawBody));

let _bodyBuf = null;
const decodeBody = (encoding) => {      // ← 编码必须显式指定，见下
    if (_bodyBuf === null) {
        _bodyBuf = parsedEvent.isBase64Encoded
            ? Buffer.from(String(rawBody), 'base64')
            : Buffer.from(String(rawBody), encoding || 'utf8');
    }
    return _bodyBuf;
};

// /login  → decodeBody()          JSON 文本，按 utf8 还原（中文密码也能正确解析）
// /upload → decodeBody('binary')  图片字节流，见下面的坑
```

FC 不同版本的 HTTP 触发器事件结构不一样，而且**二进制 body 常常被 base64 编码**。不处理 `isBase64Encoded`，你会收到一坨 base64 文本然后魔数校验永远失败——这是新人最常见的翻车点。

⚠️ **坑一：别一进 handler 就解码**。那意味着任何未认证的请求都能让你先分配几十 MB Buffer（FC 规格才 128 MB）。正确顺序是**先判路径 → 再鉴权 → 最后解码**，长度粗判用 `approxBytes` 就够（base64 解码后约 `len × 3/4`，无需真解）。

⚠️ **坑二：未编码的二进制 body 不能按 UTF-8 解**。`Buffer.from(str)` 默认就是 `utf8`，图片字节流里的高位字节（比如 PNG 头的 `0x89`）不是合法 UTF-8，会被解码成替换字符 `�`，**字节就永久毁了**——于是魔数校验对一张正常图片也永远失败，报 `Invalid file content`。这与「没处理 `isBase64Encoded`」症状一模一样，但按那条思路查会走进死胡同。

实测踩坑过程：桌面浏览器和安卓都传得好好的，**iOS 必失败**，服务端把收到的头打印出来才发现 `Content-Length: 0` / `rawLen=0`——根因其实在前端（iOS Safari 对 `xhr.send(File)` 会丢 body，见下节），但**顺带暴露了这个解码 bug**：只要客户端不走 base64 编码，`Buffer.from(str)` 这条路就必然毁字节。

修法就是 `decodeBody('binary')`（`'binary'` 即 latin1，一个字符对应一个字节，不会损坏高位字节）。**只在图片那条路径用**；登录 body 是 JSON 文本，必须按 utf8 解，否则中文用户名/密码会乱码。

### 前端发送：别直接 `xhr.send(File)`

```javascript
// ❌ 写起来最自然，但 iOS Safari 上服务端收到 0 字节
xhr.send(currentFile);

// ✅ 先读成 ArrayBuffer 再发
const buf = await currentFile.arrayBuffer();
xhr.setRequestHeader('Content-Type', currentFile.type || 'application/octet-stream');
xhr.send(buf);
```

**诊断特征**：桌面和安卓都正常，**iOS 必失败**，大小图都一样；服务端打印收到的请求头，显示 `Content-Length: 0`、`rawLen=0`、`te=none`，而前端明明 `file.size = 5311352`。**body 是在浏览器发出去之前就没写**，不是网关截断、不是格式问题。

两个配套细节：

- **必须显式设 `Content-Type`**：`ArrayBuffer` 发出去默认是 `application/octet-stream`，会被 MIME 白名单拒掉
- **别加自定义请求头**（比如 `X-Client-Size` 之类的调试头）：预检的 `Access-Control-Allow-Headers` 是固定值 `content-type, authorization`，多一个头浏览器会直接把请求拦下，症状变成「完全发不出去」

> 排查这类问题别靠猜：在前端把 `file.size`、在服务端把 `rawLen`/`content-length` **两边都打印出来对比**，一行数据就能定案。

---

## 🔧 构建依赖层

不想用 Release 附件、或想升级依赖版本时，本地构建：

```bash
mkdir -p layer-build/nodejs
cd layer-build
npm init -y
npm install ali-oss
cd nodejs && zip -r ../layer.zip node_modules
```

内部结构必须是 `nodejs/node_modules/`，否则函数启动会报 `Cannot find module 'ali-oss'`（返回 500）。

升级依赖后：控制台发布新层版本 → 函数切到新版本，**不用改业务代码**。

---

## 🧪 上线验收

部署完别急着宣布成功，按顺序验：

**1. 确认新代码已生效** —— 发一个 10 KB 的登录请求，期望返回 `413 Request too large`：

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.your-domain.com/login \
  -H "Content-Type: application/json" \
  -d '{"password":"xxxxxxxx…10000个x…"}'
```

返回 `413` = 新代码生效；返回 `200`/`401` = **线上跑的是旧代码**，重新检查部署包。

> 用 python 探针的等价写法（适合放进 CI）：
> ```bash
> python3 -c "
> import urllib.request, json
> body = json.dumps({'password': 'x' * 10000}).encode()   # 10KB 登录体
> req = urllib.request.Request('https://api.your-domain.com/login',
>       data=body, method='POST', headers={'Content-Type': 'application/json'})
> try:
>     urllib.request.urlopen(req, timeout=20)
> except Exception as e:
>     print('HTTP', getattr(e, 'code', '?'))
> "
> ```

**1.5 顺带验方法限制** —— 新版 `/login` `/upload` 只收 POST，其余返回 405：

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://api.your-domain.com/login
```

期望 `405`；返回 `400`/`401` 说明线上还是旧版代码。**这一招是本项目最有价值的运维技巧：代码改动有没有真正上线，一个探针就能验出来**，不靠「我明明传了啊」。

**1.8 🆕 PoW 流程探针** —— 不带 challenge 登录，期望 `PoW required`：

```bash
curl -s -X POST https://api.your-domain.com/login \
  -H "Content-Type: application/json" \
  -d '{"user":"test","pass":"wrong"}'
# 期望: {"success":false,"message":"PoW required","challenge":"...","difficulty":4}
```

返回 `Invalid credentials`（而非 `PoW required`）= **线上是旧代码**（强制 PoW 未生效）。

**1.9 🆕 /challenge 端点探针**：

```bash
curl -s https://api.your-domain.com/challenge
# 期望: {"success":true,"challenge":"<32 hex>","difficulty":4}
```

**2. 鉴权探针** —— 错误 token 传 `/upload`，期望 `401`：

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.your-domain.com/upload \
  -H "Authorization: Bearer wrong" -H "Content-Type: image/jpeg" --data-binary @test.jpg
```

**3. 真实上传** —— 页面上传一张图，确认返回 markdown 且 URL 可访问。

**4. 回 OSS 核实对象真的存在** —— 这一步不能省。CDN 有缓存，一张**已经从 OSS 删掉的图片**，CDN 节点可能继续返回 200 很长时间。只 curl CDN 会得到"一切正常"的假象。

```python
import oss2
auth = oss2.Auth('<AK>', '<SK>')
b = oss2.Bucket(auth, 'https://oss-cn-hangzhou.aliyuncs.com', 'my-img')
print('存在:', b.object_exists('m/26j13/ab12cd.jpg'))
```

上传验证 = **CDN 200 + OSS 里对象确实存在**，两个都对才算数。

### 上线前清单

- [ ] Bucket 是**私有**读写
- [ ] 用 RAM 用户的 AK，且策略**只授权这一个 Bucket**（别用主账号 AK）
- [ ] AK/SK 只在环境变量里，不在代码里、不在 Git 里
- [ ] `AUTH_PASS` / `JWT_SECRET` 是随机长串
- [ ] CORS 只配了一处（**控制台 或 代码，不是两个**）
- [ ] 若启用了代码级 CORS → `ALLOWED_ORIGINS` 已设为你的前端域名（未启用则不需要）
- [ ] 验收 1 返回 413、验收 2 返回 401
- [ ] `GET /login` 返回 405（确认 method 限制生效）

---

## 🔄 维护更新

| 场景 | 操作 |
| :--- | :--- |
| 改业务代码 | 改 `index.js` → `zip code.zip index.js package.json` → 控制台上传部署 → **跑验收 1 确认生效** |
| 升级依赖 | 重新 `npm install ali-oss` 打 `layer.zip` → 发布新层版本 → 函数切换 |
| 换密钥 | RAM 生成新 AK → 更新环境变量并部署 → 确认正常后**在 RAM 控制台禁用旧 AK** |

**换 AK 要定期做**，这是防止泄露后长期被动的唯一手段。

---

## ❓ 排错

| 现象 | 原因 | 解决 |
| :--- | :--- | :--- |
| 500，日志 `Cannot find module 'ali-oss'` | 层没绑，或 zip 内结构不是 `nodejs/node_modules/` | 绑定层 / 重建层 |
| 500，日志 `❌ FATAL: Missing required environment variable` | 环境变量缺项 | 补齐 8 个必填 |
| 500，日志 `CDN_DOMAIN must include protocol` | `CDN_DOMAIN` 没带协议头 | 改成 `https://...` |
| 登录成功但上传 401 | token 过期（24h）或 `JWT_SECRET` 被改过 | 重新登录 |
| 上传 400 `Invalid file content` | 文件不是白名单类型，或魔数对不上 | 检查文件真实格式 |
| 上传 413 `File too large` | 超过 20 MB | 前端也应拦一道 |
| 上传 429 `Too many attempts` | 该 IP 登录失败满 5 次，锁 15 分钟 | 等待或重启函数 |
| 魔数校验永远失败 | body 被 base64 编码但没解 | 检查 `isBase64Encoded` 分支 |
| 魔数校验永远失败，但图片**没走 base64** | 未编码 body 按 UTF-8 解码，高位字节被毁 | `/upload` 用 `decodeBody('binary')`，见「核心实现」 |
| 只有 iOS 上传失败，安卓/桌面正常；服务端 `rawLen=0` | iOS Safari 对 `xhr.send(File)` 丢 body | 先 `await file.arrayBuffer()` 再发，见「前端发送」 |
| 凌晨上传的图落到前一天目录 | FC 用 UTC 取日期 | 用 `+8小时` 偏移 |
| 自定义域名下看不到 `nosniff`/HSTS 头 | 平台层剥掉了 | 平台行为，不是 bug |
| 本地代码改了，线上行为没变 | 部署包不是最新的 | 跑「上线验收」探针确认 |
| `GET /login` 返回 400/401 而不是 405 | 线上是旧版代码（新版只收 POST） | 重新上传部署包 |
| 登录/上传返回 405 | 用了 GET 等非 POST 方法 | 按 API 表用 POST |
| 浏览器 CORS 报错 | 控制台 CORS 和代码 CORS 同时开 | 二选一 |
| 浏览器 CORS 报错（启用了代码级 CORS） | `ALLOWED_ORIGINS` 没设或没更新 | 设为你的前端域名 |
| 上传 413 但文件贴着 20 MB 边界 | base64 估算值比真实解码结果大 0–2 字节（padding 造成） | 属边界效应，文件距上限留 1 KB 余量即可 |
| 预览图显示了但 OSS 里没有 | `blob:` URL 是本地内存地址，选中文件就生成，**不代表已上传** | 以上传成功回调为准 |
| 上传成功但 URL 404 | `CDN_DOMAIN` 域名没配 / 没绑证书 / Bucket 是私有的 | 检查域名与 CDN 回源配置 |

---

## 📄 License

MIT
