# Secure OSS Image Uploader

基于 **阿里云函数计算 (FC)** + **对象存储 (OSS)** 的自建图片上传服务。

浏览器登录 → 拿 token → 上传图片 → 返回 Markdown 图片语法。图片存进你自己的 Bucket，通过 CDN 域名对外访问，不依赖任何第三方图床。

- **单文件业务代码**：`index.js` 320 行，零框架、零硬编码，配置全部走环境变量
- **依赖走 Layer**：`ali-oss` SDK 独立打包，业务代码包仅 4.9 KB
- **生产级安全**：登录鉴权、Token 防重放、IP 防爆破、MIME + 魔数双重校验、体积多重防线

---

## 📦 获取文件

| 文件 | 从哪来 |
| :--- | :--- |
| `layer.zip`（3.25 MB） | **[Releases 页](https://github.com/ezzty/oss-upload/releases/latest) 直接下载** |
| `oss-upload-code.zip`（4.9 KB） | **同上，Release 附件** |
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
| `AUTH_PASS` | `Tu1111111` | 登录密码（建议 `openssl rand -base64 24`） |
| `JWT_SECRET` | `my-secret-key...` | Token 签名密钥（建议 `openssl rand -base64 32`） |
| `OSS_ACCESS_KEY_ID` | `LTAI...` | 阿里云 AccessKey ID |
| `OSS_ACCESS_KEY_SECRET` | `<your-accesskey-secret>` | 阿里云 AccessKey Secret |
| `OSS_BUCKET` | `ioss` | 目标 Bucket 名称 |
| `OSS_REGION` | `oss-cn-hangzhou` | Bucket 所在地域 ID |
| `CDN_DOMAIN` | `https://imageoss.com` | 图片访问域名，**必须带协议头**，结尾不要带 `/` |

外加 1 个**强烈建议**配置：

| 变量名 | 示例值 | 说明 |
| :--- | :--- | :--- |
| `ALLOWED_ORIGINS` | `your-site.com` | 允许跨域的来源域名，逗号分隔，**支持子域通配** |

> **`ALLOWED_ORIGINS` 一定要设。** 代码里的兜底值是占位符 `example.com`，不配置的话浏览器上传会被 CORS 拦死。

### 5. 创建 HTTP 触发器 + 绑定域名

- 创建 HTTP 触发器，鉴权方式选「免鉴权」（鉴权由代码自己做）
- 域名管理 → 绑定自定义域名 + HTTPS 证书

⚠️ **CORS 只能选一种**：要么在触发器设置里开「允许跨域」，要么取消 `index.js` 中 CORS 代码段的注释（第 198–209 行）。**两个都开会导致响应头重复**，浏览器报 CORS 错误。

---

## 🔌 API

| 方法 | 路径 | 说明 |
| :--- | :--- | :--- |
| POST | `/login` | 传 `{user, pass}`，返回 `{success, token}`（有效期 24h） |
| POST | `/upload` | 需 `Authorization: Bearer <token>`，body 为图片二进制 + `Content-Type: image/*` |
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

---

## 🛡️ 安全设计

| 防线 | 做法 |
| :--- | :--- |
| **配置强校验** | 8 个环境变量缺一即 `exit(1)`，宁可启动失败也不带残缺配置对外服务 |
| **登录体体积限制** | `/login` body 超 4 KB 直接 413，**在 `JSON.parse` 之前**，防大 body 打满内存 |
| **Token 防伪** | HMAC-SHA256 签名，`crypto.timingSafeEqual` 常数时间比较（防时序攻击） |
| **Token 防重放** | 内含随机 JTI（8 字节）+ 24h 过期；过期时间是签名的一部分，改不了 |
| **IP 防爆破** | 登录失败 5 次锁 15 分钟，内存计数，每小时自动清理过期记录 |
| **体积双重校验** | 先看 `Content-Length`，再量真实 body 长度兜底（防伪造 Header） |
| **类型双重校验** | `Content-Type` 白名单 + 魔数检测（JPEG/PNG/GIF/WebP/BMP） |
| **来源白名单** | `ALLOWED_ORIGINS` 支持子域通配；未配置则用占位兜底 |
| **安全响应头** | `X-Content-Type-Options: nosniff` + HSTS |

### ⚠️ 两个已知的平台行为

1. **通过 FC 自定义域名访问时，`nosniff` / HSTS 响应头可能被平台层剥掉**，用 `curl -I` 看不到。这不是代码 bug。
2. **IP 锁定是单实例内存级的** —— FC 多实例间不共享。它挡的是同一连接上的暴力尝试，不是分布式撞库。要防分布式需接 WAF 或验证码。

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

**2. 鉴权探针** —— 错误 token 传 `/upload`，期望 `401`：

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.your-domain.com/upload \
  -H "Authorization: Bearer wrong" -H "Content-Type: image/jpeg" --data-binary @test.jpg
```

**3. 真实上传** —— 页面上传一张图，确认返回 markdown 且 URL 可访问。

**4. 回 OSS 核实对象真的存在** —— 这一步不能省。CDN 有缓存，一张**已经从 OSS 删掉的图片**，CDN 节点可能继续返回 200 很长时间。只 curl CDN 会得到"一切正常"的假象。

上传验证 = **CDN 200 + OSS 里对象确实存在**，两个都对才算数。

### 上线前清单

- [ ] Bucket 是**私有**读写
- [ ] 用 RAM 用户的 AK，且策略**只授权这一个 Bucket**（别用主账号 AK）
- [ ] AK/SK 只在环境变量里，不在代码里、不在 Git 里
- [ ] `AUTH_PASS` / `JWT_SECRET` 是随机长串
- [ ] `ALLOWED_ORIGINS` 已设为你的前端域名
- [ ] CORS 只配了一处（控制台 **或** 代码，不是两个）
- [ ] 验收 1 返回 413、验收 2 返回 401

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
| 浏览器 CORS 报错 | 控制台 CORS 和代码 CORS 同时开 | 二选一 |
| 浏览器 CORS 报错（换了前端域名） | `ALLOWED_ORIGINS` 没更新 | 加上新域名 |
| 预览图显示了但 OSS 里没有 | `blob:` URL 是本地内存地址，选中文件就生成，**不代表已上传** | 以上传成功回调为准 |
| 上传成功但 URL 404 | `CDN_DOMAIN` 域名没配 / 没绑证书 / Bucket 是私有的 | 检查域名与 CDN 回源配置 |

---

## 📄 License

MIT
