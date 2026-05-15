# 🚀 Secure OSS Image Uploader

基于 **阿里云函数计算 (FC)** + **OSS 对象存储** 的高安全性图片上传服务。
采用 **Layer 依赖分离** 架构，代码仅 **2KB**，所有配置通过 **环境变量** 注入，零硬编码，生产级安全。

---

## 📁 核心文件清单

| 文件名 | 大小 | 说明 | 用途 |
| :--- | :--- | :--- | :--- |
| `index_minimal.js` | ~4KB | **业务源码** | 开发参考 |
| `code_minimal.zip` | ~2KB | **部署包** | 上传至函数计算控制台 |
| `upload.html` | ~28KB | **前端页面** | 部署至 OSS 或 Web 服务器 |
| `layer.zip` | ~3MB | **依赖层** | `ali-oss` SDK，上传至 FC 层管理 |

---

## 🛠️ 部署指南

### 第一步：配置依赖层 (Layer)
*只需操作一次。*
1. 进入 [阿里云函数计算控制台](https://fcnext.console.aliyun.com/)。
2. 点击左侧 **层管理** -> **创建层**。
3. 上传 `layer.zip`，运行时选择 **Node.js 18**。
4. 记录层名称（例如：`oss-upload-dependencies`）。

### 第二步：部署函数与配置
1. 创建/进入函数 -> **函数配置** -> **编辑**。
2. **层配置**：绑定第一步创建的层。
3. **代码部署**：上传 `code_minimal.zip`。
4. **环境变量配置** (⚠️ 必须全部配置，否则服务拒绝启动):

| 变量名 (Key) | 示例值 | 说明 | 必填 |
| :--- | :--- | :--- | :---: |
| `AUTH_USER` | `admin` | 登录用户名 | ✅ |
| `AUTH_PASS` | `Tupm20158@` | 登录密码 | ✅ |
| `JWT_SECRET` | `my-secret-key...` | Token 加密密钥 (建议复杂随机串) | ✅ |
| `OSS_ACCESS_KEY_ID` | `LTAI...` | 阿里云 AccessKey ID | ✅ |
| `OSS_ACCESS_KEY_SECRET` | `<your-accesskey-secret>` | 阿里云 AccessKey Secret | ✅ |
| `OSS_BUCKET` | `ifcr` | 目标 Bucket 名称 | ✅ |
| `OSS_REGION` | `oss-cn-hangzhou` | Bucket 所在地域 ID | ✅ |
| `CDN_DOMAIN` | `https://i.example.com` | **必须包含协议**，图片访问/返回域名 | ✅ |
| `PORT` | `9000` | 服务监听端口 (默认 9000) | ❌ |

5. 保存并部署。

### 第三步：部署前端
1. 将 `upload.html` 上传至你的 Web 服务器或 OSS。
2. **修改配置**：打开 HTML 文件，找到 `_FC_PARTS` 数组，修改为你的**函数计算自定义域名** (API 域名)。
   ```javascript
   // 修改为你的 API 域名，例如:
   const _FC_PARTS = ['https://', 'uposs-api.example.com'];
   ```
3. **CORS 注意**：函数代码默认允许 `*.example.com` 来源。如果前端部署在其他域名，需修改 `index_minimal.js` 中的 `isAllowedDomain` 逻辑。

---

## 🛡️ 安全特性

1.  **全量环境变量校验**：核心配置（含用户名、Region、CDN）均强制要求，无默认值，启动时检查。
2.  **JWT 动态鉴权**：包含随机 JTI 防重放攻击，Token 有效期 24 小时。
3.  **CORS 严格白名单**：拒绝非白名单域名的跨域请求，使用反射 Origin 机制。
4.  **MIME 强校验**：服务端拦截非图片文件 (仅允许 JPEG/PNG/GIF/WEBP/BMP)。
5.  **双重流量保护**：Header 预判 + 实时流检查，超过 20MB 立即切断连接，防止恶意刷流量。
6.  **防爆破机制**：内存级 IP 计数，登录失败 5 次锁定 15 分钟。
7. **安全文件名**：使用 `crypto.randomBytes(6).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 6)` 生成 6 位 Nano ID 文件名，防止恶意覆盖（日期目录天然隔离碰撞）。

---

## 🔄 维护与更新

### 更新代码逻辑
1. 修改本地 `index_minimal.js`。
2. 重新打包 `code_minimal.zip` (包含 `index.js` 和 `package.json`)。
3. 在控制台上传新代码包。

### 更新前端界面
1. 修改 `upload.html`。
2. 重新上传至 Web 服务器。
3. **建议**：上传时设置 `Cache-Control: no-cache` 防止旧版本缓存。

### 更新依赖库
1. 本地运行 `npm install ali-oss`。
2. 将 `node_modules` 重新打包为 `layer.zip` (需符合 `nodejs/node_modules/` 目录结构)。
3. 在控制台发布新版本 Layer 并更新函数绑定。
