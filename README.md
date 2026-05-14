# 🚀 OSS 图片上传系统使用说明

本项目基于 **阿里云函数计算 (FC)** + **对象存储 (OSS)** + **前端静态页** 构建。
架构特点：**代码依赖分离 (Layer)**、**全环境变量管理**、**零敏感信息泄露**。

---

## 📁 核心文件清单

位于 `/home/jin/work/oss/oss-upload/` 目录下：

| 文件名 | 大小 | 用途 | 部署位置 |
| :--- | :--- | :--- | :--- |
| `code_minimal.zip` | ~2KB | **业务代码** (不含依赖) | 函数计算 -> 代码部署 |
| `layer.zip` | ~3.2MB | **依赖库** (ali-oss SDK) | 函数计算 -> 层管理 |
| `upload.html` | ~28KB | **前端页面** (已修复 XSS) | 阿里云 OSS Bucket (`ifcr`) -> `t/upload.html` |

---

## 🛠️ 部署指南

### 第一步：配置依赖层 (Layer)
*只需操作一次，依赖库通常不需要频繁更新。*

1. 登录 [阿里云函数计算控制台](https://fcnext.console.aliyun.com/)。
2. 点击左侧 **层管理** -> **创建层**。
3. 上传 `layer.zip`。
4. **名称建议**：`oss-upload-dependencies`。
5. **运行时**：选择 **Node.js 18**。

### 第二步：创建/配置函数
1. 创建函数（或使用现有函数），运行时选择 **Node.js 18**。
2. **绑定层**：在函数配置中，添加刚才创建的层。
3. **上传代码**：上传 `code_minimal.zip`。
4. **配置环境变量**（必须）：

| 变量名 (Key) | 变量值 (Value) | 说明 |
| :--- | :--- | :--- |
| `OSS_ACCESS_KEY_ID` | `LTAI...` | 阿里云 AK |
| `OSS_ACCESS_KEY_SECRET` | `<your-accesskey-secret>` | 阿里云 SK |
| `AUTH_USER` | `admin` | 登录用户名 |
| `AUTH_PASS` | `你的密码` | 登录密码 |
| `JWT_SECRET` | `你的随机字符串` | Token 签名密钥 |
| `OSS_BUCKET` | `ifcr` | **必填**：目标 Bucket 名称 |
| `OSS_REGION` | `oss-cn-hangzhou` | **必填**：Bucket 所在区域 |
| `OSS_DOMAIN` | `https://i.example.com` | (可选) 图片自定义域名 (默认 https://i.example.com) |

5. **部署并启动**：确保监听端口为 `9000`。

### 第三步：部署前端
1. 将 `upload.html` 上传至阿里云 OSS Bucket (`ifcr`)。
2. 路径保持为：`t/upload.html`。
3. **注意**：前端代码中硬编码了函数计算 URL，若更换后端地址，需修改 `upload.html` 中的 `_FC_PARTS` 数组。

---


## 🛡️ 安全特性

1.  **JWT 鉴权**：所有上传操作必须携带有效 Token。
2.  **CORS 白名单**：严格限制跨域来源 (`Access-Control-Allow-Origin`)，禁止通配符 `*`。
3.  **防盗链 & 伪造防护**：校验 Origin/Referer，防止恶意浏览器端调用。
4.  **MIME 强校验**：仅允许 `image/*` 类型，防止上传恶意脚本 (.php/.exe)。
5.  **文件大小限制**：默认限制 20MB，防止流量滥用。
6.  **防爆破机制**：登录失败 5 次锁定 IP 15 分钟。
7.  **密钥隔离**：所有凭证通过环境变量注入，代码零敏感信息。
## 🔄 更新维护

### 更新代码逻辑
1. 修改 `index_minimal.js`。
2. 打包为 `code_minimal.zip`（**注意**：不要包含 `node_modules`）。
3. 在控制台重新上传代码包。

### 更新前端界面
1. 修改 `upload.html`。
2. 重新上传至 OSS 的 `t/upload.html` 路径。
3. 上传时建议设置 `Cache-Control: no-cache` 以防缓存。

### 更新依赖库 (Layer)
1. 重新运行 `npm install ali-oss`。
2. 将 `node_modules` 重新打包为符合规范的目录结构 (`nodejs/node_modules/...`)。
3. 生成新的 `layer.zip` 并创建新版本的层。
