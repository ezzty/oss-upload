const http = require('http');
const OSS = require('ali-oss');
const crypto = require('crypto');

// 🔑 1. 环境变量 (严格模式 - 必须配置在 FC 控制台)
const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;
const JWT_SECRET = process.env.JWT_SECRET;
const AK = process.env.OSS_ACCESS_KEY_ID;
const SK = process.env.OSS_ACCESS_KEY_SECRET;
const OSS_REGION = process.env.OSS_REGION;

// 🌐 2. 图片返回域名 (支持 env 覆盖)
const OSS_DOMAIN = process.env.OSS_DOMAIN || 'https://i.example.com';

// 启动时检查核心变量，防止配置错误导致运行异常
if (!AUTH_USER || !AUTH_PASS || !JWT_SECRET || !AK || !SK || !OSS_REGION) {
    console.error("❌ Error: Missing required Environment Variables.");
    console.error("Please configure AUTH_USER, AUTH_PASS, JWT_SECRET, AK, SK, OSS_REGION in FC Console.");
}

// 📦 3. OSS SDK 初始化
const client = new OSS({
    region: OSS_REGION,
    accessKeyId: AK,
    accessKeySecret: SK,
    bucket: process.env.OSS_BUCKET // Bucket 名也来自环境变量
});

// 🛡️ 4. 安全策略配置
// CORS 白名单：仅允许这些域名跨域访问 (防止恶意网站盗用 Token)
const ALLOWED_ORIGINS = [
    'https://i.example.com',
    'http://localhost',
    'http://127.0.0.1'
];
// 允许的文件类型：仅图片 (防止上传恶意脚本)
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'];
// 最大文件大小：20MB (防止恶意刷流量)
const MAX_FILE_SIZE = 20 * 1024 * 1024;

// 🛡️ 防爆破计数器 (内存级)
const loginAttempts = {};

// 🔧 5. 辅助函数
const genToken = () => {
    const exp = Date.now() + 604800000; // 7 天过期
    const pay = `${AUTH_USER}.${exp}`;
    return `${pay}.${crypto.createHmac('sha256', JWT_SECRET).update(pay).digest('hex')}`;
};

const checkToken = t => {
    try {
        const [u, e, s] = t.split('.');
        if (Date.now() > +e) return false;
        return s === crypto.createHmac('sha256', JWT_SECRET).update(`${u}.${e}`).digest('hex');
    } catch { return false; }
};

// 🌐 6. Server 逻辑
http.createServer((req, res) => {
    // 获取 Origin
    const origin = req.headers['origin'];

    // CORS 设置：严格白名单匹配 (禁止 *)
    if (origin && ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    } else if (origin) {
        // 如果 Origin 存在但不在白名单中 -> 拒绝
        res.writeHead(403); res.end('Forbidden Origin');
        return;
    }

    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    const url = new URL(req.url, `http://${req.headers.host}`);

    // 🔐 登录
    if (req.method === 'POST' && url.pathname === '/login') {
        let b = []; req.on('data', c => b.push(c));
        req.on('end', () => {
            try {
                const { user, pass } = JSON.parse(Buffer.concat(b));
                const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
                if (user === AUTH_USER && pass === AUTH_PASS) {
                    delete loginAttempts[ip];
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, token: genToken() }));
                } else {
                    loginAttempts[ip] = { count: (loginAttempts[ip]?.count || 0) + 1 };
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false }));
                }
            } catch (e) { res.writeHead(400); res.end(); }
        });
        return;
    }

    // ✅ 验证 Token
    if (req.method === 'GET' && url.pathname === '/verify') {
        const t = req.headers['authorization']?.split(' ')[1];
        res.writeHead(checkToken(t) ? 200 : 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: checkToken(t) }));
        return;
    }

    // ☁️ 上传 (包含严格安全检查)
    if (req.method === 'POST' && url.pathname === '/upload') {
        const t = req.headers['authorization']?.split(' ')[1];
        if (!checkToken(t)) { res.writeHead(401); res.end(); return; }

        // 1. 检查 Content-Type (仅允许图片)
        const contentType = req.headers['content-type'] || '';
        if (!ALLOWED_MIME_TYPES.includes(contentType)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Only image files allowed' }));
            return;
        }

        // 2. 检查文件大小
        const contentLength = parseInt(req.headers['content-length'] || '0');
        if (contentLength > MAX_FILE_SIZE) {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'File too large (Max 20MB)' }));
            return;
        }

        // 3. 接收数据
        let chunks = [];
        let totalSize = 0;

        req.on('data', chunk => {
            totalSize += chunk.length;
            if (totalSize > MAX_FILE_SIZE) {
                req.destroy(); // 切断连接
                res.writeHead(413);
                res.end('File too large');
            }
            chunks.push(chunk);
        });

        req.on('end', async () => {
            try {
                const buf = Buffer.concat(chunks);
                const name = url.searchParams.get('filename') || `${Date.now()}.jpg`;
                const d = new Date();
                const key = `img/m/${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}/${name}`;
                
                // 上传 OSS
                await client.put(key, buf, { mime: contentType });
                
                // 拼接域名
                const customUrl = `${OSS_DOMAIN}/${key}`;
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, markdown: `![ ](${customUrl})`, direct: customUrl }));
            } catch (e) { res.writeHead(500); res.end(e.message); }
        });
        return;
    }

    res.writeHead(404); res.end('Not Found');
}).listen(9000, () => console.log('🚀 Secure Server running on :9000'));
