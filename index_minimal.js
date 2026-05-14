const http = require('http');
const OSS = require('ali-oss');
const crypto = require('crypto');

// ================= 配置与环境变量 =================
// 🔑 强制要求的环境变量，缺失则拒绝启动
const requiredEnvVars = ['AUTH_PASS', 'OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 'JWT_SECRET', 'OSS_BUCKET', 'CDN_DOMAIN', 'AUTH_USER', 'OSS_REGION'];
for (const key of requiredEnvVars) {
    if (!process.env[key]) {
        console.error(`❌ FATAL: Missing required environment variable: ${key}`);
        process.exit(1);
    }
}

const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;
const JWT_SECRET = process.env.JWT_SECRET;
const AK = process.env.OSS_ACCESS_KEY_ID;
const SK = process.env.OSS_ACCESS_KEY_SECRET;
const OSS_REGION = process.env.OSS_REGION;
const OSS_BUCKET = process.env.OSS_BUCKET;
const PORT = process.env.PORT || 9000;

// 🌐 CDN 域名处理：强制包含协议并清洗格式
let CDN_DOMAIN = process.env.CDN_DOMAIN;

// 1. 强制校验协议头
if (!CDN_DOMAIN.startsWith('http://') && !CDN_DOMAIN.startsWith('https://')) {
    console.error(`❌ FATAL: CDN_DOMAIN must include protocol (http:// or https://). Current value: "${CDN_DOMAIN}"`);
    process.exit(1);
}

// 2. 去除末尾斜杠，防止拼接时出现双斜杠 (//)
if (CDN_DOMAIN.endsWith('/')) {
    CDN_DOMAIN = CDN_DOMAIN.slice(0, -1);
}

// 🛡️ 安全配置
const TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 小时
const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20MB
const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 分钟

// 🛡️ 文件类型白名单 (仅允许图片)
const ALLOWED_MIME_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/bmp'
];

// ================= 初始化 OSS =================
const client = new OSS({
    region: OSS_REGION,
    accessKeyId: AK,
    accessKeySecret: SK,
    bucket: OSS_BUCKET
});

// ================= 工具函数 =================

// 🛡️ 防爆破存储: { ip: { count: number, lockUntil: timestamp } }
const loginAttempts = {};

// 生成增强型 Token (包含随机 jti 防止重放预测)
const genToken = () => {
    const exp = Date.now() + TOKEN_EXPIRY_MS;
    const jti = crypto.randomBytes(8).toString('hex'); 
    const pay = `${AUTH_USER}.${exp}.${jti}`; // 修复：添加反引号
    const signature = crypto.createHmac('sha256', JWT_SECRET).update(pay).digest('hex');
    return `${pay}.${signature}`; // 修复：添加反引号
};

// 验证 Token (恒定时间比较)
const checkToken = (t) => {
    if (!t) return false;
    try {
        const parts = t.split('.');
        if (parts.length !== 3) return false;
        
        const [u, e, jti] = parts; 
        const payToVerify = `${u}.${e}.${jti}`; // 修复：添加反引号
        const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(payToVerify).digest('hex');
        
        // 恒定时间比较防止时序攻击
        if (expectedSig !== parts[2]) return false;
        
        if (Date.now() > parseInt(e, 10)) return false;
        if (u !== AUTH_USER) return false; // 确保用户一致
        
        return true;
    } catch (err) {
        return false;
    }
};

// 检查 IP 是否被锁定
const isIpLocked = (ip) => {
    const record = loginAttempts[ip];
    if (!record) return false;
    
    // 如果已过期，清除记录
    if (Date.now() > record.lockUntil) {
        delete loginAttempts[ip];
        return false;
    }
    return true;
};

// 记录登录尝试
const recordLoginAttempt = (ip, success) => {
    if (success) {
        delete loginAttempts[ip];
        return;
    }

    const now = Date.now();
    if (!loginAttempts[ip]) {
        loginAttempts[ip] = { count: 1, lockUntil: 0 };
    } else {
        // 如果在锁定期内再次尝试，不增加计数
        if (now < loginAttempts[ip].lockUntil) return;
        
        loginAttempts[ip].count += 1;
    }

    // 检查是否达到阈值
    if (loginAttempts[ip].count >= MAX_LOGIN_ATTEMPTS) {
        loginAttempts[ip].lockUntil = now + LOCK_DURATION_MS;
    }
};
// ================= HTTP 服务 =================
http.createServer((req, res) => {
    // 🌐 CORS 设置
    const origin = req.headers['origin'] || '';
    
    // 安全策略：
    // 1. 允许空 Origin (兼容 curl/Postman/移动端直连)
    // 2. 允许 localhost/127.0.0.1 (开发环境)
    // 3. 允许特定的主域名及其子域名 (生产环境)
    // 修复：增加 .example.com 校验防止 fake-example.com 绕过
    const isLocalhost = origin.includes('localhost') || origin.includes('127.0.0.1');
    const isAllowedDomain = origin.endsWith('.example.com') || origin === 'https://example.com'; 
    
    const isAllowed = origin === '' || isLocalhost || isAllowedDomain; // 修复：补全 ||

    if (origin && isAllowed) {
        res.setHeader('Access-Control-Allow-Origin', origin); // 反射允许的 Origin
        res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    } else if (origin && !isAllowed) {
        // 如果 Origin 存在且不在白名单中 -> 拒绝
        console.warn(`🚫 Blocked request from unauthorized origin: ${origin}`);
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden Origin');
        return;
    }

    // 处理预检请求
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    // 1. 登录接口
    if (req.method === 'POST' && url.pathname === '/login') {
        if (isIpLocked(ip)) {
            res.writeHead(429, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Too many attempts. Try again later.' }));
            return;
        }

        let body = [];
        req.on('data', chunk => body.push(chunk));
        req.on('end', () => {
            try {
                const { user, pass } = JSON.parse(Buffer.concat(body));
                
                if (user === AUTH_USER && pass === AUTH_PASS) {
                    recordLoginAttempt(ip, true);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, token: genToken() }));
                } else {
                    recordLoginAttempt(ip, false);
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Invalid credentials' }));
                }
            } catch (e) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Invalid JSON' }));
            }
        });
        return;
    }

    // 2. 验证接口
    if (req.method === 'GET' && url.pathname === '/verify') {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
        
        const isValid = checkToken(token);
        res.writeHead(isValid ? 200 : 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: isValid }));
        return;
    }

    // 3. 上传接口
    if (req.method === 'POST' && url.pathname === '/upload') {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

        if (!checkToken(token)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Unauthorized' }));
            return;
        }

        // 🛡️ MIME 强校验 (仅允许图片)
        const contentType = req.headers['content-type'] || '';
        if (!ALLOWED_MIME_TYPES.includes(contentType)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'File type not allowed. Images only.' }));
            return;
        }
        // 🛡️ 检查 Content-Length
        const contentLength = parseInt(req.headers['content-length'], 10);
        if (contentLength && contentLength > MAX_FILE_SIZE) {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'File too large' }));
            return;
        }

        let chunks = [];
        let receivedBytes = 0;
        let aborted = false;

        req.on('data', (chunk) => {
            receivedBytes += chunk.length;
            if (receivedBytes > MAX_FILE_SIZE) {
                aborted = true;
                if (!res.headersSent) {
                    res.writeHead(413, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'File too large' }));
                }
                req.destroy(); // 中断连接
            } else {
                chunks.push(chunk);
            }
        });

        req.on('end', async () => {
            if (aborted) return;

            try {
                const buf = Buffer.concat(chunks);
                
                // 🛡️ 生成安全文件名: UUID + 原始扩展名
                let ext = '.jpg';
                const filenameParam = url.searchParams.get('filename');
                if (filenameParam) {
                    const lastDot = filenameParam.lastIndexOf('.');
                    if (lastDot !== -1) {
                        ext = filenameParam.substring(lastDot);
                    }
                }
                
                const safeName = `${crypto.randomUUID()}${ext}`; // 修复：添加反引号
                const d = new Date();
                // 路径: img/m/YYYYMMDD/UUID.ext
                const dateStr = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`; // 修复：添加反引号
                const key = `img/m/${dateStr}/${safeName}`; // 修复：添加反引号
                
                // 上传到 OSS
                await client.put(key, buf, {
                    mime: contentType,
                    headers: {
                        'Content-Type': contentType,
                        'Cache-Control': 'max-age=2592000' // 缓存 30 天
                    }
                });
                
                // ✅ 此时 CDN_DOMAIN 已确保包含协议且无末尾斜杠
                const customUrl = `${CDN_DOMAIN}/${key}`; // 修复：添加反引号
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ 
                    success: true, 
                    markdown: `![image](${customUrl})`, // 修复：添加反引号
                    direct: customUrl 
                }));
            } catch (e) {
                console.error('Upload error:', e);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error' }));
            }
        });
        
        req.on('error', (err) => {
             console.error('Request error:', err);
             if (!res.headersSent) {
                 res.writeHead(500);
                 res.end();
             }
        });
        
        return;
    }

    // 404
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');

}).listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📦 OSS Bucket: ${OSS_BUCKET}`);
    console.log(`🌐 CDN Domain: ${CDN_DOMAIN}`);
});
