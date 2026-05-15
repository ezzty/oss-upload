const http = require('http');
const OSS = require('ali-oss');
const crypto = require('crypto');
const { PassThrough } = require('stream');

// ================= 配置与环境变量 =================
const requiredEnvVars = [
    'AUTH_PASS', 'OSS_ACCESS_KEY_ID', 'OSS_ACCESS_KEY_SECRET', 
    'JWT_SECRET', 'OSS_BUCKET', 'CDN_DOMAIN', 'AUTH_USER', 'OSS_REGION'
];

for (const key of requiredEnvVars) {
    if (!process.env[key]) {
        console.error(`❌ FATAL: Missing required environment variable: ${key}`);
        process.exit(1);
    }
}

const CONFIG = {
    AUTH_USER: process.env.AUTH_USER,
    AUTH_PASS: process.env.AUTH_PASS,
    JWT_SECRET: process.env.JWT_SECRET,
    OSS: {
        region: process.env.OSS_REGION,
        accessKeyId: process.env.OSS_ACCESS_KEY_ID,
        accessKeySecret: process.env.OSS_ACCESS_KEY_SECRET,
        bucket: process.env.OSS_BUCKET
    },
    CDN_DOMAIN: process.env.CDN_DOMAIN,
    PORT: process.env.PORT || 9000,
    SECURITY: {
        TOKEN_EXPIRY_MS: 24 * 60 * 60 * 1000,
        MAX_FILE_SIZE: 20 * 1024 * 1024,
        MAX_LOGIN_BODY_SIZE: 4 * 1024, // 4KB
        MAX_LOGIN_ATTEMPTS: 5,
        LOCK_DURATION_MS: 15 * 60 * 1000,
        CLEANUP_INTERVAL_MS: 60 * 60 * 1000,
        READ_TIMEOUT_MS: 10000
    }
};

// 🌐 CDN 域名标准化
function normalizeCdnDomain(domain) {
    if (!domain.startsWith('http://') && !domain.startsWith('https://')) {
        throw new Error(`CDN_DOMAIN must include protocol. Got: ${domain}`);
    }
    return domain.replace(/\/$/, '');
}

try {
    CONFIG.CDN_DOMAIN = normalizeCdnDomain(CONFIG.CDN_DOMAIN);
} catch (e) {
    console.error(`❌ FATAL: ${e.message}`);
    process.exit(1);
}

// 🛡 文件类型白名单
const ALLOWED_MIME_TYPES = new Set([
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp'
]);

const EXT_MAP = {
    'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
    'image/webp': '.webp', 'image/bmp': '.bmp'
};

// 🛡 核心安全：内置魔数检测 (强化版)
const detectFileType = (buf) => {
    const len = buf.length;
    // JPEG: FF D8 FF
    if (len >= 3 && buf[0]===0xFF && buf[1]===0xD8 && buf[2]===0xFF) return 'image/jpeg';
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (len >= 8 && buf[0]===0x89 && buf[1]===0x50 && buf[2]===0x4E && buf[3]===0x47 &&
        buf[4]===0x0D && buf[5]===0x0A && buf[6]===0x1A && buf[7]===0x0A) return 'image/png';
    // GIF: 47 49 46 38 (39|37) 61
    if (len >= 6 && buf[0]===0x47 && buf[1]===0x49 && buf[2]===0x46 && buf[3]===0x38 &&
        (buf[4]===0x39 || buf[4]===0x37) && buf[5]===0x61) return 'image/gif';
    // WEBP: 52 49 46 46 ... 57 45 42 50
    if (len >= 12 && buf[0]===0x52 && buf[1]===0x49 && buf[2]===0x46 && buf[3]===0x46 && 
        buf[8]===0x57 && buf[9]===0x45 && buf[10]===0x42 && buf[11]===0x50) return 'image/webp';
    // BMP: 42 4D + 非零文件大小 (字节 2-5)
    if (len >= 6 && buf[0]===0x42 && buf[1]===0x4D && (buf[2]|buf[3]|buf[4]|buf[5]) !== 0) return 'image/bmp';
    return null;
};

// ================= 初始化 OSS =================
const ossClient = new OSS({
    region: CONFIG.OSS.region,
    accessKeyId: CONFIG.OSS.accessKeyId,
    accessKeySecret: CONFIG.OSS.accessKeySecret,
    bucket: CONFIG.OSS.bucket
});

// ================= 工具函数 =================
const loginAttempts = {};

setInterval(() => {
    const now = Date.now();
    let cleaned = 0;
    for (const ip in loginAttempts) {
        if (loginAttempts[ip].lockUntil > 0 && now > loginAttempts[ip].lockUntil) {
            delete loginAttempts[ip];
            cleaned++;
        }
    }
    if (cleaned > 0) console.log(`🧹 Cleaned ${cleaned} expired login attempts.`);
}, CONFIG.SECURITY.CLEANUP_INTERVAL_MS);

const genToken = () => {
    const exp = Date.now() + CONFIG.SECURITY.TOKEN_EXPIRY_MS;
    const jti = crypto.randomBytes(8).toString('hex'); 
    const payload = `${CONFIG.AUTH_USER}.${exp}.${jti}`;
    const signature = crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(payload).digest('hex');
    return `${payload}.${signature}`;
};

const checkToken = (t) => {
    if (!t || typeof t !== 'string') return false;
    try {
        const parts = t.split('.');
        if (parts.length !== 4) return false;
        const [u, e, jti, signature] = parts; 
        const payloadToVerify = `${u}.${e}.${jti}`;
        const expectedSig = crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(payloadToVerify).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(expectedSig), Buffer.from(signature))) return false;
        const expiry = parseInt(e, 10);
        if (isNaN(expiry) || Date.now() > expiry) return false;
        if (u !== CONFIG.AUTH_USER) return false;
        return true;
    } catch (err) { return false; }
};

const isIpLocked = (ip) => {
    const record = loginAttempts[ip];
    if (!record) return false;
    if (record.lockUntil === 0) return false;
    if (Date.now() > record.lockUntil) { delete loginAttempts[ip]; return false; }
    return true;
};

const recordLoginAttempt = (ip, success) => {
    if (success) { delete loginAttempts[ip]; return; }
    const now = Date.now();
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 1, lockUntil: 0 };
    else { if (now < loginAttempts[ip].lockUntil) return; loginAttempts[ip].count += 1; }
    if (loginAttempts[ip].count >= CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
        loginAttempts[ip].lockUntil = now + CONFIG.SECURITY.LOCK_DURATION_MS;
        console.warn(`🔒 IP ${ip} locked.`);
    }
};

const isValidOrigin = (origin) => {
    if (!origin) return true;
    if (origin.startsWith('http://localhost:') || origin === 'http://localhost' ||
        origin.startsWith('http://127.0.0.1:') || origin === 'http://127.0.0.1') return true;
    try {
        const url = new URL(origin);
        const h = url.hostname;
        return h === 'example.com' || h.endsWith('.example.com');
    } catch (e) { return false; }
};

const sendJson = (res, statusCode, data) => {
    if (res.headersSent) return;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
};

// 辅助函数：等待可读事件
const waitForReadable = (req, timeoutMs) => {
    return new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => cleanup(new Error('Read timeout')), timeoutMs);
        const cleanup = (err) => {
            clearTimeout(timeoutId);
            req.removeListener('readable', onReadable);
            req.removeListener('end', onEnd);
            req.removeListener('error', onError);
            if (err) reject(err); else resolve();
        };
        const onReadable = () => cleanup(null);
        const onEnd = () => cleanup(null);
        const onError = (err) => cleanup(err);

        req.on('readable', onReadable);
        req.on('end', onEnd);
        req.on('error', onError);
        if (req.readable) cleanup(null);
    });
};

// ================= HTTP 服务 =================
http.createServer((req, res) => {
    const origin = req.headers['origin'] || '';
    
    if (isValidOrigin(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    } else if (origin) {
        console.warn(`🚫 Blocked origin: ${origin}`);
        sendJson(res, 403, { success: false, message: 'Forbidden Origin' });
        return;
    }

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    const url = new URL(req.url, `http://${req.headers.host}`);
    const pathname = url.pathname;

    // --- 1. 登录 (修复竞态条件) ---
    if (req.method === 'POST' && pathname === '/login') {
        if (isIpLocked(ip)) { sendJson(res, 429, { success: false, message: 'Too many attempts.' }); return; }
        
        let body = [];
        let receivedSize = 0;
        let sizeExceeded = false;

        req.on('data', chunk => {
            receivedSize += chunk.length;
            if (receivedSize > CONFIG.SECURITY.MAX_LOGIN_BODY_SIZE) {
                sizeExceeded = true;
                req.destroy();
                return;
            }
            body.push(chunk);
        });
        req.on('end', () => {
            if (sizeExceeded) {
                sendJson(res, 413, { success: false, message: 'Request body too large' });
                return;
            }
            try {
                const { user, pass } = JSON.parse(Buffer.concat(body));
                if (user === CONFIG.AUTH_USER && pass === CONFIG.AUTH_PASS) {
                    recordLoginAttempt(ip, true);
                    sendJson(res, 200, { success: true, token: genToken() });
                } else { recordLoginAttempt(ip, false); sendJson(res, 401, { success: false, message: 'Invalid credentials' }); }
            } catch (e) { sendJson(res, 400, { success: false, message: 'Invalid JSON' }); }
        });
        req.on('error', () => {
            if (!res.headersSent) {
                sendJson(res, sizeExceeded ? 413 : 500, { success: false, message: sizeExceeded ? 'Request body too large' : 'Request error' });
            }
        });
        return;
    }

    // --- 2. 验证 ---
    if (req.method === 'GET' && pathname === '/verify') {
        const auth = req.headers['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
        const isValid = checkToken(token);
        sendJson(res, isValid ? 200 : 401, { success: isValid });
        return;
    }

    // --- 3. 上传 (高性能流式版 - 修复超时/泄漏) ---
    if (req.method === 'POST' && pathname === '/upload') {
        const auth = req.headers['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;

        if (!checkToken(token)) { sendJson(res, 401, { success: false, message: 'Unauthorized' }); return; }

        const contentType = req.headers['content-type']?.split(';')[0].trim() || '';
        if (!ALLOWED_MIME_TYPES.has(contentType)) { sendJson(res, 400, { success: false, message: 'File type not allowed.' }); return; }

        const contentLength = parseInt(req.headers['content-length'], 10);
        if (contentLength && contentLength > CONFIG.SECURITY.MAX_FILE_SIZE) {
            sendJson(res, 413, { success: false, message: 'File too large' }); return;
        }

        req.pause(); 
        const timeoutHandle = setTimeout(() => req.destroy(new Error('Read timeout')), CONFIG.SECURITY.READ_TIMEOUT_MS);
        let uploadStream = null;

        (async () => {
            try {
                let buffer = null;
                let mime = null;

                let chunk = req.read();
                if (!chunk && !req.readableEnded) await waitForReadable(req, CONFIG.SECURITY.READ_TIMEOUT_MS);
                chunk = req.read();

                if (chunk) {
                    if (chunk.length >= 12) {
                        mime = detectFileType(chunk.subarray(0, 12));
                        buffer = chunk;
                    } else {
                        buffer = chunk;
                        while (buffer.length < 12 && !req.readableEnded) {
                            let nextChunk = req.read();
                            if (!nextChunk) await waitForReadable(req, CONFIG.SECURITY.READ_TIMEOUT_MS);
                            nextChunk = req.read();
                            if (!nextChunk) break;
                            buffer = Buffer.concat([buffer, nextChunk]);
                        }
                        if (buffer.length >= 12) mime = detectFileType(buffer.subarray(0, 12));
                    }
                }

                // 🚀 核心修复 1：检测通过后立即停止超时，防止大文件上传被误杀
                clearTimeout(timeoutHandle);

                if (!mime) { req.destroy(); sendJson(res, 400, { success: false, message: 'Invalid file content' }); return; }

                uploadStream = new PassThrough();
                uploadStream.on('error', (err) => console.error('Upload stream error:', err));
                
                uploadStream.write(buffer);
                if (!req.readableEnded) {
                    req.pipe(uploadStream);
                    req.on('error', (err) => { console.error('Request stream error:', err); uploadStream.destroy(); });
                } else {
                    uploadStream.end();
                }

                const randomName = crypto.randomBytes(3).toString('hex');
                const d = new Date();
                const dateStr = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
                const ext = EXT_MAP[mime] || '.bin';
                const key = `img/m/${dateStr}/${randomName}${ext}`;
                
                await ossClient.put(key, uploadStream, {
                    headers: { 'Content-Type': mime, 'Cache-Control': 'max-age=2592000' }
                });
                
                const customUrl = `${CONFIG.CDN_DOMAIN}/${key}`;
                sendJson(res, 200, { success: true, markdown: `![image](${customUrl})`, direct: customUrl });
                
            } catch (err) {
                // 🚀 核心修复 2：确保流被清理，防止资源泄漏
                if (uploadStream) uploadStream.destroy();
                console.error('Upload error:', err.message);
                if (!res.headersSent) {
                    const status = err.message.includes('timeout') ? 408 : 500;
                    sendJson(res, status, { success: false, message: 'Upload failed' });
                }
            }
        })();

        return;
    }

    sendJson(res, 404, { success: false, message: 'Not Found' });

}).listen(CONFIG.PORT, () => {
    console.log(`🚀 Server running on port ${CONFIG.PORT}`);
    console.log(`📦 OSS Bucket: ${CONFIG.OSS.bucket}`);
    console.log(`🌐 CDN Domain: ${CONFIG.CDN_DOMAIN}`);
});
