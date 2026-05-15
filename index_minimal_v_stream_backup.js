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
        MAX_LOGIN_ATTEMPTS: 5,
        LOCK_DURATION_MS: 15 * 60 * 1000,
        CLEANUP_INTERVAL_MS: 60 * 60 * 1000,
        READ_TIMEOUT_MS: 10000 // 头部读取超时 10 秒
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

// 扩展名映射
const EXT_MAP = {
    'image/jpeg': '.jpg', 'image/png': '.png', 'image/gif': '.gif',
    'image/webp': '.webp', 'image/bmp': '.bmp'
};

// 🛡 核心安全：内置魔数检测 (前 12 字节)
// 优化：直接按位比较，减少函数调用开销
const detectFileType = (buf) => {
    // buf 长度保证 >= 12
    if (buf[0]===0xFF && buf[1]===0xD8 && buf[2]===0xFF) return 'image/jpeg';
    if (buf[0]===0x89 && buf[1]===0x50 && buf[2]===0x4E && buf[3]===0x47) return 'image/png';
    if (buf[0]===0x47 && buf[1]===0x49 && buf[2]===0x46) return 'image/gif';
    if (buf[0]===0x42 && buf[1]===0x4D) return 'image/bmp';
    if (buf[0]===0x52 && buf[1]===0x49 && buf[2]===0x46 && buf[3]===0x46 && 
        buf[8]===0x57 && buf[9]===0x45 && buf[10]===0x42 && buf[11]===0x50) return 'image/webp';
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

    // --- 1. 登录 ---
    if (req.method === 'POST' && pathname === '/login') {
        if (isIpLocked(ip)) { sendJson(res, 429, { success: false, message: 'Too many attempts.' }); return; }
        let body = [];
        req.on('data', chunk => body.push(chunk));
        req.on('end', () => {
            try {
                const { user, pass } = JSON.parse(Buffer.concat(body));
                if (user === CONFIG.AUTH_USER && pass === CONFIG.AUTH_PASS) {
                    recordLoginAttempt(ip, true);
                    sendJson(res, 200, { success: true, token: genToken() });
                } else { recordLoginAttempt(ip, false); sendJson(res, 401, { success: false, message: 'Invalid credentials' }); }
            } catch (e) { sendJson(res, 400, { success: false, message: 'Invalid JSON' }); }
        });
        return;
    }

    // --- 2. 验证 ---
    if (req.method === 'GET' && pathname === '/verify') {
        const auth = req.headers['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
        sendJson(res, checkToken(token) ? 200 : 401, { success: !!checkToken(token) });
        return;
    }

    // --- 3. 上传 (高性能流式版) ---
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

        // 🚀 高性能流式核心逻辑
        req.pause(); // 暂停数据流，准备手动控制
        
        // 设置超时，防止慢速攻击
        const timeoutHandle = setTimeout(() => req.destroy(new Error('Read timeout')), CONFIG.SECURITY.READ_TIMEOUT_MS);

        (async () => {
            try {
                let buffer = null;
                let mime = null;

                // 1. 尝试读取第一个 chunk
                let chunk = req.read();
                
                // 如果缓冲区空，等待 readable 事件
                if (!chunk) {
                    await new Promise((resolve, reject) => {
                        const onReadable = () => {
                            cleanup();
                            resolve();
                        };
                        const onEnd = () => { cleanup(); resolve(); }; // 流可能直接结束
                        const onError = reject;
                        const cleanup = () => {
                            req.removeListener('readable', onReadable);
                            req.removeListener('end', onEnd);
                            req.removeListener('error', onError);
                        };
                        req.on('readable', onReadable);
                        req.on('end', onEnd);
                        req.on('error', onError);
                    });
                    chunk = req.read();
                }

                if (chunk) {
                    // 性能优化：如果 chunk 足够大，直接 subarray 检测，零拷贝
                    if (chunk.length >= 12) {
                        mime = detectFileType(chunk.subarray(0, 12));
                        buffer = chunk; // 保存引用
                    } else {
                        buffer = chunk;
                        // 如果不够，继续读
                        while (buffer.length < 12) {
                            const nextChunk = req.read();
                            if (!nextChunk) {
                                // 再次等待
                                await new Promise((resolve, reject) => {
                                    const onReadable = () => { cleanup(); resolve(); };
                                    const onEnd = () => { cleanup(); resolve(); };
                                    const onError = reject;
                                    const cleanup = () => {
                                        req.removeListener('readable', onReadable);
                                        req.removeListener('end', onEnd);
                                        req.removeListener('error', onError);
                                    };
                                    req.on('readable', onReadable);
                                    req.on('end', onEnd);
                                    req.on('error', onError);
                                });
                                const c = req.read();
                                if (!c) break; // 流结束
                                
                                // 拼接
                                buffer = Buffer.concat([buffer, c]);
                            } else {
                                buffer = Buffer.concat([buffer, nextChunk]);
                            }
                        }
                        if (buffer.length >= 12) {
                            mime = detectFileType(buffer.subarray(0, 12));
                        }
                    }
                }

                clearTimeout(timeoutHandle);

                // 2. 校验结果
                if (!mime || buffer.length < 12) {
                    req.destroy();
                    sendJson(res, 400, { success: false, message: 'Invalid file content' });
                    return;
                }

                // 3. 构建上传流并 Pipe
                const uploadStream = new PassThrough();
                
                // 将已读取的数据推入流
                uploadStream.write(buffer);

                // 如果请求还没结束，接管剩余流
                if (!req.readableEnded) {
                    req.pipe(uploadStream);
                } else {
                    uploadStream.end();
                }

                // 4. 执行上传
                const randomName = crypto.randomBytes(3).toString('hex');
                const d = new Date();
                const dateStr = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
                const ext = EXT_MAP[mime] || '.bin';
                const key = `img/m/${dateStr}/${randomName}${ext}`;
                
                await ossClient.put(key, uploadStream, {
                    headers: {
                        'Content-Type': mime,
                        'Cache-Control': 'max-age=2592000'
                    }
                });
                
                const customUrl = `${CONFIG.CDN_DOMAIN}/${key}`;
                sendJson(res, 200, { success: true, markdown: `![image](${customUrl})`, direct: customUrl });
                
            } catch (err) {
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
