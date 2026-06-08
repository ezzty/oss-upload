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
    SECURITY: {
        TOKEN_EXPIRY_MS: 24 * 60 * 60 * 1000,
        MAX_FILE_SIZE: 20 * 1024 * 1024,
        MAX_LOGIN_BODY_SIZE: 4 * 1024,
        MAX_LOGIN_ATTEMPTS: 5,
        LOCK_DURATION_MS: 15 * 60 * 1000,
        CLEANUP_INTERVAL_MS: 60 * 60 * 1000
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

// 🛡 魔数检测
const detectFileType = (buf) => {
    const len = buf.length;
    if (len >= 3 && buf[0]===0xFF && buf[1]===0xD8 && buf[2]===0xFF) return 'image/jpeg';
    if (len >= 8 && buf[0]===0x89 && buf[1]===0x50 && buf[2]===0x4E && buf[3]===0x47 &&
        buf[4]===0x0D && buf[5]===0x0A && buf[6]===0x1A && buf[7]===0x0A) return 'image/png';
    if (len >= 6 && buf[0]===0x47 && buf[1]===0x49 && buf[2]===0x46 && buf[3]===0x38 &&
        (buf[4]===0x39 || buf[4]===0x37) && buf[5]===0x61) return 'image/gif';
    if (len >= 12 && buf[0]===0x52 && buf[1]===0x49 && buf[2]===0x46 && buf[3]===0x46 &&
        buf[8]===0x57 && buf[9]===0x45 && buf[10]===0x42 && buf[11]===0x50) return 'image/webp';
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
        const record = loginAttempts[ip];
        const lastAccess = record.lastAccess || 0;
        if (now - lastAccess > CONFIG.SECURITY.CLEANUP_INTERVAL_MS) {
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
    if (!loginAttempts[ip]) loginAttempts[ip] = { count: 1, lockUntil: 0, lastAccess: now };
    else { if (now < loginAttempts[ip].lockUntil) return; loginAttempts[ip].count += 1; loginAttempts[ip].lastAccess = now; }
    if (loginAttempts[ip].count >= CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
        loginAttempts[ip].lockUntil = now + CONFIG.SECURITY.LOCK_DURATION_MS;
        loginAttempts[ip].lastAccess = now;
        console.warn(`🔒 IP ${ip} locked.`);
    }
};

// 🛡 Origin 校验 — 优先使用环境变量，向后兼容硬编码 example.com
const ALLOWED_HOSTS = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : ['example.com'];

const isValidOrigin = (origin) => {
    if (!origin) return true;
    try {
        const url = new URL(origin);
        const h = url.hostname;
        return ALLOWED_HOSTS.some(domain => h === domain || h.endsWith('.' + domain));
    } catch (e) { return false; }
};

// ================= FC 入口 =================
exports.handler = async function (event, context) {
    // 解析 event
    let parsedEvent;
    if (typeof event === 'object' && !Buffer.isBuffer(event)) {
        parsedEvent = event;
    } else {
        try { parsedEvent = JSON.parse(event.toString()); } catch(e) { parsedEvent = {}; }
    }

    const path = parsedEvent.rawPath || parsedEvent.path || parsedEvent.pathName || '/';
    const headers = parsedEvent.headers || {};

    // 规范化 headers 为小写
    const hdrs = {};
    for (const k in headers) hdrs[k.toLowerCase()] = headers[k];

    // 推断 method — FC 3.0 HTTP 触发器把 method 放在 requestContext.http.method
    const rc = parsedEvent.requestContext || {};
    const method = (rc.http && rc.http.method) || hdrs['x-http-method-override'] || parsedEvent.httpMethod || 'GET';

    // 处理 body
    let bodyBuf = parsedEvent.body || '';
    if (parsedEvent.isBase64Encoded) {
        try { bodyBuf = Buffer.from(bodyBuf, 'base64'); } catch(e) {}
    } else {
        bodyBuf = Buffer.from(String(bodyBuf));
    }

    // 🛡 兜底：大文件边界保护（防止伪造 Content-Length 绕过）
    const maxUploadSize = CONFIG.SECURITY.MAX_FILE_SIZE;
    if (bodyBuf.length > maxUploadSize) {
        return { statusCode: 413, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'File too large' }), isBase64Encoded: false };
    }

    // CORS: 如果 FC 控制台已开启"允许跨域"，代码不重复设置
    // 如果 FC 未开启 CORS，取消下面注释启用代码级 CORS
    /*
    const origin = hdrs['origin'] || '';
    if (!isValidOrigin(origin) && origin) {
        return { statusCode: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'Forbidden Origin' }), isBase64Encoded: false };
    }
    const corsHeaders = {
        'access-control-allow-origin': origin || '*',
        'access-control-allow-methods': 'POST, GET, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization',
        'access-control-allow-credentials': 'true'
    };
    */
    const corsHeaders = {};

    if (method === 'OPTIONS') {
        return { statusCode: 204, headers: corsHeaders, body: '', isBase64Encoded: false };
    }

    // 构造 res
    let statusCode = 200;
    let responseHeaders = {};
    let responseBody = '';

    const sendJson = (code, data) => {
        statusCode = code;
        responseHeaders = {
            ...corsHeaders,
            'content-type': 'application/json',
            'x-content-type-options': 'nosniff',
            'strict-transport-security': 'max-age=31536000; includeSubDomains'
        };
        responseBody = JSON.stringify(data);
    };

    // --- /verify ---
    if (path === '/verify') {
        const auth = hdrs['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
        const isValid = checkToken(token);
        sendJson(isValid ? 200 : 401, { success: isValid });
        return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
    }

    // --- /login ---
    if (path === '/login') {
        const ip = hdrs['x-forwarded-for']?.split(',')[0]?.trim() || '127.0.0.1';
        if (isIpLocked(ip)) {
            return { statusCode: 429, headers: { ...corsHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'Too many attempts.' }), isBase64Encoded: false };
        }
        if (bodyBuf.length > CONFIG.SECURITY.MAX_LOGIN_BODY_SIZE) {
            return { statusCode: 413, headers: { ...corsHeaders, 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'Request too large' }), isBase64Encoded: false };
        }
        try {
            const { user, pass } = JSON.parse(bodyBuf.toString());
            if (user === CONFIG.AUTH_USER && pass === CONFIG.AUTH_PASS) {
                recordLoginAttempt(ip, true);
                sendJson(200, { success: true, token: genToken() });
            } else {
                recordLoginAttempt(ip, false);
                sendJson(401, { success: false, message: 'Invalid credentials' });
            }
        } catch(e) {
            sendJson(400, { success: false, message: 'Invalid JSON' });
        }
        return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
    }

    // --- /upload ---
    if (path === '/upload') {
        const auth = hdrs['authorization'];
        const token = auth && auth.startsWith('Bearer ') ? auth.slice(7) : null;
        if (!checkToken(token)) {
            sendJson(401, { success: false, message: 'Unauthorized' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const contentType = (hdrs['content-type'] || '').split(';')[0].trim();
        if (!ALLOWED_MIME_TYPES.has(contentType)) {
            sendJson(400, { success: false, message: 'File type not allowed.' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const cl = parseInt(hdrs['content-length'] || '0', 10);
        if (cl > CONFIG.SECURITY.MAX_FILE_SIZE) {
            sendJson(413, { success: false, message: 'File too large' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const mime = detectFileType(bodyBuf);
        if (!mime) {
            sendJson(400, { success: false, message: 'Invalid file content' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const ext = EXT_MAP[mime] || '.bin';
        const randomName = crypto.randomBytes(3).toString('hex');
        const d = new Date();
        const dateStr = `${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
        const key = `img/m/${dateStr}/${randomName}${ext}`;

        try {
            const stream = new PassThrough();
            stream.end(bodyBuf);
            await ossClient.put(key, stream, {
                headers: { 'Content-Type': mime, 'Cache-Control': 'max-age=2592000' }
            });
            const customUrl = `${CONFIG.CDN_DOMAIN}/${key}`;
            sendJson(200, { success: true, markdown: `![image](${customUrl})`, direct: customUrl });
        } catch (err) {
            console.error('Upload error:', err.stack);
            sendJson(500, { success: false, message: 'Upload failed' });
        }
        return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
    }

    sendJson(404, { success: false, message: 'Not Found' });
    return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
};
