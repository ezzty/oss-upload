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
// 用 Map 而非普通对象：天然免疫原型污染（X-Forwarded-For 传 __proto__ 不会污染 Object.prototype）
const loginAttempts = new Map();
const MAX_TRACKED_IPS = 1000;

// 只接受形如 IPv4 / IPv6 的值，杜绝 __proto__、constructor 等特殊键
const isValidIp = (ip) =>
    typeof ip === 'string' &&
    (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) || ip.includes(':')) &&
    ip.length <= 45;

// 惰性清理：在每次 /login 时顺带做，不依赖 setInterval
// （FC 实例空闲会被冻结、销毁会丢定时器，全局定时器在 FC 里不可靠）
const cleanupLoginAttempts = (now) => {
    if (loginAttempts.size < MAX_TRACKED_IPS) return;
    for (const [ip, record] of loginAttempts) {
        if (now - (record.lastAccess || 0) > CONFIG.SECURITY.CLEANUP_INTERVAL_MS) {
            loginAttempts.delete(ip);
        }
    }
    // 仍然超限：丢弃最旧的一半，给内存兜底
    if (loginAttempts.size >= MAX_TRACKED_IPS) {
        const entries = [...loginAttempts.entries()].sort((a, b) => a[1].lastAccess - b[1].lastAccess);
        for (let i = 0; i < entries.length / 2; i++) loginAttempts.delete(entries[i][0]);
    }
};

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
        // 必须先校验 64 位 hex，再按 hex 解码；否则 length 不等会抛异常走 catch，掩盖真实原因
        if (!/^[0-9a-f]{64}$/.test(signature)) return false;
        if (!crypto.timingSafeEqual(Buffer.from(expectedSig, 'hex'), Buffer.from(signature, 'hex'))) return false;
        const expiry = parseInt(e, 10);
        if (isNaN(expiry) || Date.now() > expiry) return false;
        if (u !== CONFIG.AUTH_USER) return false;
        return true;
    } catch (err) { return false; }
};

const isIpLocked = (ip) => {
    const record = loginAttempts.get(ip);
    if (!record) return false;
    if (record.lockUntil === 0) return false;
    if (Date.now() > record.lockUntil) { loginAttempts.delete(ip); return false; }
    return true;
};

const recordLoginAttempt = (ip, success) => {
    if (success) { loginAttempts.delete(ip); return; }
    const now = Date.now();
    const record = loginAttempts.get(ip);
    if (!record) {
        loginAttempts.set(ip, { count: 1, lockUntil: 0, lastAccess: now });
    } else {
        if (now < record.lockUntil) return;
        record.count += 1;
        record.lastAccess = now;
    }
    const after = loginAttempts.get(ip);
    if (after.count >= CONFIG.SECURITY.MAX_LOGIN_ATTEMPTS) {
        after.lockUntil = now + CONFIG.SECURITY.LOCK_DURATION_MS;
        after.lastAccess = now;
        console.warn(`🔒 IP ${ip} locked.`);
    }
};

// 🛡 Origin 校验 — 优先使用环境变量；未配置时用占位兜底，部署时务必设 ALLOWED_ORIGINS
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
    const method = (((rc.http && rc.http.method) || parsedEvent.httpMethod || hdrs['x-http-method-override'] || 'GET') + '').toUpperCase();

    // 🛡 CORS：默认由 FC 控制台「允许跨域」处理，此处不重复设置。
    // 若改用代码级 CORS，取消下面注释块即可 —— corsHeaders 已在下方声明，
    // 注释块内只做**赋值**，不会与外层重复声明（重复 const 会 SyntaxError 导致函数起不来）。
    let corsHeaders = {};
    /*
    const origin = String(hdrs['origin'] || '');
    if (origin && !isValidOrigin(origin)) {
        return { statusCode: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'Forbidden Origin' }), isBase64Encoded: false };
    }
    corsHeaders = {
        'access-control-allow-origin': origin || '*',
        'access-control-allow-methods': 'POST, GET, OPTIONS',
        'access-control-allow-headers': 'Content-Type, Authorization',
        'access-control-allow-credentials': 'true'
    };
    */

    if (method === 'OPTIONS') {
        return { statusCode: 204, headers: corsHeaders, body: '', isBase64Encoded: false };
    }

    // 🛡 body 惰性解码：先用未解码长度粗判，鉴权通过后才真正分配 Buffer。
    // 一开始就 Buffer.from 会让未认证的大 body 先吃掉几十 MB（FC 规格仅 128 MB）。
    const rawBody = parsedEvent.body || '';
    const approxBytes = parsedEvent.isBase64Encoded
        ? Math.floor(String(rawBody).length * 3 / 4)
        : Buffer.byteLength(String(rawBody));

    let _bodyBuf = null;
    const decodeBody = () => {
        if (_bodyBuf === null) {
            _bodyBuf = parsedEvent.isBase64Encoded
                ? Buffer.from(String(rawBody), 'base64')
                : Buffer.from(String(rawBody));
        }
        return _bodyBuf;
    };

    // 🛡 全局兜底：未解码长度已超上限直接拒（防伪造 Content-Length 绕过，且不分配 Buffer）
    if (approxBytes > CONFIG.SECURITY.MAX_FILE_SIZE) {
        return { statusCode: 413, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ success: false, message: 'File too large' }), isBase64Encoded: false };
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
            'cache-control': 'no-store',
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
        if (method !== 'POST') {
            sendJson(405, { success: false, message: 'Method Not Allowed' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }
        // IP 优先取 FC 平台注入的 sourceIp；XFF 最左值可能被客户端伪造，不可直接信任
        const xff = String(hdrs['x-forwarded-for'] || '').split(',')[0].trim();
        const rawIp = (rc.http && rc.http.sourceIp) || hdrs['x-real-ip'] || xff || '127.0.0.1';
        const ip = isValidIp(rawIp) ? rawIp : 'untrusted';
        cleanupLoginAttempts(Date.now());
        if (isIpLocked(ip)) {
            return { statusCode: 429, headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ success: false, message: 'Too many attempts.' }), isBase64Encoded: false };
        }
        // 4KB 限制必须在 JSON.parse 之前，且用未解码长度先判（不为超大垃圾请求分配 Buffer）
        if (approxBytes > CONFIG.SECURITY.MAX_LOGIN_BODY_SIZE) {
            return { statusCode: 413, headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ success: false, message: 'Request too large' }), isBase64Encoded: false };
        }
        const bodyBuf = decodeBody();
        if (bodyBuf.length > CONFIG.SECURITY.MAX_LOGIN_BODY_SIZE) {
            return { statusCode: 413, headers: { ...corsHeaders, 'content-type': 'application/json', 'cache-control': 'no-store' }, body: JSON.stringify({ success: false, message: 'Request too large' }), isBase64Encoded: false };
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
        if (method !== 'POST') {
            sendJson(405, { success: false, message: 'Method Not Allowed' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }
        const auth = hdrs['authorization'];
        const token = auth && String(auth).startsWith('Bearer ') ? String(auth).slice(7) : null;
        // 先鉴权，通过后才解码 body —— 未认证的大 body 不该分配 Buffer
        if (!checkToken(token)) {
            sendJson(401, { success: false, message: 'Unauthorized' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const contentType = String(hdrs['content-type'] || '').split(';')[0].trim().toLowerCase();
        if (!ALLOWED_MIME_TYPES.has(contentType)) {
            sendJson(400, { success: false, message: 'File type not allowed.' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const cl = parseInt(hdrs['content-length'] || '0', 10);
        if (cl > CONFIG.SECURITY.MAX_FILE_SIZE) {
            sendJson(413, { success: false, message: 'File too large' });
            return { statusCode, headers: responseHeaders, body: responseBody, isBase64Encoded: false };
        }

        const bodyBuf = decodeBody();
        if (bodyBuf.length > CONFIG.SECURITY.MAX_FILE_SIZE) {
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
        // 路径格式：m/YY{月字母}DD/随机名 —— a=1月…l=12月（例：26j07 = 2026年10月7日）
        // 用北京时间(+8)取日期，避免FC默认UTC导致凌晨上传落到前一天
        const d = new Date(Date.now() + 8 * 3600 * 1000);
        const yy = String(d.getUTCFullYear()).slice(2);
        const mon = 'abcdefghijkl'[d.getUTCMonth()];
        const dd = String(d.getUTCDate()).padStart(2, '0');
        const key = `m/${yy}${mon}${dd}/${randomName}${ext}`;

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
