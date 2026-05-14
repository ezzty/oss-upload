const http = require('http');
const OSS = require('ali-oss');
const crypto = require('crypto');

// 🔑 环境变量
const AUTH_USER = process.env.AUTH_USER || 'admin';
const AUTH_PASS = process.env.AUTH_PASS;
const JWT_SECRET = process.env.JWT_SECRET || 'oss-upload-secret-jin-2026';
const AK = process.env.OSS_ACCESS_KEY_ID;
const SK = process.env.OSS_ACCESS_KEY_SECRET;

if (!AUTH_PASS || !AK || !SK) console.error("❌ Missing ENV");

// 📦 OSS SDK
const client = new OSS({
    region: process.env.OSS_REGION || 'oss-cn-hangzhou',
    accessKeyId: AK,
    accessKeySecret: SK,
    bucket: process.env.OSS_BUCKET
});

// 🛡️ 防爆破
const loginAttempts = {};

const genToken = () => {
    const exp = Date.now() + 604800000;
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

http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

    // 🛡️ 防盗链
    const origin = req.headers['origin'] || '';
    if (origin && !origin.includes('example.com') && !origin.includes('10.0.0') && !origin.includes('localhost')) {
        res.writeHead(403); res.end('Access Denied'); return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);

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

    if (req.method === 'GET' && url.pathname === '/verify') {
        const t = req.headers['authorization']?.split(' ')[1];
        res.writeHead(checkToken(t) ? 200 : 401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: checkToken(t) }));
        return;
    }

    if (req.method === 'POST' && url.pathname === '/upload') {
        const t = req.headers['authorization']?.split(' ')[1];
        if (!checkToken(t)) { res.writeHead(401); res.end(); return; }

        let c = []; req.on('data', x => c.push(x));
        req.on('end', async () => {
            try {
                const buf = Buffer.concat(c);
                const name = url.searchParams.get('filename') || `${Date.now()}.jpg`;
                const d = new Date();
                const key = `img/m/${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}/${name}`;
                
                await client.put(key, buf, {
                    mime: req.headers['content-type'] || 'image/jpeg',
                    headers: { 'Content-Type': req.headers['content-type'] || 'image/jpeg' }
                });
                
                // 🌐 使用默认域名拼接图片链接
                const customUrl = `https://i.example.com/${key}`;
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: true, markdown: `![ ](${customUrl})`, direct: customUrl }));
            } catch (e) { res.writeHead(500); res.end(e.message); }
        });
        return;
    }

    res.writeHead(404); res.end('Not Found');
}).listen(9000, () => console.log('🚀 Server running on :9000'));