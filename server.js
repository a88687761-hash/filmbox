import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-this-password';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const DATA_DIR = path.join(__dirname, 'data');
const VIDEOS_FILE = path.join(DATA_DIR, 'videos.json');
const VISITORS_FILE = path.join(DATA_DIR, 'visitors.json');

await fs.mkdir(DATA_DIR, { recursive: true });
for (const file of [VIDEOS_FILE, VISITORS_FILE]) {
  try { await fs.access(file); } catch { await fs.writeFile(file, '[]'); }
}

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

async function readJson(file, fallback = []) {
  try { return JSON.parse(await fs.readFile(file, 'utf8')); } catch { return fallback; }
}
async function writeJson(file, value) {
  await fs.writeFile(file, JSON.stringify(value, null, 2), 'utf8');
}
function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}
function makeSession() {
  const payload = `${Date.now()}`;
  return `${payload}.${sign(payload)}`;
}
function isAdmin(req) {
  const raw = req.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith('admin_session='));
  if (!raw) return false;
  const value = decodeURIComponent(raw.split('=').slice(1).join('='));
  const [timestamp, signature] = value.split('.');
  if (!timestamp || !signature || !/^\d+$/.test(timestamp)) return false;
  if (Date.now() - Number(timestamp) > 24 * 60 * 60 * 1000) return false;
  const expected = sign(timestamp);
  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? String(forwarded).split(',')[0].trim() : req.socket.remoteAddress || '';
  return ip.replace(/^::ffff:/, '');
}
function maskIp(ip) {
  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.x.x`;
  }
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':') + ':…';
  return 'نامشخص';
}

app.post('/api/admin/login', (req, res) => {
  const password = String(req.body?.password || '');
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'رمز عبور اشتباه است.' });
  const session = makeSession();
  res.setHeader('Set-Cookie', `admin_session=${encodeURIComponent(session)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`);
  res.json({ ok: true });
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/admin/me', (req, res) => res.json({ admin: isAdmin(req) }));

app.get('/api/videos', async (req, res) => {
  const videos = await readJson(VIDEOS_FILE, []);
  res.json(videos);
});

app.post('/api/videos', async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'دسترسی غیرمجاز' });
  const { title, description = '', year = '', genre = '', poster = '', videoUrl } = req.body || {};
  if (!title || !videoUrl) return res.status(400).json({ error: 'عنوان و لینک ویدئو الزامی است.' });
  const videos = await readJson(VIDEOS_FILE, []);
  const id = videos.reduce((max, v) => Math.max(max, Number(v.id) || 0), 0) + 1;
  const item = { id, title: String(title).slice(0, 120), description: String(description).slice(0, 500), year: String(year).slice(0, 10), genre: String(genre).slice(0, 50), poster: String(poster).slice(0, 1000), videoUrl: String(videoUrl).slice(0, 2000) };
  videos.push(item);
  await writeJson(VIDEOS_FILE, videos);
  res.json(item);
});

app.delete('/api/videos/:id', async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'دسترسی غیرمجاز' });
  const id = Number(req.params.id);
  const videos = await readJson(VIDEOS_FILE, []);
  const next = videos.filter(v => Number(v.id) !== id);
  await writeJson(VIDEOS_FILE, next);
  res.json({ ok: true });
});

app.get('/api/admin/visitors', async (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ error: 'دسترسی غیرمجاز' });
  const visitors = await readJson(VISITORS_FILE, []);
  res.json(visitors.slice(-500).reverse());
});

app.post('/api/track', async (req, res) => {
  const ua = String(req.headers['user-agent'] || '').slice(0, 300);
  const referrer = String(req.headers.referer || '').slice(0, 500);
  const page = String(req.body?.page || '/').slice(0, 300);
  const ip = getClientIp(req);
  const visitors = await readJson(VISITORS_FILE, []);
  visitors.push({
    id: crypto.randomUUID(),
    time: new Date().toISOString(),
    ip: maskIp(ip),
    page,
    referrer,
    userAgent: ua
  });
  if (visitors.length > 5000) visitors.splice(0, visitors.length - 5000);
  await writeJson(VISITORS_FILE, visitors);
  res.status(204).end();
});

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/watch/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'watch.html')));

app.listen(PORT, () => console.log(`FilmBox running on http://localhost:${PORT}`));
