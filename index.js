// ============================================================
//  MIO SHOP - index.js (tanpa chat, dengan contact sosial & profil lengkap)
//  Database: JSON files (users, products, follows)
// ============================================================

const express     = require('express');
const http        = require('http');
const fs          = require('fs');
const path        = require('path');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const multer      = require('multer');
const cookieParser= require('cookie-parser');
const rateLimit   = require('express-rate-limit');
const helmet      = require('helmet');
const cors        = require('cors');
const { v4: uuid }= require('uuid');

// ─── CONFIG ──────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'MioShop_S3cr3t_K3y_2024!_ChangeMe';
const DATA_DIR   = path.join(__dirname, 'data');
const UPLOADS_DIR= path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ─── AUTO-CREATE DIRECTORIES & DATABASE ──────────────────────
const dirs = [DATA_DIR, UPLOADS_DIR, PUBLIC_DIR,
  path.join(UPLOADS_DIR, 'avatars'),
  path.join(UPLOADS_DIR, 'wallpapers'),
  path.join(UPLOADS_DIR, 'products')
];
dirs.forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

const DB_FILES = {
  users:    path.join(DATA_DIR, 'users.json'),
  products: path.join(DATA_DIR, 'products.json'),
  follows:  path.join(DATA_DIR, 'follows.json'),
};
Object.entries(DB_FILES).forEach(([, fp]) => {
  if (!fs.existsSync(fp)) fs.writeFileSync(fp, '[]', 'utf8');
});
console.log('✅ Database JSON files ready in ./data/');

// ─── DB HELPERS ───────────────────────────────────────────────
const readDB  = (key) => JSON.parse(fs.readFileSync(DB_FILES[key], 'utf8'));
const writeDB = (key, data) => fs.writeFileSync(DB_FILES[key], JSON.stringify(data, null, 2), 'utf8');

// ─── MULTER STORAGE ───────────────────────────────────────────
const makeStorage = (dest) => multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(UPLOADS_DIR, dest)),
  filename:    (_, file, cb) => cb(null, uuid() + path.extname(file.originalname))
});
const imgFilter = (_, file, cb) =>
  /image\/(jpeg|jpg|png|gif|webp)/.test(file.mimetype) ? cb(null, true) : cb(new Error('Only images allowed'));

const uploadAvatar    = multer({ storage: makeStorage('avatars'),   fileFilter: imgFilter, limits: { fileSize: 5e6 } });
const uploadWallpaper = multer({ storage: makeStorage('wallpapers'),fileFilter: imgFilter, limits: { fileSize: 10e6 } });
const uploadProduct   = multer({ storage: makeStorage('products'),  fileFilter: imgFilter, limits: { fileSize: 5e6, files: 5 } });

// ─── JWT MIDDLEWARE ───────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.cookies?.token || req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Token invalid or expired' }); }
};

// ─── APP SETUP ───────────────────────────────────────────────
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.static(PUBLIC_DIR));

// Rate limiters
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many requests, slow down.' } });
const apiLimiter  = rateLimit({ windowMs: 1 * 60 * 1000,  max: 120 });
app.use('/api/auth', authLimiter);
app.use('/api',      apiLimiter);

// ─── API: AUTH ────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Username 3-20 chars, letters/numbers/_' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password min 6 characters' });

  const users = readDB('users');
  if (users.find(u => u.username === username || u.email === email))
    return res.status(409).json({ error: 'Username or email already exists' });

  const hash = await bcrypt.hash(password, 12);
  const user = {
    id: uuid(), username, email,
    password: hash,
    bio: '', avatar: null, wallpaper: null,
    createdAt: new Date().toISOString()
  };
  users.push(user);
  writeDB('users', users);
  res.json({ message: 'Registered successfully' });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const users = readDB('users');
  const user  = users.find(u => u.username === username || u.email === username);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Wrong username or password' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'strict' });
  res.json({ message: 'Login successful', token, user: safeUser(user) });
});

app.post('/api/auth/logout', (_, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

app.get('/api/auth/me', auth, (req, res) => {
  const users = readDB('users');
  const user  = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(safeUser(user));
});

const safeUser = (u) => ({ id: u.id, username: u.username, email: u.email, bio: u.bio, avatar: u.avatar, wallpaper: u.wallpaper, createdAt: u.createdAt });

// ─── API: USERS (untuk stats & list user) ────────────────────
app.get('/api/users', (req, res) => {
  const users = readDB('users');
  const limit = req.query.limit ? parseInt(req.query.limit) : users.length;
  res.json(users.slice(0, limit).map(u => safeUser(u)));
});

// Get single user by username (with follow counts)
app.get('/api/users/:username', (req, res) => {
  const users   = readDB('users');
  const follows = readDB('follows');
  const user    = users.find(u => u.username === req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const followerCount  = follows.filter(f => f.followingId === user.id).length;
  const followingCount = follows.filter(f => f.followerId  === user.id).length;
  res.json({ ...safeUser(user), followerCount, followingCount });
});

// Get user by ID (for internal use)
app.get('/api/users/id/:userId', (req, res) => {
  const users = readDB('users');
  const user = users.find(u => u.id === req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(safeUser(user));
});

// ─── API: PROFILE ─────────────────────────────────────────────
app.put('/api/profile', auth, (req, res) => {
  const users = readDB('users');
  const idx   = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const { bio } = req.body;
  if (bio !== undefined) users[idx].bio = bio.slice(0, 200);
  writeDB('users', users);
  res.json(safeUser(users[idx]));
});

app.post('/api/profile/avatar', auth, uploadAvatar.single('avatar'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const users = readDB('users');
  const idx   = users.findIndex(u => u.id === req.user.id);
  users[idx].avatar = '/uploads/avatars/' + req.file.filename;
  writeDB('users', users);
  res.json({ avatar: users[idx].avatar });
});

app.post('/api/profile/wallpaper', auth, uploadWallpaper.single('wallpaper'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const users = readDB('users');
  const idx   = users.findIndex(u => u.id === req.user.id);
  users[idx].wallpaper = '/uploads/wallpapers/' + req.file.filename;
  writeDB('users', users);
  res.json({ wallpaper: users[idx].wallpaper });
});

// ─── API: PRODUCTS ────────────────────────────────────────────
// List products (with optional filter)
app.get('/api/products', (req, res) => {
  const products = readDB('products');
  const { userId, q, category } = req.query;
  let result = products.filter(p => p.published);
  if (userId)   result = result.filter(p => p.userId === userId);
  if (category) result = result.filter(p => p.category === category);
  if (q)        result = result.filter(p =>
    p.title.toLowerCase().includes(q.toLowerCase()) ||
    p.description.toLowerCase().includes(q.toLowerCase())
  );
  res.json(result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// My products (including drafts)
app.get('/api/products/mine', auth, (req, res) => {
  const products = readDB('products');
  res.json(products.filter(p => p.userId === req.user.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// Single product
app.get('/api/products/:id', (req, res) => {
  const products = readDB('products');
  const p = products.find(p => p.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Product not found' });
  res.json(p);
});

// Create product
app.post('/api/products', auth, uploadProduct.array('photos', 5), (req, res) => {
  const { title, description, price, category, type, downloadUrl, tags, published, contactWa, contactTiktok, contactIg } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'Title and description required' });
  const photos   = (req.files || []).map(f => '/uploads/products/' + f.filename);
  const products = readDB('products');
  const product  = {
    id: uuid(),
    userId: req.user.id,
    username: req.user.username,
    title: title.slice(0, 100),
    description: description.slice(0, 2000),
    price: parseFloat(price) || 0,
    category: category || 'other',
    type: type || 'digital',
    downloadUrl: downloadUrl || '',
    tags: tags ? tags.split(',').map(t => t.trim()).slice(0, 10) : [],
    photos,
    published: published === 'true',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    contactWa: contactWa || '',
    contactTiktok: contactTiktok || '',
    contactIg: contactIg || ''
  };
  products.push(product);
  writeDB('products', products);
  res.status(201).json(product);
});

// Edit product
app.put('/api/products/:id', auth, uploadProduct.array('photos', 5), (req, res) => {
  const products = readDB('products');
  const idx      = products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });
  if (products[idx].userId !== req.user.id) return res.status(403).json({ error: 'Not your product' });

  const { title, description, price, category, type, downloadUrl, tags, published, removePhotos, contactWa, contactTiktok, contactIg } = req.body;
  const p = products[idx];
  if (title)       p.title       = title.slice(0, 100);
  if (description) p.description = description.slice(0, 2000);
  if (price !== undefined) p.price = parseFloat(price) || 0;
  if (category)    p.category    = category;
  if (type)        p.type        = type;
  if (downloadUrl !== undefined) p.downloadUrl = downloadUrl;
  if (tags)        p.tags        = tags.split(',').map(t => t.trim()).slice(0, 10);
  if (published !== undefined) p.published = published === 'true';
  if (contactWa !== undefined) p.contactWa = contactWa;
  if (contactTiktok !== undefined) p.contactTiktok = contactTiktok;
  if (contactIg !== undefined) p.contactIg = contactIg;

  // Remove selected photos
  if (removePhotos) {
    const toRemove = JSON.parse(removePhotos);
    p.photos = p.photos.filter(ph => !toRemove.includes(ph));
  }
  // Add new photos (max 5 total)
  const newPhotos = (req.files || []).map(f => '/uploads/products/' + f.filename);
  p.photos = [...p.photos, ...newPhotos].slice(0, 5);
  p.updatedAt = new Date().toISOString();
  writeDB('products', products);
  res.json(p);
});

// Delete product
app.delete('/api/products/:id', auth, (req, res) => {
  const products = readDB('products');
  const idx      = products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Product not found' });
  if (products[idx].userId !== req.user.id) return res.status(403).json({ error: 'Not your product' });
  products.splice(idx, 1);
  writeDB('products', products);
  res.json({ message: 'Product deleted' });
});

// ─── API: FOLLOW ──────────────────────────────────────────────
app.post('/api/follow/:userId', auth, (req, res) => {
  if (req.user.id === req.params.userId) return res.status(400).json({ error: "Can't follow yourself" });
  const follows = readDB('follows');
  const exists  = follows.find(f => f.followerId === req.user.id && f.followingId === req.params.userId);
  if (exists) {
    writeDB('follows', follows.filter(f => !(f.followerId === req.user.id && f.followingId === req.params.userId)));
    return res.json({ following: false });
  }
  follows.push({ id: uuid(), followerId: req.user.id, followingId: req.params.userId, createdAt: new Date().toISOString() });
  writeDB('follows', follows);
  res.json({ following: true });
});

app.get('/api/follow/status/:userId', auth, (req, res) => {
  const follows  = readDB('follows');
  const following = !!follows.find(f => f.followerId === req.user.id && f.followingId === req.params.userId);
  res.json({ following });
});

// Get followers list for a user
app.get('/api/followers/:userId', (req, res) => {
  const follows = readDB('follows');
  const users = readDB('users');
  const followers = follows.filter(f => f.followingId === req.params.userId).map(f => {
    const user = users.find(u => u.id === f.followerId);
    return user ? safeUser(user) : null;
  }).filter(Boolean);
  res.json(followers);
});

// Get following list for a user
app.get('/api/following/:userId', (req, res) => {
  const follows = readDB('follows');
  const users = readDB('users');
  const following = follows.filter(f => f.followerId === req.params.userId).map(f => {
    const user = users.find(u => u.id === f.followingId);
    return user ? safeUser(user) : null;
  }).filter(Boolean);
  res.json(following);
});

// ─── FRONTEND ────────────────────────────────────────────
// Route '/' dilayani oleh express.static(PUBLIC_DIR)

// ─── START SERVER ─────────────────────────────────────────────
const server = http.createServer(app);
server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║  🛍  MIO SHOP is running!            ║
║  http://localhost:${PORT}               ║
╚══════════════════════════════════════╝

📁 Data: ./data/  (users, products, follows)
📷 Uploads: ./uploads/
🔐 JWT Secret: set env JWT_SECRET to override

✨ Fitur:
   - Jual/Beli produk digital
   - Upload hingga 5 foto per produk
   - Follow kreator favorit
   - Kontak WhatsApp, TikTok, Instagram
   - Lihat profil penjual & produknya
   - Mobile friendly
`);
});
