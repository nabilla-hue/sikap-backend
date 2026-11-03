process.env.TZ = 'Asia/Jakarta';
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const db = new Database(process.env.DB_FILE || path.join(__dirname, 'sikap.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, nama TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('pemilik','kasir')), pass_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS menu(id INTEGER PRIMARY KEY, nama TEXT NOT NULL, harga INTEGER NOT NULL, aktif INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS transaksi(id INTEGER PRIMARY KEY, tgl TEXT NOT NULL, jam TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id), metode TEXT NOT NULL, total INTEGER NOT NULL, bayar INTEGER NOT NULL, kembali INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS transaksi_item(id INTEGER PRIMARY KEY, transaksi_id INTEGER NOT NULL REFERENCES transaksi(id), menu_id INTEGER NOT NULL REFERENCES menu(id), nama TEXT NOT NULL, harga INTEGER NOT NULL, qty INTEGER NOT NULL);
`);

const hash = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const verify = (p, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(p, s, 64), Buffer.from(k, 'hex')); };

if (!db.prepare('SELECT COUNT(*) c FROM users').get().c) {
  db.transaction(() => {
    const u = db.prepare('INSERT INTO users(username,nama,role,pass_hash) VALUES(?,?,?,?)');
    u.run('pemilik', 'Pemilik', 'pemilik', hash('pemilik123'));
    u.run('kasir', 'Kasir', 'kasir', hash('kasir123'));
    const m = db.prepare('INSERT INTO menu(nama,harga) VALUES(?,?)');
    [['Soto Betawi Daging', 35000], ['Soto Betawi Tetelan', 30000], ['Soto Betawi Campur', 38000], ['Nasi putih', 5000], ['Emping', 5000], ['Es teh manis', 6000], ['Es jeruk', 8000]]
      .forEach(([n, h]) => m.run(n, h));
  })();
}

// Sesi (disimpan di memori server) dan pembatasan percobaan login
const sessions = new Map(), fails = new Map();
const cookie = req => (/(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '') || [])[1];
const auth = role => (req, res, next) => {
  const s = sessions.get(cookie(req));
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Silakan masuk terlebih dahulu.' });
  req.user = db.prepare('SELECT id,username,nama,role FROM users WHERE id=?').get(s.uid);
  if (!req.user) return res.status(401).json({ error: 'Akun tidak ditemukan.' });
  if (role && req.user.role !== role) return res.status(403).json({ error: 'Akses ditolak untuk peran Anda.' });
  next();
};
const pub = u => ({ u: u.username, n: u.nama, r: u.role });

function trxList(where, arg) {
  const rows = db.prepare(`SELECT t.*,u.nama kasir FROM transaksi t JOIN users u ON u.id=t.user_id ${where} ORDER BY t.id`).all(...arg);
  const it = db.prepare('SELECT * FROM transaksi_item WHERE transaksi_id=?');
  return rows.map(t => ({ id: t.id, tgl: t.tgl, jam: t.jam, total: t.total, metode: t.metode, bayar: t.bayar, kembali: t.kembali, kasir: t.kasir,
    items: it.all(t.id).map(i => ({ id: String(i.menu_id), nama: i.nama, harga: i.harga, qty: i.qty })) }));
}
function state(user) {
  const S = {
    menu: db.prepare('SELECT * FROM menu WHERE aktif=1 ORDER BY id').all().map(m => ({ id: String(m.id), nama: m.nama, harga: m.harga })),
    trx: [], users: []
  };
  if (user.role === 'pemilik') {
    S.trx = trxList('', []);
    S.users = db.prepare('SELECT username,nama,role FROM users ORDER BY id').all().map(u => ({ u: u.username, n: u.nama, r: u.role }));
  }
  return S;
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', (req, res) => {
  const ip = req.ip, f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 60000) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 5) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi dalam 1 menit.' });
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || '').toLowerCase());
  if (!u || !verify(String(password || ''), u.pass_hash)) { fails.set(ip, { n: f.n + 1, t: f.t }); return res.status(401).json({ error: 'Nama pengguna atau kata sandi salah.' }); }
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { uid: u.id, exp: Date.now() + 12 * 3600e3 });
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200`);
  res.json({ user: pub({ username: u.username, nama: u.nama, role: u.role }) });
});
app.post('/api/logout', (req, res) => { sessions.delete(cookie(req)); res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); res.json({ ok: true }); });
app.get('/api/me', auth(), (req, res) => res.json({ user: pub(req.user) }));
app.get('/api/state', auth(), (req, res) => res.json(state(req.user)));

app.post('/api/checkout', auth(), (req, res) => {
  const { items, metode, bayar } = req.body || {};
  if (!Array.isArray(items) || !items.length || !['Tunai', 'QRIS', 'Transfer'].includes(metode)) return res.status(400).json({ error: 'Data pesanan tidak valid.' });
  try {
    const id = db.transaction(() => {
      let total = 0; const lines = [];
      for (const it of items) {
        const qty = Math.floor(+it.qty), m = db.prepare('SELECT * FROM menu WHERE id=? AND aktif=1').get(+it.id);
        if (!m || !(qty > 0)) throw new Error('Menu tidak valid.');
        total += m.harga * qty; lines.push({ m, qty });
      }
      const paid = metode === 'Tunai' ? Math.floor(+bayar) || 0 : total;
      if (paid < total) throw new Error('Uang diterima kurang dari total.');
      const now = new Date();
      const tid = db.prepare('INSERT INTO transaksi(tgl,jam,user_id,metode,total,bayar,kembali) VALUES(?,?,?,?,?,?,?)')
        .run(now.toLocaleDateString('sv-SE'), now.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' }), req.user.id, metode, total, paid, paid - total).lastInsertRowid;
      for (const l of lines) db.prepare('INSERT INTO transaksi_item(transaksi_id,menu_id,nama,harga,qty) VALUES(?,?,?,?,?)').run(tid, l.m.id, l.m.nama, l.m.harga, l.qty);
      return tid;
    })();
    res.json(trxList('WHERE t.id=?', [id])[0]);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/users', auth('pemilik'), (req, res) => {
  const { nama, username, password, peran } = req.body || {};
  if (!nama || !/^[a-z0-9_]{3,}$/.test(username || '') || (password || '').length < 6 || !['kasir', 'pemilik'].includes(peran)) return res.status(400).json({ error: 'Data pengguna tidak valid.' });
  try { db.prepare('INSERT INTO users(username,nama,role,pass_hash) VALUES(?,?,?,?)').run(username, nama, peran, hash(password)); res.json({ ok: true }); }
  catch { res.status(400).json({ error: 'Nama pengguna sudah dipakai.' }); }
});
app.put('/api/users/:u/password', auth('pemilik'), (req, res) => {
  if ((req.body?.password || '').length < 6) return res.status(400).json({ error: 'Kata sandi minimal 6 karakter.' });
  db.prepare('UPDATE users SET pass_hash=? WHERE username=?').run(hash(req.body.password), req.params.u);
  res.json({ ok: true });
});
app.delete('/api/users/:u', auth('pemilik'), (req, res) => {
  if (req.params.u === req.user.username) return res.status(400).json({ error: 'Tidak bisa menghapus akun sendiri.' });
  try { db.prepare('DELETE FROM users WHERE username=?').run(req.params.u); res.json({ ok: true }); }
  catch { res.status(400).json({ error: 'Akun ini sudah punya riwayat transaksi sehingga tidak bisa dihapus.' }); }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) app.listen(PORT, () => console.log('SIKAP berjalan di http://localhost:' + PORT));
module.exports = app;
