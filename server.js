// IEM Admission Portal - Express + PostgreSQL backend
require('dotenv').config();
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const { Pool, types } = require('pg');
types.setTypeParser(1700, parseFloat);                       // NUMERIC -> JS number
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const q = (t, p) => pool.query(t, p);

const TEXT = ['full_name','program_code','dob','gender','aadhaar','nationality','category','religion','blood_group','mobile','email','alt_mobile',
 'address1','address2','city','state','pin','country','guardian_name','relation','guardian_mobile','guardian_email','occupation','income',
 'board10','school10','year10','roll10','board12','school12','year12','roll12','other_qual','entrance_rank','entrance_roll','domicile'];
const NUM = ['marks10','marks12'], COLS = TEXT.concat(NUM);
const REQ_DOCS = ['tenth','twelfth','photo_id','photograph'], FEES = { application: 1000, tuition: 85000, other: 5000 };

const hash = (pw, salt = crypto.randomBytes(8).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const check = (pw, h) => hash(pw, h.split(':')[0]) === h;
const sessions = new Map();
const clean = b => { const o = {}; for (const c of COLS) if (c in b) { const v = b[c]; o[c] = (v === '' || v == null) ? null : NUM.includes(c) ? Number(v) : String(v).trim(); } return o; };
const upd = async (id, d) => { const ks = Object.keys(d); if (ks.length) await q(`UPDATE applications SET ${ks.map((k, i) => `${k}=$${i + 1}`).join(',')} WHERE id=$${ks.length + 1}`, [...ks.map(k => d[k]), id]); };
const notify = (uid, msg) => q('INSERT INTO notifications(user_id,message) VALUES ($1,$2)', [uid, msg]);
const getApp = async (id, u) => { if (!/^\d+$/.test(id)) return null; const { rows } = await q('SELECT * FROM applications WHERE id=$1', [id]); const a = rows[0]; return a && (u.role === 'admin' || a.user_id === u.id) ? a : null; };
const detail = async a => ({ ...a,
  documents: (await q('SELECT doc_type,filename,mime,size,uploaded_at FROM documents WHERE application_id=$1', [a.id])).rows,
  payment: (await q('SELECT * FROM payments WHERE application_id=$1 ORDER BY id DESC LIMIT 1', [a.id])).rows[0] || null, fees: FEES });

const app = express();
app.use(express.json({ limit: '6mb' }));
app.use(express.static(path.join(__dirname, 'public')));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });

app.get('/api/programs', wrap(async (req, res) => res.json((await q('SELECT * FROM programs ORDER BY code')).rows)));
app.post('/api/register', wrap(async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name?.trim() || !/\S+@\S+\.\S+/.test(email || '') || !/^\d{10}$/.test(phone || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Enter a valid name, email, 10-digit phone and a password of 6+ characters' });
  const e = email.trim().toLowerCase();
  if ((await q('SELECT 1 FROM users WHERE email=$1', [e])).rowCount) return res.status(409).json({ error: 'Email already registered' });
  await q('INSERT INTO users(name,email,phone,password) VALUES ($1,$2,$3,$4)', [name.trim(), e, phone, hash(password)]);
  res.status(201).json({ ok: true });
}));
app.post('/api/login', wrap(async (req, res) => {
  const { email, password, role } = req.body;
  const u = (await q('SELECT * FROM users WHERE email=$1', [(email || '').trim().toLowerCase()])).rows[0];
  if (!u || !check(password || '', u.password) || u.role !== (role || 'applicant')) return res.status(401).json({ error: 'Invalid credentials for ' + (role || 'applicant') + ' login' });
  const token = crypto.randomUUID(); sessions.set(token, u.id);
  res.json({ token, user: { id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role } });
}));

// ---- everything below needs login ----
const auth = wrap(async (req, res, next) => {
  const uid = sessions.get((req.headers.authorization || '').replace('Bearer ', ''));
  const u = uid && (await q('SELECT id,name,email,phone,role FROM users WHERE id=$1', [uid])).rows[0];
  if (!u) return res.status(401).json({ error: 'Please login' });
  req.user = u; next();
});
app.use('/api', auth);
app.get('/api/me', (req, res) => res.json(req.user));
app.post('/api/change-password', wrap(async (req, res) => {
  const { current, next } = req.body || {};
  const row = (await q('SELECT password FROM users WHERE id=$1', [req.user.id])).rows[0];
  if (!row || !check(current || '', row.password)) return res.status(400).json({ error: 'Current password is incorrect' });
  if (typeof next !== 'string' || next.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  if (next === current) return res.status(400).json({ error: 'New password must be different from the current one' });
  await q('UPDATE users SET password=$1 WHERE id=$2', [hash(next), req.user.id]);
  res.json({ ok: true });
}));
app.get('/api/notifications', wrap(async (req, res) => res.json((await q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY id DESC', [req.user.id])).rows)));
app.post('/api/notifications/read', wrap(async (req, res) => { await q('UPDATE notifications SET is_read=TRUE WHERE user_id=$1', [req.user.id]); res.json({ ok: true }); }));

app.get('/api/applications/mine', wrap(async (req, res) => res.json((await q('SELECT * FROM applications WHERE user_id=$1 ORDER BY id DESC', [req.user.id])).rows)));
app.post('/api/applications', wrap(async (req, res) => {
  const { rows } = await q('INSERT INTO applications(user_id) VALUES ($1) RETURNING id', [req.user.id]);
  await upd(rows[0].id, clean(req.body));
  res.status(201).json(await detail(await getApp(String(rows[0].id), req.user)));
}));
app.get('/api/applications/:id', wrap(async (req, res) => { const a = await getApp(req.params.id, req.user); a ? res.json(await detail(a)) : res.status(404).json({ error: 'Not found' }); }));
app.put('/api/applications/:id', wrap(async (req, res) => {
  const a = await getApp(req.params.id, req.user); if (!a) return res.status(404).json({ error: 'Not found' });
  if (a.status !== 'Draft') return res.status(400).json({ error: 'Submitted applications cannot be edited' });
  await upd(a.id, clean(req.body)); res.json(await detail(await getApp(req.params.id, req.user)));
}));
app.post('/api/applications/:id/documents', wrap(async (req, res) => {
  const a = await getApp(req.params.id, req.user); if (!a || a.user_id !== req.user.id) return res.status(404).json({ error: 'Not found' });
  const { doc_type, filename, mime, data } = req.body;
  if (!['tenth','twelfth','photo_id','photograph','other','migration','gap'].includes(doc_type)) return res.status(400).json({ error: 'Bad document type' });
  if (!['application/pdf','image/jpeg','image/png'].includes(mime)) return res.status(400).json({ error: 'Only PDF, JPG, JPEG, PNG allowed' });
  const size = Math.floor((data || '').length * 3 / 4);
  if (!data || size > 2 * 1024 * 1024) return res.status(400).json({ error: 'Maximum file size is 2 MB' });
  await q(`INSERT INTO documents(application_id,doc_type,filename,mime,size,data) VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (application_id,doc_type) DO UPDATE SET filename=EXCLUDED.filename, mime=EXCLUDED.mime, size=EXCLUDED.size, data=EXCLUDED.data, uploaded_at=NOW()`,
    [a.id, doc_type, filename, mime, size, data]);
  res.json(await detail(a));
}));
app.delete('/api/applications/:id/documents/:type', wrap(async (req, res) => {
  const a = await getApp(req.params.id, req.user); if (!a || a.user_id !== req.user.id) return res.status(404).json({ error: 'Not found' });
  await q('DELETE FROM documents WHERE application_id=$1 AND doc_type=$2', [a.id, req.params.type]); res.json(await detail(a));
}));
app.post('/api/applications/:id/pay', wrap(async (req, res) => {
  const a = await getApp(req.params.id, req.user); if (!a || a.user_id !== req.user.id) return res.status(404).json({ error: 'Not found' });
  if (a.payment_status === 'Success') return res.status(400).json({ error: 'Already paid' });
  const miss = ['full_name','dob','mobile','email','program_code','marks10','marks12'].filter(k => a[k] == null);
  if (miss.length) return res.status(400).json({ error: 'Complete the application form first (missing: ' + miss.join(', ') + ')' });
  const have = (await q('SELECT doc_type FROM documents WHERE application_id=$1', [a.id])).rows.map(r => r.doc_type);
  if (REQ_DOCS.some(d => !have.includes(d))) return res.status(400).json({ error: 'Upload all mandatory documents first' });
  const total = FEES.application + FEES.tuition + FEES.other;
  const txn = 'TXN' + new Date().toISOString().replace(/\D/g, '').slice(2, 14) + String(a.id).padStart(3, '0');
  await q('INSERT INTO payments(application_id,txn_id,method,amount,status) VALUES ($1,$2,$3,$4,$5)', [a.id, txn, req.body.method || 'UPI', total, 'Success']);
  await q("UPDATE applications SET payment_status='Success', status='Submitted', submitted_at=NOW() WHERE id=$1", [a.id]);
  await notify(req.user.id, `Application ${a.app_no} submitted and payment of Rs. ${total} received (${txn}).`);
  res.json(await detail(await getApp(req.params.id, req.user)));
}));

// ---- admin ----
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
app.get('/api/admin/applications', admin, wrap(async (req, res) => res.json((await q(`SELECT id,app_no,full_name,email,program_code,marks10,marks12,merit,payment_status,status
  FROM applications WHERE status<>'Draft' ORDER BY program_code, merit DESC NULLS LAST, id`)).rows)));
app.post('/api/admin/allocate', admin, wrap(async (req, res) => {
  await q(`WITH r AS (SELECT a.id, pr.intake, ROW_NUMBER() OVER (PARTITION BY a.program_code ORDER BY a.merit DESC NULLS LAST, a.id) AS rn
      FROM applications a JOIN programs pr ON pr.code = a.program_code WHERE a.status <> 'Draft')
    UPDATE applications a SET status = CASE WHEN r.rn <= r.intake THEN 'Admitted' ELSE 'Waitlisted' END FROM r WHERE r.id = a.id`);
  await q(`INSERT INTO notifications(user_id,message) SELECT user_id, 'Admission result for ' || app_no || ': ' || status FROM applications WHERE status <> 'Draft'`);
  res.json({ ok: true });
}));
app.patch('/api/admin/applications/:id', admin, wrap(async (req, res) => {
  const { status } = req.body;
  if (!['Submitted','Admitted','Waitlisted','Rejected'].includes(status)) return res.status(400).json({ error: 'Bad status' });
  const a = (await q('UPDATE applications SET status=$1 WHERE id=$2 RETURNING user_id, app_no', [status, req.params.id])).rows[0];
  if (!a) return res.status(404).json({ error: 'Not found' });
  await notify(a.user_id, `Your application ${a.app_no} status is now: ${status}`); res.json({ ok: true });
}));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

(async () => {
  await q(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  await q(`INSERT INTO programs(code,name,intake,description,eligibility,duration) VALUES
    ('CSE','B.Tech in Computer Science & Engineering (CSE)',180,'Focus on software development, data structures, algorithms, AI, databases, computer networks and emerging technologies.','10+2 (PCM) with valid rank/score','4 Years'),
    ('ECE','B.Tech in Electronics & Communication Engg. (ECE)',120,'Study of electronics systems, signal processing, communication systems, VLSI, embedded systems and wireless technologies.','10+2 (PCM) with valid rank/score','4 Years'),
    ('ME','B.Tech in Mechanical Engineering (ME)',120,'Learn principles of mechanics, thermodynamics, materials, manufacturing, CAD/CAM and modern mechanical system design.','10+2 (PCM) with valid rank/score','4 Years')
    ON CONFLICT (code) DO NOTHING`);
  if (!(await q("SELECT 1 FROM users WHERE role='admin'")).rowCount)
    await q("INSERT INTO users(name,email,password,role) VALUES ('Administrator','admin',$1,'admin')", [hash('admin123')]);
  if (process.env.SEED_DEMO === 'true') { const n = await require('./seed-demo')(q); console.log('Demo students added:', n); }
  app.listen(process.env.PORT || 5000, () => console.log('IEM Portal (PostgreSQL) running at http://localhost:' + (process.env.PORT || 5000)));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
