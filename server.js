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
// ---- email verification (needs the Brevo settings below; without them new users are auto-verified so nobody gets locked out) ----
const sha = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const mailReady = () => !!(process.env.BREVO_API_KEY && process.env.MAIL_FROM);
const appBase = req => (process.env.APP_URL || (req.protocol + '://' + req.get('host'))).replace(/\/$/, '');
async function issueVerification(u, req) {
  const token = crypto.randomBytes(32).toString('hex');
  await q("INSERT INTO email_verifications(user_id,token_hash,expires_at,created_at) VALUES ($1,$2,NOW() + INTERVAL '24 hours',NOW()) ON CONFLICT (user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash, expires_at=EXCLUDED.expires_at, created_at=NOW()", [u.id, sha(token)]);
  const link = appBase(req) + '/#verify=' + token;
  try {
    return await sendMail(u.email, 'Verify your email - IEM Admission Portal',
      '<p>Hello ' + u.name.replace(/[<>&]/g, '') + ',</p><p>Thank you for registering. Please confirm your email address to activate your account. The link is valid for 24 hours.</p><p><a href="' + link + '">Verify my email</a></p><p>If you did not register, ignore this email.</p>',
      'Hello ' + u.name + ', open this link to verify your email (valid 24 hours): ' + link);
  } catch (err) { console.error(err.message); return false; }
}
app.post('/api/register', wrap(async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name?.trim() || !/\S+@\S+\.\S+/.test(email || '') || !/^\d{10}$/.test(phone || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Enter a valid name, email, 10-digit phone and a password of 6+ characters' });
  const e = email.trim().toLowerCase();
  if ((await q('SELECT 1 FROM users WHERE email=$1', [e])).rowCount) return res.status(409).json({ error: 'Email already registered' });
  const needs = mailReady();
  const u = (await q('INSERT INTO users(name,email,phone,password,email_verified) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email', [name.trim(), e, phone, hash(password), !needs])).rows[0];
  if (!needs) { console.log('[email verification skipped: BREVO_API_KEY / MAIL_FROM not set]', e); return res.status(201).json({ ok: true, needsVerification: false }); }
  const sent = await issueVerification(u, req);
  res.status(201).json({ ok: true, needsVerification: true, emailSent: sent });
}));
app.post('/api/login', wrap(async (req, res) => {
  const { email, password, role } = req.body;
  const id = (email || '').trim().toLowerCase();
  let u = (await q('SELECT * FROM users WHERE LOWER(email)=$1', [id])).rows[0];
  if (!u && id && !id.includes('@')) { const m = (await q("SELECT * FROM users WHERE LOWER(email) LIKE $1 AND role='applicant'", [id.replace(/[\\%_]/g, '') + '@%'])).rows; if (m.length === 1) u = m[0]; }
  if (!u || !check(password || '', u.password) || u.role !== (role || 'applicant')) return res.status(401).json({ error: 'Invalid credentials for ' + (role || 'applicant') + ' login' });
  if (u.email_verified === false) return res.status(403).json({ code: 'unverified', error: 'Please verify your email first. We sent a link to ' + u.email + '.' });
  const token = crypto.randomUUID(); sessions.set(token, u.id);
  res.json({ token, user: { id: u.id, name: u.name, email: u.email, phone: u.phone, role: u.role } });
}));
app.post('/api/verify-email', wrap(async (req, res) => {
  const r = (await q('SELECT user_id FROM email_verifications WHERE token_hash=$1 AND expires_at>NOW()', [sha((req.body || {}).token || '')])).rows[0];
  if (!r) return res.status(400).json({ error: 'This verification link is invalid or has expired. Request a new one from the login page.' });
  await q('UPDATE users SET email_verified=TRUE WHERE id=$1', [r.user_id]);
  await q('DELETE FROM email_verifications WHERE user_id=$1', [r.user_id]);
  res.json({ ok: true });
}));
app.post('/api/resend-verification', wrap(async (req, res) => {
  const e = (((req.body || {}).email) || '').trim().toLowerCase();
  const generic = { ok: true, message: 'If that account is waiting for verification, a new link has been sent.' };
  const u = e && (await q("SELECT u.id,u.name,u.email,(SELECT created_at FROM email_verifications v WHERE v.user_id=u.id) AS last_sent, (SELECT created_at > NOW() - INTERVAL '60 seconds' FROM email_verifications v WHERE v.user_id=u.id) AS too_soon FROM users u WHERE u.email=$1 AND u.email_verified=FALSE", [e])).rows[0];
  if (!u) return res.json(generic);
  if (u.too_soon) return res.status(429).json({ error: 'Please wait a minute before requesting another email.' });
  await issueVerification(u, req);
  res.json(generic);
}));

// ---- forgot / reset password + shared mail sender (Brevo's web API) ----
// Needs BREVO_API_KEY + MAIL_FROM (a sender verified in Brevo) + APP_URL. Without them the link is only printed in the server log.
async function sendMail(to, subject, html, text) {
  if (!process.env.BREVO_API_KEY || !process.env.MAIL_FROM) { console.log('[email not configured] to:', to, '|', subject, '|', text); return false; }
  const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST',
    headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ sender: { name: 'IEM Admission Portal', email: process.env.MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html, textContent: text }) });
  if (!r.ok) throw new Error('email failed: ' + r.status + ' ' + (await r.text()).slice(0, 200));
  return true;
}
app.post('/api/forgot-password', wrap(async (req, res) => {
  const e = (((req.body || {}).email) || '').trim().toLowerCase();
  const generic = { ok: true, message: 'If that email is registered, a reset link has been sent. It is valid for 30 minutes.' };
  const u = e && (await q("SELECT id,name,email FROM users WHERE email=$1 AND role='applicant'", [e])).rows[0];
  if (!u) return res.json(generic);                         // same answer either way, so emails cannot be guessed
  const token = crypto.randomBytes(32).toString('hex');
  await q("INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES ($1,$2,NOW() + INTERVAL '30 minutes') ON CONFLICT (user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash, expires_at=EXCLUDED.expires_at", [u.id, sha(token)]);
  const base = (process.env.APP_URL || (req.protocol + '://' + req.get('host'))).replace(/\/$/, '');
  const link = base + '/#reset=' + token;
  try {
    await sendMail(u.email, 'Reset your IEM Admission Portal password',
      '<p>Hello ' + u.name.replace(/[<>&]/g, '') + ',</p><p>Click the link below to set a new password. It is valid for 30 minutes.</p><p><a href="' + link + '">Reset my password</a></p><p>If you did not ask for this, ignore this email.</p>',
      'Hello ' + u.name + ', open this link to set a new password (valid 30 minutes): ' + link);
  } catch (err) { console.error(err.message); }
  res.json(generic);
}));
app.post('/api/reset-password', wrap(async (req, res) => {
  const { token, next } = req.body || {};
  if (typeof next !== 'string' || next.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const r = (await q('SELECT user_id FROM password_resets WHERE token_hash=$1 AND expires_at>NOW()', [sha(token || '')])).rows[0];
  if (!r) return res.status(400).json({ error: 'This reset link is invalid or has expired. Please request a new one.' });
  await q('UPDATE users SET password=$1 WHERE id=$2', [hash(next), r.user_id]);
  await q('DELETE FROM password_resets WHERE user_id=$1', [r.user_id]);
  for (const [t, id] of sessions) if (id === r.user_id) sessions.delete(t);   // sign out other devices
  res.json({ ok: true });
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
const PROFILE_COLS = 'id,name,email,phone,role,dob,gender,address,city,state,pincode,guardian_name,guardian_phone,designation,department,about,created_at';
app.get('/api/profile', wrap(async (req, res) => res.json((await q('SELECT ' + PROFILE_COLS + ' FROM users WHERE id=$1', [req.user.id])).rows[0])));
app.put('/api/profile', wrap(async (req, res) => {
  const b = req.body || {}, t = (k, max) => (typeof b[k] === 'string' ? b[k].trim().slice(0, max) : '');
  const name = t('name', 100), phone = t('phone', 10), dob = t('dob', 10), gender = t('gender', 20), pincode = t('pincode', 6), gphone = t('guardian_phone', 10);
  if (!name) return res.status(400).json({ error: 'Name is required' });
  if (!/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Phone must be 10 digits' });
  if (dob && (!/^\d{4}-\d{2}-\d{2}$/.test(dob) || isNaN(Date.parse(dob)) || new Date(dob) > new Date())) return res.status(400).json({ error: 'Enter a valid date of birth' });
  if (gender && !['Male', 'Female', 'Other'].includes(gender)) return res.status(400).json({ error: 'Invalid gender' });
  if (pincode && !/^\d{6}$/.test(pincode)) return res.status(400).json({ error: 'PIN code must be 6 digits' });
  if (gphone && !/^\d{10}$/.test(gphone)) return res.status(400).json({ error: 'Guardian phone must be 10 digits' });
  const admin = req.user.role === 'admin';
  await q('UPDATE users SET name=$1, phone=$2, dob=$3, gender=$4, address=$5, city=$6, state=$7, pincode=$8, guardian_name=$9, guardian_phone=$10, designation=$11, department=$12, about=$13 WHERE id=$14',
    [name, phone, dob || null, gender || null, t('address', 250) || null, t('city', 80) || null, t('state', 80) || null, pincode || null,
     admin ? null : (t('guardian_name', 100) || null), admin ? null : (gphone || null),
     admin ? (t('designation', 100) || null) : null, admin ? (t('department', 100) || null) : null, t('about', 500) || null, req.user.id]);
  res.json((await q('SELECT ' + PROFILE_COLS + ' FROM users WHERE id=$1', [req.user.id])).rows[0]);
}));
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
// ---- admin: overview, every registered student (even with no application), documents ----
const stageOf = r => !r.app_id ? 'Registered' : r.status !== 'Draft' ? r.status : r.docs >= 4 ? 'Awaiting payment' : r.docs > 0 ? 'Uploading documents' : 'Form in progress';
const studentRows = async () => (await q(`SELECT u.id, u.name, u.email, u.phone, u.email_verified, u.created_at, a.id AS app_id, a.app_no, a.status, a.payment_status, a.program_code, a.merit,
    COALESCE(d.n, 0) AS docs, (SELECT COUNT(*)::int FROM applications x WHERE x.user_id = u.id) AS app_count
  FROM users u LEFT JOIN LATERAL (SELECT * FROM applications x WHERE x.user_id = u.id ORDER BY x.id DESC LIMIT 1) a ON TRUE
  LEFT JOIN LATERAL (SELECT COUNT(*)::int AS n FROM documents WHERE application_id = a.id AND doc_type IN ('tenth','twelfth','photo_id','photograph')) d ON TRUE
  WHERE u.role = 'applicant' ORDER BY u.created_at DESC, u.id DESC`)).rows.map(r => ({ ...r, stage: stageOf(r) }));
app.get('/api/admin/students', admin, wrap(async (req, res) => res.json(await studentRows())));
app.get('/api/admin/overview', admin, wrap(async (req, res) => {
  const st = await studentRows(), n = f => st.filter(f).length, by = {};
  for (const r of st) by[r.stage] = (by[r.stage] || 0) + 1;
  const programs = (await q(`SELECT p.code, p.name, p.intake,
      COUNT(a.id) FILTER (WHERE a.status <> 'Draft')::int AS submitted, COUNT(a.id) FILTER (WHERE a.status = 'Admitted')::int AS admitted,
      COUNT(a.id) FILTER (WHERE a.status = 'Waitlisted')::int AS waitlisted, COUNT(a.id) FILTER (WHERE a.status = 'Rejected')::int AS rejected,
      COUNT(a.id) FILTER (WHERE a.status = 'Draft')::int AS drafts
    FROM programs p LEFT JOIN applications a ON a.program_code = p.code GROUP BY p.code, p.name, p.intake ORDER BY p.code`)).rows;
  const apps = (await q(`SELECT COUNT(*) FILTER (WHERE status <> 'Draft')::int AS submitted, COUNT(*) FILTER (WHERE payment_status = 'Success')::int AS paid, COUNT(*)::int AS total FROM applications`)).rows[0];
  res.json({ registered: st.length, verified: n(r => r.email_verified), unverified: n(r => !r.email_verified), notApplied: by.Registered || 0, stages: by, apps, programs });
}));
app.get('/api/admin/payments', admin, wrap(async (req, res) => res.json((await q(`SELECT p.id, p.txn_id, p.method, p.amount, p.status, p.paid_at, a.id AS app_id, a.app_no, a.full_name, a.email, a.program_code
  FROM payments p JOIN applications a ON a.id = p.application_id ORDER BY p.paid_at DESC, p.id DESC`)).rows)));
app.get('/api/admin/applications/:id/documents/:type', admin, wrap(async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(404).json({ error: 'Not found' });
  const d = (await q('SELECT filename,mime,data FROM documents WHERE application_id=$1 AND doc_type=$2', [req.params.id, req.params.type])).rows[0];
  d ? res.json(d) : res.status(404).json({ error: 'Document not found' });
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
  await q(`UPDATE users SET designation=COALESCE(designation,'Admission Officer'), department=COALESCE(department,'Admission Cell'),
      address=COALESCE(address,'Institute of Engineering & Management, Y-12, GN Block, Sector V, Salt Lake Electronics Complex'), city=COALESCE(city,'Kolkata'),
      state=COALESCE(state,'West Bengal'), pincode=COALESCE(pincode,'700091'),
      about=COALESCE(about,'Manages the undergraduate admission process: reviews applications and documents, tracks payments, runs merit allocation and publishes admission results.')
    WHERE role='admin'`);
  if (process.env.SEED_DEMO === 'true') { const n = await require('./seed-demo')(q); console.log('Demo students added:', n); }
  app.listen(process.env.PORT || 5000, () => console.log('IEM Portal (PostgreSQL) running at http://localhost:' + (process.env.PORT || 5000)));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
