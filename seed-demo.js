// Demo data for the IEM Admission Portal. Runs once at startup when SEED_DEMO=true.
// Safe to run repeatedly: students that already exist (same email) are skipped.
// Every demo student logs in with the password below.
const crypto = require('crypto');
const DEMO_PASSWORD = 'Student@123';
const hash = (pw) => { const salt = crypto.randomBytes(8).toString('hex'); return salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex'); };

// state: none = account only, draft = form partly filled, paid = submitted and paid
const STUDENTS = [
  { name: 'Aarav Mehta',   email: 'aarav.mehta@demo.iem',   phone: '9000000001', prog: 'CSE', m10: 92.4, m12: 95.1, state: 'paid',  gender: 'Male',   cat: 'General', city: 'Kolkata' },
  { name: 'Ishita Roy',    email: 'ishita.roy@demo.iem',    phone: '9000000002', prog: 'CSE', m10: 88.2, m12: 91.4, state: 'paid',  gender: 'Female', cat: 'General', city: 'Howrah' },
  { name: 'Kabir Das',     email: 'kabir.das@demo.iem',     phone: '9000000003', prog: 'CSE', m10: 79.0, m12: 74.5, state: 'paid',  gender: 'Male',   cat: 'OBC-A',   city: 'Siliguri' },
  { name: 'Sneha Paul',    email: 'sneha.paul@demo.iem',    phone: '9000000004', prog: 'ECE', m10: 90.0, m12: 86.2, state: 'paid',  gender: 'Female', cat: 'General', city: 'Durgapur' },
  { name: 'Rohit Verma',   email: 'rohit.verma@demo.iem',   phone: '9000000005', prog: 'ECE', m10: 70.0, m12: 68.0, state: 'paid',  gender: 'Male',   cat: 'SC',      city: 'Patna' },
  { name: 'Tanvi Ghosh',   email: 'tanvi.ghosh@demo.iem',   phone: '9000000006', prog: 'ME',  m10: 84.0, m12: 89.5, state: 'paid',  gender: 'Female', cat: 'General', city: 'Kolkata' },
  { name: 'Arjun Singh',   email: 'arjun.singh@demo.iem',   phone: '9000000007', prog: 'ME',  m10: 76.5, m12: 72.0, state: 'paid',  gender: 'Male',   cat: 'EWS',     city: 'Ranchi' },
  { name: 'Meera Nair',    email: 'meera.nair@demo.iem',    phone: '9000000008', prog: 'CSE', m10: 81.0, m12: 83.0, state: 'draft', gender: 'Female', cat: 'General', city: 'Kolkata' },
  { name: 'Dev Sharma',    email: 'dev.sharma@demo.iem',    phone: '9000000009', prog: 'ECE', m10: 65.0, m12: 70.0, state: 'draft', gender: 'Male',   cat: 'OBC-B',   city: 'Asansol' },
  { name: 'Priya Banerjee',email: 'priya.banerjee@demo.iem',phone: '9000000010', prog: null,  state: 'none' }
];

module.exports = async function seedDemo(q) {
  const pw = hash(DEMO_PASSWORD);
  let created = 0;
  for (let i = 0; i < STUDENTS.length; i++) {
    const s = STUDENTS[i];
    let uid;
    const ex = await q('SELECT id FROM users WHERE email=$1', [s.email]);
    if (ex.rowCount) {
      uid = ex.rows[0].id;
      // already complete? (account-only students have no application by design)
      if (s.state === 'none' || (await q('SELECT 1 FROM applications WHERE user_id=$1', [uid])).rowCount) continue;
    } else {
      uid = (await q('INSERT INTO users(name,email,phone,password) VALUES ($1,$2,$3,$4) RETURNING id', [s.name, s.email, s.phone, pw])).rows[0].id;
    }
    created++;
    if (s.state === 'none') continue;

    const first = s.name.split(' ')[0].toLowerCase();
    const submitted = s.state === 'paid';
    const app = (await q(
      `INSERT INTO applications(user_id,status,payment_status,submitted_at,full_name,program_code,dob,gender,aadhaar,nationality,category,religion,blood_group,
         mobile,email,address1,city,state,pin,country,guardian_name,relation,guardian_mobile,occupation,income,
         board10,school10,year10,roll10,board12,school12,year12,roll12,entrance_rank,domicile,marks10,marks12)
       VALUES ($1,$2,$3,$4::timestamptz,$5,$6,$7,$8,$9,'Indian',$10,'Hindu','B+',
         $11,$12,$13,$14,'West Bengal',$15,'India',$16,'Father',$17,'Service','5 - 10 Lakh',
         'CBSE',$18,'2022',$19,'CBSE',$20,'2024',$21,$22,'West Bengal',$23,$24) RETURNING id, app_no`,
      [uid, submitted ? 'Submitted' : 'Draft', submitted ? 'Success' : 'Pending', submitted ? new Date(Date.now() - (200 - i * 10) * 3600 * 1000).toISOString() : null,
       s.name, s.prog, '2006-0' + ((i % 9) + 1) + '-1' + (i % 9), s.gender, '5000' + String(10000000 + i),
       s.cat, s.phone, s.email, (10 + i) + ', Demo Road', s.city, '7000' + String(10 + i), 'Mr. ' + first + ' Senior', '98300' + String(10000 + i),
       'Demo Public School', 'R10' + (1000 + i), 'Demo Senior Secondary', 'R12' + (1000 + i), 'JEE Main - ' + (20000 + i * 137), s.m10, s.m12]
    )).rows[0];

    if (!submitted) continue;
    // tiny placeholder files for the four mandatory documents
    for (const [type, file, mime] of [['tenth', 'class10.pdf', 'application/pdf'], ['twelfth', 'class12.pdf', 'application/pdf'], ['photo_id', 'aadhaar.pdf', 'application/pdf'], ['photograph', 'photo.jpg', 'image/jpeg']])
      await q('INSERT INTO documents(application_id,doc_type,filename,mime,size,data) VALUES ($1,$2,$3,$4,$5,$6)', [app.id, type, file, mime, 2048, 'demo']);
    const txn = 'TXNDEMO' + String(1000 + i);
    await q('INSERT INTO payments(application_id,txn_id,method,amount,status) VALUES ($1,$2,$3,$4,$5)', [app.id, txn, 'UPI', 91000, 'Success']);
    await q('INSERT INTO notifications(user_id,message) VALUES ($1,$2)', [uid, `Application ${app.app_no} submitted and payment of Rs. 91000 received (${txn}).`]);
  }
  // Make sure every demo account can log in with the demo password, even if it was created by an older version.
  const fixed = await q("UPDATE users SET password=$1, email_verified=TRUE, role='applicant' WHERE email LIKE '%@demo.iem'", [pw]);
  console.log('Demo accounts ready:', fixed.rowCount, '(password: ' + DEMO_PASSWORD + ')');
  return created;
};
module.exports.DEMO_PASSWORD = DEMO_PASSWORD;
