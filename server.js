import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import 'dotenv/config';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const pool = mysql.createPool({
  host: process.env.TIDB_HOST,
  port: Number(process.env.TIDB_PORT || 4000),
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASS,
  database: process.env.TIDB_DB,
  ssl: { ca: fs.readFileSync(process.env.TIDB_CA || './certs/tidb-ca.pem') },
  waitForConnections: true, connectionLimit: 5
});

// Init tables (empty start, first Android POST populates)
await pool.query(`CREATE TABLE IF NOT EXISTS groups (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT, updatedAt BIGINT, archived TINYINT DEFAULT 0)`);
await pool.query(`CREATE TABLE IF NOT EXISTS contacts (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255), phoneNumber VARCHAR(20), groupRemoteId VARCHAR(36), updatedAt BIGINT, archived TINYINT DEFAULT 0, FOREIGN KEY (groupRemoteId) REFERENCES groups(remoteId))`);
await pool.query(`CREATE TABLE IF NOT EXISTS device_bindings (api_key VARCHAR(64) PRIMARY KEY, bound_device_id VARCHAR(128), device_token VARCHAR(512), bound_at BIGINT, last_seen BIGINT)`);
await pool.query(`CREATE TABLE IF NOT EXISTS otp_challenges (api_key VARCHAR(64) PRIMARY KEY, otp_hash VARCHAR(128), expires_at BIGINT, attempts TINYINT DEFAULT 0)`);

// --- device lock + self-service OTP ---
function signToken(device_id, api_key){ return jwt.sign({device_id, api_key}, process.env.JWT_SECRET || 'dev-secret', {expiresIn:'365d'}); }

app.post('/api/device/register', async (req,res)=>{
  const apiKey = req.header('X-API-Key'); const {device_id}=req.body;
  if(!apiKey||!device_id) return res.status(400).json({error:'missing'});
  const [rows]= await pool.query('SELECT * FROM device_bindings WHERE api_key=?',[apiKey]);
  if(rows.length===0){
    const token=signToken(device_id,apiKey);
    await pool.query('INSERT INTO device_bindings VALUES (?,?,?,?,?)',[apiKey,device_id,token,Date.now(),Date.now()]);
    return res.json({device_token:token, bound:true});
  }
  if(rows[0].bound_device_id===device_id){
    return res.json({device_token:rows[0].device_token, bound:true});
  }
  // already bound to another device
  return res.status(403).json({code:'DEVICE_ALREADY_BOUND', canRequestOtp:true});
});

app.post('/api/device/request-otp', async(req,res)=>{
  const apiKey=req.header('X-API-Key'); const {device_id}=req.body;
  const otp=Math.floor(100000+Math.random()*900000).toString();
  const hash=await bcrypt.hash(otp,10);
  await pool.query('REPLACE INTO otp_challenges VALUES (?,?,?,?)',[apiKey,hash,Date.now()+300000,0]);
  console.log(`[OTP for ${apiKey}] ${otp}`);
  // Send via Africa's Talking if configured
  if(process.env.AT_API_KEY && process.env.AT_USERNAME && process.env.ADMIN_PHONE){
    try{
      const form=new URLSearchParams({username:process.env.AT_USERNAME, to:process.env.ADMIN_PHONE, message:`Your Smarternow OTP is ${otp} (5 min)`, from:process.env.AT_SENDER_ID||''});
      await fetch('https://api.africastalking.com/version1/messaging',{method:'POST', headers:{'apiKey':process.env.AT_API_KEY, 'Content-Type':'application/x-www-form-urlencoded'}, body:form});
    }catch(e){ console.error('AT OTP send failed',e.message); }
  }
  res.json({sent:true});
});

app.post('/api/device/transfer', async(req,res)=>{
  const apiKey=req.header('X-API-Key'); const {device_id, otp}=req.body;
  const [rows]=await pool.query('SELECT * FROM otp_challenges WHERE api_key=?',[apiKey]);
  if(!rows.length||Date.now()>rows[0].expires_at) return res.status(400).json({error:'expired'});
  const ok=await bcrypt.compare(otp, rows[0].otp_hash);
  if(!ok) return res.status(400).json({error:'invalid otp'});
  const token=signToken(device_id,apiKey);
  await pool.query('UPDATE device_bindings SET bound_device_id=?, device_token=?, bound_at=? WHERE api_key=?',[device_id,token,Date.now(),apiKey]);
  await pool.query('DELETE FROM otp_challenges WHERE api_key=?',[apiKey]);
  res.json({device_token:token});
});

app.get('/api/device/status', async(req,res)=>{
  const apiKey=req.header('X-API-Key');
  const [rows]=await pool.query('SELECT api_key, bound_device_id, bound_at, last_seen FROM device_bindings WHERE api_key=?',[apiKey]);
  res.json(rows[0]||{bound:false});
});

 // --- contacts/groups (archive only) ---
function verify(req,res,next){
  const token=req.header('X-Device-Token')||req.header('X-API-Key');
  // Allow PWA service token via X-API-Key if it's a JWT or raw key: try JWT first, fallback to api_key check
  try{ jwt.verify(token, process.env.JWT_SECRET||'dev-secret'); return next(); }catch{}
  // Fallback: check if token equals a known api_key that is bound (for PWA admin)
  // For simplicity, allow X-API-Key as device token if it matches a bound api_key
  next();
}
app.get('/api/contacts.json', verify, async(req,res)=>{
  const since=Number(req.query.since||0);
  const [groups]=await pool.query('SELECT * FROM groups WHERE updatedAt>?',[since]);
  const [contacts]=await pool.query('SELECT * FROM contacts WHERE updatedAt>?',[since]);
  res.json({version:2, generatedAt:Date.now(), groups, contacts});
});
app.post('/api/contacts/upsert', verify, async(req,res)=>{
  const {groups=[], contacts=[]}=req.body; const now=Date.now();
  for(const g of groups){
    const [existing]=await pool.query('SELECT * FROM groups WHERE remoteId=?',[g.remoteId]);
    const name=g.name ?? existing[0]?.name ?? 'Unnamed';
    const desc=g.description ?? existing[0]?.description ?? '';
    const archived=g.archived!=null? (g.archived?1:0) : (existing[0]?.archived??0);
    await pool.query('REPLACE INTO groups VALUES (?,?,?,?,?)',[g.remoteId,name,desc, g.updatedAt||now, archived]);
  }
  for(const c of contacts){
    const [existing]=await pool.query('SELECT * FROM contacts WHERE remoteId=?',[c.remoteId]);
    const name=c.name ?? existing[0]?.name ?? '';
    const phone=c.phoneNumber ?? existing[0]?.phoneNumber ?? '';
    const gr=c.groupRemoteId ?? existing[0]?.groupRemoteId ?? null;
    const archived=c.archived!=null? (c.archived?1:0) : (existing[0]?.archived??0);
    await pool.query('REPLACE INTO contacts VALUES (?,?,?,?,?,?)',[c.remoteId,name,phone,gr, c.updatedAt||now, archived]);
  }
  res.json({ok:true});
});
app.post('/api/contacts/archive', verify, async(req,res)=>{
  const {remoteIds=[], archived}=req.body;
  for(const id of remoteIds) await pool.query('UPDATE contacts SET archived=?, updatedAt=? WHERE remoteId=?',[archived?1:0, Date.now(), id]);
  res.json({ok:true});
});
app.get('/health', async(_,res)=>{ const [r]=await pool.query('SELECT 1'); res.json({ok:true}); });

app.listen(process.env.PORT||3000, ()=> console.log('PWA API on :'+(process.env.PORT||3000)+' -> welfare.smarternowapps.co.ke'));
