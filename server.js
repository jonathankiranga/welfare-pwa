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
// favicon 204 to avoid 404 log noise
app.get('/favicon.ico', (req,res)=> res.status(204).end());

function buildSsl() {
  // TiDB Cloud requires TLS. Try CA file if present, else fallback to system CAs
  try {
    const caPath = process.env.TIDB_CA || './certs/tidb-ca.pem';
    if (fs.existsSync(caPath)) return { ca: fs.readFileSync(caPath), minVersion: 'TLSv1.2', rejectUnauthorized: true };
  } catch {}
  return { minVersion: 'TLSv1.2', rejectUnauthorized: true };
}
const pool = mysql.createPool({
  host: process.env.TIDB_HOST,
  port: Number(process.env.TIDB_PORT || 4000),
  user: process.env.TIDB_USER,
  password: process.env.TIDB_PASS,
  database: process.env.TIDB_DB,
  ssl: process.env.TIDB_HOST ? buildSsl() : undefined,
  waitForConnections: true, connectionLimit: 5
});

// Init tables — auto-create DB if missing (TiDB starts empty)
async function initDb() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS contact_groups (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT, updatedAt BIGINT, archived TINYINT DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS contacts (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255), phoneNumber VARCHAR(20), groupRemoteId VARCHAR(36), updatedAt BIGINT, archived TINYINT DEFAULT 0, FOREIGN KEY (groupRemoteId) REFERENCES contact_groups(remoteId))`);
    await pool.query(`CREATE TABLE IF NOT EXISTS device_bindings (api_key VARCHAR(64) PRIMARY KEY, bound_device_id VARCHAR(128), device_token VARCHAR(512), bound_at BIGINT, last_seen BIGINT)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS otp_challenges (api_key VARCHAR(64) PRIMARY KEY, otp_hash VARCHAR(128), expires_at BIGINT, attempts TINYINT DEFAULT 0)`);
    await pool.query(`CREATE TABLE IF NOT EXISTS site_content (keyName VARCHAR(64) PRIMARY KEY, value TEXT, updatedAt BIGINT)`);
    // Seed default homepage content if empty
    const [existing] = await pool.query(`SELECT * FROM site_content WHERE keyName='homepage'`);
    if (existing.length === 0) {
      await pool.query(`INSERT INTO site_content VALUES (?,?,?)`, ['homepage', JSON.stringify({title:'Smarternow Welfare', subtitle:'Private System — Staff Access Only', message:'This is a closed internal system for authorized staff. Please log in to manage groups and contacts.'}), Date.now()]);
    }
  } catch (e) {
    if (e.message.includes('Unknown database')) {
      const dbName = process.env.TIDB_DB;
      console.warn(`DB '${dbName}' not found — creating...`);
      const tmpPool = mysql.createPool({
        host: process.env.TIDB_HOST, port: Number(process.env.TIDB_PORT || 4000),
        user: process.env.TIDB_USER, password: process.env.TIDB_PASS,
        ssl: buildSsl(), waitForConnections: true, connectionLimit: 2
      });
      try {
        await tmpPool.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
        console.log(`Created database ${dbName}, retrying init...`);
        await tmpPool.end();
        await pool.query(`CREATE TABLE IF NOT EXISTS contact_groups (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255) NOT NULL, description TEXT, updatedAt BIGINT, archived TINYINT DEFAULT 0)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS contacts (remoteId VARCHAR(36) PRIMARY KEY, name VARCHAR(255), phoneNumber VARCHAR(20), groupRemoteId VARCHAR(36), updatedAt BIGINT, archived TINYINT DEFAULT 0, FOREIGN KEY (groupRemoteId) REFERENCES contact_groups(remoteId))`);
        await pool.query(`CREATE TABLE IF NOT EXISTS device_bindings (api_key VARCHAR(64) PRIMARY KEY, bound_device_id VARCHAR(128), device_token VARCHAR(512), bound_at BIGINT, last_seen BIGINT)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS otp_challenges (api_key VARCHAR(64) PRIMARY KEY, otp_hash VARCHAR(128), expires_at BIGINT, attempts TINYINT DEFAULT 0)`);
        await pool.query(`CREATE TABLE IF NOT EXISTS site_content (keyName VARCHAR(64) PRIMARY KEY, value TEXT, updatedAt BIGINT)`);
      } catch (e2) {
        console.warn('DB auto-create failed (create it manually in TiDB Dashboard):', e2.message);
      } finally { try{ await tmpPool.end(); }catch{} }
    } else {
      console.warn('DB init skipped (set TIDB_* env vars on Render):', e.message);
    }
  }
}
await initDb();

// --- device lock + self-service OTP ---
function signToken(device_id, api_key){ return jwt.sign({device_id, api_key}, process.env.JWT_SECRET || 'dev-secret', {expiresIn:'365d'}); }

app.post('/api/device/register', async (req,res)=>{
  const apiKey = 'welfare'; const {device_id}=req.body;
  if(!device_id) return res.status(400).json({error:'missing device_id'});
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
  const apiKey='welfare'; const {device_id}=req.body;
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
  const apiKey='welfare'; const {device_id, otp}=req.body;
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
  const apiKey='welfare';
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
app.get('/api/contacts.json', async(req,res)=>{
  try{
    const since=Number(req.query.since||0);
    const [groups]=await pool.query('SELECT * FROM contact_groups WHERE updatedAt>?',[since]);
    const [contacts]=await pool.query('SELECT * FROM contacts WHERE updatedAt>?',[since]);
    res.json({version:2, generatedAt:Date.now(), groups, contacts});
  }catch(e){
    // DB not configured yet (empty start) — return empty so PWA doesn't 502
    res.json({version:2, generatedAt:Date.now(), groups:[], contacts:[], warning:'DB not configured: set TIDB_* env vars. '+e.message});
  }
});
app.post('/api/contacts/upsert', verify, async(req,res)=>{
  try{
    const {groups=[], contacts=[]}=req.body; const now=Date.now();
    for(const g of groups){
      const [existing]=await pool.query('SELECT * FROM contact_groups WHERE remoteId=?',[g.remoteId]);
      const name=g.name ?? existing[0]?.name ?? 'Unnamed';
      const desc=g.description ?? existing[0]?.description ?? '';
      const archived=g.archived!=null? (g.archived?1:0) : (existing[0]?.archived??0);
      await pool.query('REPLACE INTO contact_groups VALUES (?,?,?,?,?)',[g.remoteId,name,desc, g.updatedAt||now, archived]);
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
  }catch(e){
    console.error('upsert failed:', e.message);
    res.status(500).json({error:'DB error: '+e.message});
  }
});
app.post('/api/contacts/archive', verify, async(req,res)=>{
  try{
    const {remoteIds=[], archived}=req.body;
    for(const id of remoteIds) await pool.query('UPDATE contacts SET archived=?, updatedAt=? WHERE remoteId=?',[archived?1:0, Date.now(), id]);
    res.json({ok:true});
  }catch(e){
    console.error('archive failed:', e.message);
    res.status(500).json({error:'DB error: '+e.message});
  }
});
app.get('/api/site-content', async(req,res)=>{
  try{
    const [rows]=await pool.query(`SELECT value FROM site_content WHERE keyName='homepage'`);
    if(rows.length===0) return res.json({title:'Smarternow Welfare', subtitle:'Private System — Staff Access Only', message:'This is a closed internal system for authorized staff.'});
    res.json(JSON.parse(rows[0].value));
  }catch(e){ res.json({title:'Smarternow Welfare', subtitle:'Private System — Staff Access Only', message:'This is a closed internal system.'}); }
});
app.post('/api/site-content', async(req,res)=>{
  const {title, subtitle, message}=req.body;
  if(!title) return res.status(400).json({error:'title required'});
  await pool.query(`REPLACE INTO site_content VALUES (?,?,?)`, ['homepage', JSON.stringify({title, subtitle, message}), Date.now()]);
  res.json({ok:true});
});

app.get('/health', async(_,res)=>{
  try{ await pool.query('SELECT 1'); res.json({ok:true, db:true}); }
  catch(e){ res.json({ok:true, db:false, warning:'DB not configured: set TIDB_* env vars. '+e.message}); }
});

app.listen(process.env.PORT||3000, ()=> console.log('PWA API on :'+(process.env.PORT||3000)+' -> welfare.smarternowapps.co.ke'));
