// FreeToolBuilder accounts API (Cloudflare Pages Functions + D1).
// Needs: a D1 binding named DB, and a secret ADMIN_KEY (Pages project > Settings).
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{"content-type":"application/json","cache-control":"no-store"}});
const enc=new TextEncoder();
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
async function hashPw(pw,salt){const k=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc.encode(salt),iterations:10000},k,256));}
function same(a,b){if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0;}
async function setup(db){await db.batch([
 db.prepare("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,name TEXT,salt TEXT,hash TEXT,pro_until INTEGER DEFAULT 0,created INTEGER,note TEXT)"),
 db.prepare("CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,created INTEGER)"),
 db.prepare("CREATE TABLE IF NOT EXISTS tries(k TEXT PRIMARY KEY,n INTEGER,t INTEGER)")]);}
const pub=u=>({email:u.email,name:u.name||"",proUntil:u.pro_until||0,pro:(u.pro_until||0)>Date.now()});
async function me(db,req){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");if(!/^[a-f0-9]{64}$/.test(t))return null;
 return db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?").bind(t).first();}
async function limited(db,key){const now=Date.now(),r=await db.prepare("SELECT n,t FROM tries WHERE k=?").bind(key).first();
 if(r&&now-r.t<15*60e3&&r.n>=10)return true;await db.prepare("INSERT INTO tries(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN ?-t>900000 THEN 1 ELSE n+1 END,t=CASE WHEN ?-t>900000 THEN ? ELSE t END").bind(key,now,now,now,now).run();return false;}
async function session(db,uid){const tok=rnd(32);await db.prepare("INSERT INTO sessions(token,user_id,created) VALUES(?,?,?)").bind(tok,uid,Date.now()).run();return tok;}
export async function onRequest({request:req,env,params}){
 const db=env.DB;if(!db)return J({error:"Accounts are not switched on yet."},503);
 const path=[].concat(params.path||[]).join("/"),m=req.method;let body={};if(m==="POST"){try{body=await req.json();}catch(e){return J({error:"Bad request"},400);}}
 try{await setup(db);
 if(path==="signup"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),pw=String(body.password||""),name=String(body.name||"").trim().slice(0,60);
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)||email.length>120)return J({error:"Please type a real email address."},400);
  if(pw.length<8||pw.length>200)return J({error:"Use a password of at least 8 characters."},400);
  if(await limited(db,"s:"+(req.headers.get("cf-connecting-ip")||"x")))return J({error:"Too many tries. Wait 15 minutes."},429);
  if(await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first())return J({error:"This email already has an account. Log in instead."},409);
  const salt=rnd(16),hash=await hashPw(pw,salt);const r=await db.prepare("INSERT INTO users(email,name,salt,hash,created) VALUES(?,?,?,?,?)").bind(email,name,salt,hash,Date.now()).run();
  const u=await db.prepare("SELECT * FROM users WHERE id=?").bind(r.meta.last_row_id).first();return J({token:await session(db,u.id),user:pub(u)});}
 if(path==="login"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),pw=String(body.password||"");
  if(await limited(db,"l:"+email))return J({error:"Too many tries. Wait 15 minutes."},429);
  const u=await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u||!same(await hashPw(pw,u.salt),u.hash))return J({error:"Email or password is not right."},401);
  return J({token:await session(db,u.id),user:pub(u)});}
 if(path==="me"){const u=await me(db,req);return u?J({user:pub(u)}):J({error:"Not signed in"},401);}
 if(path==="logout"&&m==="POST"){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");await db.prepare("DELETE FROM sessions WHERE token=?").bind(t).run();return J({ok:true});}
 if(path.startsWith("admin/")){const key=req.headers.get("x-admin-key")||"";if(!env.ADMIN_KEY||key.length<12||!same(key,env.ADMIN_KEY))return J({error:"Wrong admin key."},403);
  if(path==="admin/users"){const q=String(new URL(req.url).searchParams.get("q")||"").toLowerCase();const r=await db.prepare("SELECT email,name,pro_until,created,note FROM users WHERE email LIKE ? ORDER BY created DESC LIMIT 200").bind("%"+q+"%").all();return J({users:r.results});}
  if(path==="admin/grant"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),months=Math.max(-12,Math.min(24,parseInt(body.months,10)||0)),note=String(body.note||"").slice(0,200);
   const u=await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u)return J({error:"No account with that email."},404);
   const base=Math.max(Date.now(),u.pro_until||0),until=months<=0?0:base+months*30*864e5;await db.prepare("UPDATE users SET pro_until=?,note=? WHERE id=?").bind(until,note||u.note,u.id).run();return J({ok:true,email,proUntil:until});}
  if(path==="admin/reset"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),pw=String(body.password||"");if(pw.length<8)return J({error:"New password needs 8+ characters."},400);
   const salt=rnd(16),hash=await hashPw(pw,salt);const r=await db.prepare("UPDATE users SET salt=?,hash=? WHERE email=?").bind(salt,hash,email).run();
   const u=await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first();if(u)await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id).run();return J({ok:!!r.meta.changes});}}
 return J({error:"Not found"},404);}catch(e){return J({error:"Server error. Try again."},500);}}
