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
// The site owner: Pro for life, and the only person who can open the stats page.
const OWNERS=["afaqali1388@gmail.com"];const isOwner=u=>!!u&&OWNERS.indexOf(String(u.email||"").toLowerCase())>=0;const LIFE=4102444800000;
const pub=u=>{const o=isOwner(u),pu=o?LIFE:(u.pro_until||0);return {email:u.email,name:u.name||"",proUntil:pu,pro:pu>Date.now(),owner:o};};
async function setup2(db){await db.batch([
 db.prepare("CREATE TABLE IF NOT EXISTS ev(t INTEGER,vid TEXT,sid TEXT,uid INTEGER,k TEXT,tool TEXT,n INTEGER,msg TEXT,country TEXT,ref TEXT)"),
 db.prepare("CREATE INDEX IF NOT EXISTS ev_t ON ev(t)"),
 db.prepare("CREATE TABLE IF NOT EXISTS pres(sid TEXT PRIMARY KEY,t INTEGER,uid INTEGER,tool TEXT,page TEXT,country TEXT)"),
 db.prepare("CREATE TABLE IF NOT EXISTS fb(id INTEGER PRIMARY KEY AUTOINCREMENT,t INTEGER,tool TEXT,up INTEGER,text TEXT,uid INTEGER,country TEXT,ref TEXT,vid TEXT)")]);
 for(const c of ["ref TEXT","country TEXT"])try{await db.prepare("ALTER TABLE users ADD COLUMN "+c).run();}catch(e){}}
const S=(v,n)=>String(v==null?"":v).replace(/[\u0000-\u001f]/g," ").slice(0,n);
const KINDS=["view","open","start","done","dl","err","time","ping"];
async function me(db,req){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");if(!/^[a-f0-9]{64}$/.test(t))return null;
 return db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.created>?").bind(t,Date.now()-60*864e5).first();}
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
  try{await setup2(db);await db.prepare("UPDATE users SET ref=?,country=? WHERE id=?").bind(S(body.ref,80),S(req.cf&&req.cf.country||req.headers.get("cf-ipcountry"),4),r.meta.last_row_id).run();}catch(e){}
  const u=await db.prepare("SELECT * FROM users WHERE id=?").bind(r.meta.last_row_id).first();return J({token:await session(db,u.id),user:pub(u)});}
 if(path==="login"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),pw=String(body.password||"");
  if(await limited(db,"l:"+email))return J({error:"Too many tries. Wait 15 minutes."},429);
  const u=await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u||!same(await hashPw(pw,u.salt),u.hash))return J({error:"Email or password is not right."},401);
  return J({token:await session(db,u.id),user:pub(u)});}
 if(path==="me"){const u=await me(db,req);return u?J({user:pub(u)}):J({error:"Not signed in"},401);}
 if(path==="logout"&&m==="POST"){const t=(req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"");await db.prepare("DELETE FROM sessions WHERE token=?").bind(t).run();return J({ok:true});}
 if(path==="ev"&&m==="POST"){await setup2(db);const k=S(body.k,8);if(KINDS.indexOf(k)<0)return J({error:"Bad kind"},400);
  const now=Date.now(),sid=S(body.sid,24),vid=S(body.vid,24),tool=S(body.tool,40),cc=S(req.cf&&req.cf.country||req.headers.get("cf-ipcountry"),4);if(!/^[a-z0-9]{8,24}$/.test(sid))return J({error:"Bad id"},400);
  const u=req.headers.get("authorization")?await me(db,req):null,uid=u?u.id:null;
  await db.prepare("INSERT INTO pres(sid,t,uid,tool,page,country) VALUES(?,?,?,?,?,?) ON CONFLICT(sid) DO UPDATE SET t=excluded.t,uid=excluded.uid,tool=excluded.tool,page=excluded.page,country=excluded.country").bind(sid,now,uid,tool,S(body.page,40),cc).run();
  if(k!=="ping")await db.prepare("INSERT INTO ev(t,vid,sid,uid,k,tool,n,msg,country,ref) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(now,vid,sid,uid,k,tool,Math.max(0,Math.min(36e5,parseInt(body.n,10)||0)),S(body.msg,160),cc,S(body.ref,80)).run();
  if(Math.random()<0.01)await db.batch([db.prepare("DELETE FROM ev WHERE t<?").bind(now-120*864e5),db.prepare("DELETE FROM pres WHERE t<?").bind(now-864e5)]);
  return J({ok:true});}
 if(path==="fb"&&m==="POST"){await setup2(db);const tool=S(body.tool,40),text=S(body.text,600).trim();if(!tool)return J({error:"Bad request"},400);
  if(await limited(db,"f:"+(req.headers.get("cf-connecting-ip")||"x")))return J({error:"Too many tries. Wait 15 minutes."},429);
  const u=req.headers.get("authorization")?await me(db,req):null;
  await db.prepare("INSERT INTO fb(t,tool,up,text,uid,country,ref,vid) VALUES(?,?,?,?,?,?,?,?)").bind(Date.now(),tool,body.up?1:0,text,u?u.id:null,S(req.cf&&req.cf.country||req.headers.get("cf-ipcountry"),4),S(body.ref,80),S(body.vid,24)).run();
  return J({ok:true});}
 if(path==="stats"){const u=await me(db,req);if(!isOwner(u))return J({error:"Only the site owner can see this page. Log in with the owner email."},403);await setup2(db);
  const now=Date.now(),on=now-150e3,hr=now-36e5,wk=now-7*864e5,mo=now-30*864e5,q=(sql,...a)=>db.prepare(sql).bind(...a);
  const r=await db.batch([
   q("SELECT COUNT(*) n,SUM(uid IS NOT NULL) signed,SUM(tool<>'') busy FROM pres WHERE t>?",on),
   q("SELECT tool k,COUNT(*) n FROM pres WHERE t>? AND tool<>'' GROUP BY tool ORDER BY n DESC LIMIT 15",on),
   q("SELECT page k,COUNT(*) n FROM pres WHERE t>? GROUP BY page ORDER BY n DESC LIMIT 15",on),
   q("SELECT country k,COUNT(*) n FROM pres WHERE t>? GROUP BY country ORDER BY n DESC LIMIT 15",on),
   q("SELECT COUNT(*) n FROM pres WHERE t>?",hr),
   q("SELECT COUNT(*) n FROM users"),
   q("SELECT COUNT(*) n FROM ev WHERE k='open'"),
   q("SELECT SUM(n) s,COUNT(DISTINCT sid) v FROM ev WHERE k='time' AND t>?",mo),
   q("SELECT COUNT(*) n FROM fb"),
   q("SELECT COUNT(DISTINCT vid) n FROM ev WHERE t>?",wk),
   q("SELECT COUNT(*) n FROM users WHERE created>?",wk),
   q("SELECT COUNT(DISTINCT CASE WHEN k='dl' THEN sid END) d,COUNT(DISTINCT CASE WHEN k='open' THEN sid END) o FROM ev WHERE t>?",wk),
   q("SELECT COUNT(DISTINCT vid) n FROM ev WHERE t>? AND k='view' AND n=0",wk),
   q("SELECT tool,SUM(k='open') opened,SUM(k='start') started,SUM(k='done') finished,SUM(k='dl') dls,SUM(k='err') failed FROM ev WHERE t>? AND tool<>'' GROUP BY tool ORDER BY opened DESC LIMIT 200",mo),
   q("SELECT tool,SUM(up=1) up,SUM(up=0) down FROM fb GROUP BY tool"),
   q("SELECT f.t,f.up,f.tool,f.text,f.country,f.ref,u.name,u.email,u.created joined FROM fb f LEFT JOIN users u ON u.id=f.uid ORDER BY f.t DESC LIMIT 500"),
   q("SELECT tool,msg,COUNT(*) n,MAX(t) last FROM ev WHERE k='err' AND t>? GROUP BY tool,msg ORDER BY n DESC LIMIT 50",mo),
   q("SELECT COALESCE(NULLIF(ref,''),'direct') k,COUNT(*) n FROM users GROUP BY 1 ORDER BY n DESC LIMIT 15"),
   q("SELECT tool k,COUNT(*) n FROM ev WHERE k='open' AND t>? AND tool<>'' GROUP BY tool ORDER BY n DESC LIMIT 15",mo),
   q("SELECT COALESCE(NULLIF(country,''),'??') k,COUNT(DISTINCT vid) n FROM ev WHERE t>? GROUP BY 1 ORDER BY n DESC LIMIT 15",mo)]);
  const R=i=>r[i].results||[],F=i=>R(i)[0]||{};
  return J({now,online:{n:F(0).n||0,signed:F(0).signed||0,using:F(0).busy||0,hour:F(4).n||0,tools:R(1),pages:R(2),countries:R(3)},
   totals:{users:F(5).n||0,opens:F(6).n||0,avgMs:F(7).v?Math.round(F(7).s/F(7).v):0,comments:F(8).n||0},
   week:{visitors:F(9).n||0,signups:F(10).n||0,dlRate:F(11).o?F(11).d/F(11).o:0,returnRate:F(9).n?F(12).n/F(9).n:0},
   tools:R(13),votes:R(14),comments:R(15),errors:R(16),sources:R(17),top:R(18),countries:R(19)});}
 if(path.startsWith("admin/")){const key=req.headers.get("x-admin-key")||"";if(!isOwner(await me(db,req))){if(!(env.ADMIN_KEY&&same(key,env.ADMIN_KEY))&&await limited(db,"a:"+(req.headers.get("cf-connecting-ip")||"x")))return J({error:"Too many tries. Wait 15 minutes."},429);if(!env.ADMIN_KEY||key.length<12||!same(key,env.ADMIN_KEY))return J({error:"Wrong admin key."},403);}
  if(path==="admin/users"){const q=String(new URL(req.url).searchParams.get("q")||"").toLowerCase();const r=await db.prepare("SELECT email,name,pro_until,created,note FROM users WHERE email LIKE ? ORDER BY created DESC LIMIT 200").bind("%"+q+"%").all();return J({users:r.results});}
  if(path==="admin/grant"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),months=Math.max(-12,Math.min(24,parseInt(body.months,10)||0)),note=String(body.note||"").slice(0,200);
   const u=await db.prepare("SELECT * FROM users WHERE email=?").bind(email).first();if(!u)return J({error:"No account with that email."},404);
   const base=Math.max(Date.now(),u.pro_until||0),until=months<=0?0:base+months*30*864e5;await db.prepare("UPDATE users SET pro_until=?,note=? WHERE id=?").bind(until,note||u.note,u.id).run();return J({ok:true,email,proUntil:until});}
  if(path==="admin/reset"&&m==="POST"){const email=String(body.email||"").trim().toLowerCase(),pw=String(body.password||"");if(pw.length<8)return J({error:"New password needs 8+ characters."},400);
   const salt=rnd(16),hash=await hashPw(pw,salt);const r=await db.prepare("UPDATE users SET salt=?,hash=? WHERE email=?").bind(salt,hash,email).run();
   const u=await db.prepare("SELECT id FROM users WHERE email=?").bind(email).first();if(u)await db.prepare("DELETE FROM sessions WHERE user_id=?").bind(u.id).run();return J({ok:!!r.meta.changes});}}
 return J({error:"Not found"},404);}catch(e){console.error("api",path,e&&e.message);return J({error:"Server error. Try again."},500);}}
