const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.PORT || 3000);
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 }) : null;
const sessions = new Map();
const MIME = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json','.zip':'application/zip'};
function json(res, status, body) { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(JSON.stringify(body)); }
function parseCookies(header='') { return Object.fromEntries(header.split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2)); }
function currentUser(req) { const sid=parseCookies(req.headers.cookie).cnc_session; const s=sessions.get(sid); if(!s) return null; if(s.expires < Date.now()){sessions.delete(sid);return null;} return s.user; }
function hashPassword(password, salt=crypto.randomBytes(16).toString('hex')) { return salt+':'+crypto.scryptSync(password,salt,64).toString('hex'); }
function verifyPassword(password, stored) { if(!stored || !stored.includes(':')) return false; const [salt,digest]=stored.split(':'); const candidate=crypto.scryptSync(password,salt,64); const expected=Buffer.from(digest,'hex'); return candidate.length===expected.length && crypto.timingSafeEqual(candidate,expected); }
async function body(req) { let data=''; for await (const chunk of req){data+=chunk;if(data.length>32768)throw Error('Request too large');} return JSON.parse(data||'{}'); }
function safeOrigin(req){const origin=req.headers.origin;if(!origin)return true;try {return new URL(origin).host===req.headers.host;}catch{return false;}}
function serve(req,res,pathname) {
  const route=pathname==='/'?'/index.html':pathname==='/admin'||pathname==='/admin/'?'/admin/index.html':pathname;
  const target=path.resolve(ROOT,'.'+route);
  if(!target.startsWith(ROOT+path.sep))return json(res,403,{error:'Forbidden'});
  fs.stat(target,(err,stat)=>{
    if(err||!stat.isFile())return json(res,404,{error:'Not found'});
    res.writeHead(200,{'Content-Type':MIME[path.extname(target)]||'application/octet-stream','X-Content-Type-Options':'nosniff','Referrer-Policy':'strict-origin-when-cross-origin'});
    fs.createReadStream(target).pipe(res);
  });
}
async function main(){
  if(!pool) throw Error('DATABASE_URL must be configured');
  await pool.query('SELECT 1');
  await pool.query(fs.readFileSync(path.join(ROOT,'database/schema.sql'),'utf8'));
  http.createServer(async(req,res)=>{
    try {
      const url=new URL(req.url,'http://localhost');
      const pathname=decodeURIComponent(url.pathname);
      if(pathname==='/api/health')return json(res,200,{ok:true,database:'connected'});
      if(pathname.startsWith('/api/')){
        if(req.method==='POST'&&!safeOrigin(req))return json(res,403,{error:'Origin rejected'});
        if(pathname==='/api/auth/setup'&&req.method==='POST'){
          const {email,password,setupToken}=await body(req);
          const expected=process.env.ADMIN_SETUP_TOKEN;
          if(!expected||!setupToken||!crypto.timingSafeEqual(Buffer.from(crypto.createHash('sha256').update(String(setupToken)).digest()),Buffer.from(crypto.createHash('sha256').update(expected).digest())))return json(res,403,{error:'Invalid setup token'});
          if(String(email).toLowerCase()!==String(process.env.ADMIN_EMAIL||'mknur00@gmail.com').toLowerCase()||typeof password!=='string'||password.length<12)return json(res,400,{error:'Use the administrator email and a password of at least 12 characters'});
          const existing=await pool.query("SELECT id FROM staff_users WHERE role='super_admin' AND is_active=true LIMIT 1");
          if(existing.rowCount)return json(res,409,{error:'Administrator already configured'});
          await pool.query("INSERT INTO staff_users(email,role,password_hash,is_active) VALUES($1,'super_admin',$2,true) ON CONFLICT DO NOTHING",[email.toLowerCase(),hashPassword(password)]);
          return json(res,201,{ok:true});
        }
        if(pathname==='/api/auth/login'&&req.method==='POST'){
          const {email,password}=await body(req);
          const found=await pool.query('SELECT id,email,role,password_hash FROM staff_users WHERE lower(email)=lower($1) AND is_active=true',[String(email||'')]);
          if(!found.rowCount||typeof password!=='string'||!verifyPassword(password,found.rows[0].password_hash))return json(res,401,{error:'Invalid login'});
          const user={id:found.rows[0].id,email:found.rows[0].email,role:found.rows[0].role};
          const sid=crypto.randomBytes(32).toString('hex');
          sessions.set(sid,{user,expires:Date.now()+8*60*60*1000});
          res.setHeader('Set-Cookie','cnc_session='+sid+'; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800');
          return json(res,200,{user});
        }
        if(pathname==='/api/auth/me'&&req.method==='GET'){const user=currentUser(req);return user?json(res,200,{user}):json(res,401,{error:'Not signed in'});}
        if(pathname==='/api/auth/logout'&&req.method==='POST'){const sid=parseCookies(req.headers.cookie).cnc_session;sessions.delete(sid);res.setHeader('Set-Cookie','cnc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true});}
        const user=currentUser(req);
        if(!user)return json(res,401,{error:'Not signed in'});
        if(pathname==='/api/customers'&&req.method==='GET'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const q=String(url.searchParams.get('q')||'').trim().slice(0,100);
          const result=await pool.query("SELECT id,name,company_name,email,phone,customer_type,city,postcode,created_at FROM customers WHERE ($1 = '' OR name ILIKE '%'||$1||'%' OR coalesce(company_name,'') ILIKE '%'||$1||'%' OR coalesce(email,'') ILIKE '%'||$1||'%' OR coalesce(phone,'') ILIKE '%'||$1||'%') ORDER BY created_at DESC LIMIT 100",[q]);
          return json(res,200,{customers:result.rows});
        }
        if(pathname==='/api/customers'&&req.method==='POST'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req);
          if(typeof data.name!=='string'||!data.name.trim()||data.name.length>200)return json(res,400,{error:'Customer name is required (maximum 200 characters)'});
          const fields=['company_name','email','phone','address_line1','address_line2','city','postcode','notes'];
          const values=fields.map(k=>data[k]==null?null:String(data[k]).trim().slice(0,k==='notes'?2000:255));
          const type=data.customer_type==='trade'?'trade':'individual';
          const result=await pool.query('INSERT INTO customers (name,customer_type,company_name,email,phone,address_line1,address_line2,city,postcode,notes,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,name,created_at',[data.name.trim(),type,...values,user.id]);
          await pool.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES ($1,'customer',$2,'create')",[user.id,result.rows[0].id]);
          return json(res,201,{customer:result.rows[0]});
        }
        if(pathname==='/api/quotes'&&req.method==='GET'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const result=await pool.query("SELECT q.id,q.quote_number,q.status,q.total_pence,q.created_at,c.name AS customer_name,c.company_name FROM quotes q JOIN customers c ON c.id=q.customer_id ORDER BY q.created_at DESC LIMIT 100");
          return json(res,200,{quotes:result.rows});
        }
        if(pathname==='/api/quotes'&&req.method==='POST'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req);
          if(!Array.isArray(data.items)||data.items.length<1||data.items.length>100)return json(res,400,{error:'Include between 1 and 100 quote items'});
          if(typeof data.customer_id!=='string'||!(/^[0-9a-f-]{36}$/i.test(data.customer_id)))return json(res,400,{error:'Select a customer'});
          const items=[];
          for(const item of data.items){
            const description=String(item.description||'').trim().slice(0,500);
            const quantity=Number(item.quantity);
            const unitPrice=Number(item.unit_price_pence);
            if(!description||!Number.isFinite(quantity)||quantity<=0||quantity>100000||!Number.isSafeInteger(unitPrice)||unitPrice<0||unitPrice>100000000)return json(res,400,{error:'Invalid quote item'});
            const lineTotal=Math.round(quantity*unitPrice);
            if(!Number.isSafeInteger(lineTotal))return json(res,400,{error:'Quote amount too large'});
            items.push({description,quantity,unitPrice,lineTotal,unit:String(item.unit||'each').slice(0,30)});
          }
          const subtotal=items.reduce((sum,item)=>sum+item.lineTotal,0);
          const discount=Number(data.discount_pence||0);
          const vat=Number(data.vat_pence||0);
          if(!Number.isSafeInteger(subtotal)||!Number.isSafeInteger(discount)||discount<0||discount>subtotal||!Number.isSafeInteger(vat)||vat<0)return json(res,400,{error:'Invalid quote totals'});
          const client=await pool.connect();
          try{
            await client.query('BEGIN');
            const customer=await client.query('SELECT id FROM customers WHERE id=$1',[data.customer_id]);
            if(!customer.rowCount){await client.query('ROLLBACK');return json(res,404,{error:'Customer not found'});}
            const result=await client.query("INSERT INTO quotes(customer_id,subtotal_pence,discount_pence,vat_pence,total_pence,customer_notes,created_by,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7,$7) RETURNING id,quote_number,status,total_pence",[data.customer_id,subtotal,discount,vat,subtotal-discount+vat,String(data.customer_notes||'').slice(0,2000),user.id]);
            for(let i=0;i<items.length;i++){const item=items[i];await client.query('INSERT INTO quote_items(quote_id,sort_order,description,quantity,unit,unit_price_pence,line_total_pence) VALUES($1,$2,$3,$4,$5,$6,$7)',[result.rows[0].id,i,item.description,item.quantity,item.unit,item.unitPrice,item.lineTotal]);}
            await client.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'quote',$2,'create')",[user.id,result.rows[0].id]);
            await client.query('COMMIT');
            return json(res,201,{quote:result.rows[0]});
          }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
        }
        if(pathname==='/api/dashboard'&&req.method==='GET'){
          const [customers,quotes,jobs]=await Promise.all([pool.query('SELECT count(*)::int AS total FROM customers'),pool.query('SELECT count(*)::int AS total FROM quotes'),pool.query('SELECT count(*)::int AS total FROM jobs')]);
          return json(res,200,{customers:customers.rows[0].total,quotes:quotes.rows[0].total,jobs:jobs.rows[0].total,user});
        }
        return json(res,404,{error:'API route not found'});
      }
      if(req.method!=='GET'&&req.method!=='HEAD')return json(res,405,{error:'Method not allowed'});
      return serve(req,res,pathname);
    } catch(e){console.error(e);return json(res,500,{error:'Server error'});}
  }).listen(PORT,'0.0.0.0',()=>console.log('CNC ONLINE listening on '+PORT));
}
main().catch(e=>{console.error(e);process.exit(1)});
