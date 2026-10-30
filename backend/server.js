const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Pool } = require('pg');
const { nestParts } = require('./nesting');
const ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.PORT || 3000);
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, max: 5 }) : null;
const sessions = new Map();
const enquiryLimits = new Map();
const MIME = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json','.zip':'application/zip'};
function json(res, status, body) { res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(JSON.stringify(body)); }
function parseCookies(header='') { return Object.fromEntries(header.split(';').map(x=>x.trim().split('=').map(decodeURIComponent)).filter(x=>x.length===2)); }
function currentUser(req) { const sid=parseCookies(req.headers.cookie).cnc_session; const s=sessions.get(sid); if(!s) return null; if(s.expires < Date.now()){sessions.delete(sid);return null;} return s.user; }
function hashPassword(password, salt=crypto.randomBytes(16).toString('hex')) { return salt+':'+crypto.scryptSync(password,salt,64).toString('hex'); }
function verifyPassword(password, stored) { if(!stored || !stored.includes(':')) return false; const [salt,digest]=stored.split(':'); const candidate=crypto.scryptSync(password,salt,64); const expected=Buffer.from(digest,'hex'); return candidate.length===expected.length && crypto.timingSafeEqual(candidate,expected); }
async function body(req,limit=32768) { let data=''; for await (const chunk of req){data+=chunk;if(data.length>limit)throw Error('Request too large');} return JSON.parse(data||'{}'); }
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
        if(pathname==='/api/public/cutlists'&&req.method==='POST'){
          const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
          const now=Date.now(),key=crypto.createHash('sha256').update(ip).digest('hex');
          const limit=enquiryLimits.get(key)||{count:0,until:now+3600000};
          if(limit.until<now){limit.count=0;limit.until=now+3600000;}
          if(limit.count>=5)return json(res,429,{error:'Too many submissions. Please try later.'});
          limit.count++;enquiryLimits.set(key,limit);
          const data=await body(req,7500000);
          if(data.website)return json(res,200,{ok:true});
          const name=String(data.name||'').trim(),email=String(data.email||'').trim(),phone=String(data.phone||'').trim();
          if(name.length<2||name.length>200||email.length>255||phone.length>60||(!email&&!phone)||(email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))return json(res,400,{error:'Provide your name and a valid email or phone number.'});
          if(!Array.isArray(data.panels)||!data.panels.length||data.panels.length>100)return json(res,400,{error:'Add between 1 and 100 panel lines.'});
          const parts=[];
          for(const p of data.panels){
            const length=Number(p.length),width=Number(p.width),quantity=Number(p.quantity),thickness=Number(p.thickness);
            const material=String(p.material||'').trim().slice(0,200),part=String(p.part||'Panel').trim().slice(0,120);
            if(!material||!part||![length,width,quantity,thickness].every(Number.isFinite)||!Number.isInteger(length)||!Number.isInteger(width)||!Number.isInteger(quantity)||length<1||width<1||length>10000||width>10000||quantity<1||quantity>10000||thickness<=0||thickness>100)return json(res,400,{error:'Invalid panel dimensions or thickness.'});
            const isMdfPly=/mdf|plywood/i.test(material),fire=/fire\s*rated\s*mdf/i.test(material),sign=/foamex|aluminium composite/i.test(material);
            const valid=/foamex/i.test(material)?[3,5,10]:/aluminium composite/i.test(material)?[3,4]:fire?[12,18]:isMdfPly?[6,9,12,18]:[18];
            if(!valid.includes(thickness))return json(res,400,{error:'Thickness not available for '+material});
            if(sign&&(p.l1||p.l2||p.w1||p.w2||['edge','both'].includes(p.service)))return json(res,400,{error:'Sign materials cannot have edgebanding.'});
            parts.push({part,material,length,width,quantity,thickness,finish:String(p.finish||'').slice(0,120),service:String(p.service||'').slice(0,40),edgeType:String(p.edgeType||'').slice(0,60),l1:p.l1===true,l2:p.l2===true,w1:p.w1===true,w2:p.w2===true});
          }
          const attachments=[];let totalBytes=0;
          if(data.files!==undefined){if(!Array.isArray(data.files)||data.files.length>5)return json(res,400,{error:'Attach no more than 5 files.'});for(const file of data.files){const name=String(file.name||'').slice(0,200);if(!/\.(csv|txt|pdf|png|jpe?g|webp|dxf|dwg|svg|xlsx?|ods|zip)$/i.test(name)||typeof file.base64!=='string'||file.base64.length>7000000||!/^[A-Za-z0-9+/]*={0,2}$/.test(file.base64))return json(res,400,{error:'Unsupported attachment: '+name});const bytes=Buffer.from(file.base64,'base64');totalBytes+=bytes.length;if(!bytes.length||bytes.length>5242880||totalBytes>5242880)return json(res,400,{error:'Attachments must total 5 MB or less.'});attachments.push({name,bytes,mime:String(file.type||'application/octet-stream').slice(0,100)});}}
          const client=await pool.connect();
          try{
            await client.query('BEGIN');
            const customer=await client.query('INSERT INTO customers(name,email,phone,customer_type,company_name,postcode) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[name,email,phone,data.customer_type==='trade'?'trade':'individual',String(data.company_name||'').slice(0,200),String(data.postcode||'').slice(0,30)]);
            const quote=await client.query("INSERT INTO quotes(customer_id,customer_notes,internal_notes) VALUES($1,$2,'Online cut-list submission — prices awaiting review') RETURNING id,quote_number",[customer.rows[0].id,String(data.notes||'').slice(0,2000)]);
            for(let i=0;i<parts.length;i++){
              const p=parts[i],description=p.part+' — '+p.material+(p.finish?' ('+p.finish+')':'')+' — '+p.thickness+'mm — '+p.length+' × '+p.width+'mm — '+p.service;
              await client.query('INSERT INTO quote_items(quote_id,sort_order,description,quantity,unit,unit_price_pence,line_total_pence,specifications) VALUES($1,$2,$3,$4,$5,0,0,$6::jsonb)',[quote.rows[0].id,i,description,p.quantity,'panel',JSON.stringify(p)]);
            }
            for(const file of attachments)await client.query('INSERT INTO enquiry_uploads(quote_id,original_filename,mime_type,byte_size,file_data) VALUES($1,$2,$3,$4,$5)',[quote.rows[0].id,file.name,file.mime,file.bytes.length,file.bytes]);
            await client.query("INSERT INTO audit_log(entity_type,entity_id,action) VALUES('quote',$1,'public_cutlist')",[quote.rows[0].id]);
            await client.query('COMMIT');
            return json(res,201,{ok:true,reference:String(quote.rows[0].quote_number)});
          }catch(err){await client.query('ROLLBACK');throw err;}finally{client.release();}
        }
        if(pathname==='/api/public/enquiries'&&req.method==='POST'){
          const ip=String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
          const now=Date.now(), key=crypto.createHash('sha256').update(ip).digest('hex');
          const record=enquiryLimits.get(key)||{count:0,until:now+3600000};
          if(record.until<now){record.count=0;record.until=now+3600000;}
          if(record.count>=5)return json(res,429,{error:'Too many enquiries. Please try again later.'});
          record.count++;enquiryLimits.set(key,record);
          if(enquiryLimits.size>2000)for(const [k,v] of enquiryLimits){if(v.until<now)enquiryLimits.delete(k);}
          const data=await body(req,7200000);
          if(data.website)return json(res,200,{ok:true});
          const name=String(data.name||'').trim(),email=String(data.email||'').trim(),phone=String(data.phone||'').trim(),requirements=String(data.requirements||'').trim();
          if(name.length<2||name.length>200||requirements.length<10||requirements.length>2000||email.length>255||phone.length>60||(!email&&!phone)||email&& !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json(res,400,{error:'Enter your name, contact details and cutting requirements.'});
          let upload=null;
          if(data.file){
            const name=String(data.file.name||'').slice(0,200);
            const allowed=/\.(csv|txt|pdf|png|jpe?g|webp|dxf|dwg|svg|xlsx?|ods|zip)$/i;
            if(!allowed.test(name)||typeof data.file.base64!=='string'||data.file.base64.length>7000000||!/^[A-Za-z0-9+/]*={0,2}$/.test(data.file.base64))return json(res,400,{error:'Unsupported file. Upload CSV, Excel, PDF, image, DXF, DWG, SVG or ZIP up to 5 MB.'});
            const bytes=Buffer.from(data.file.base64,'base64');
            if(bytes.length<1||bytes.length>5242880)return json(res,400,{error:'File must be 5 MB or smaller.'});
            upload={name,bytes,mime:String(data.file.type||'application/octet-stream').slice(0,100)};
          }
          const client=await pool.connect();
          try{
            await client.query('BEGIN');
            const customer=await client.query('INSERT INTO customers(name,customer_type,company_name,email,phone,postcode) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[name,data.customer_type==='trade'?'trade':'individual',String(data.company_name||'').slice(0,200),email,phone,String(data.postcode||'').slice(0,30)]);
            const quote=await client.query("INSERT INTO quotes(customer_id,customer_notes,internal_notes) VALUES($1,$2,'Public website enquiry — pricing not reviewed') RETURNING id,quote_number",[customer.rows[0].id,requirements]);
            await client.query("INSERT INTO quote_items(quote_id,description,quantity,unit,unit_price_pence,line_total_pence) VALUES($1,'Customer enquiry — pricing pending',1,'job',0,0)",[quote.rows[0].id]);
            await client.query("INSERT INTO audit_log(entity_type,entity_id,action) VALUES('quote',$1,'public_enquiry')",[quote.rows[0].id]);
            if(upload)await client.query('INSERT INTO enquiry_uploads(quote_id,original_filename,mime_type,byte_size,file_data) VALUES($1,$2,$3,$4,$5)',[quote.rows[0].id,upload.name,upload.mime,upload.bytes.length,upload.bytes]);
            await client.query('COMMIT');
            return json(res,201,{ok:true,reference:String(quote.rows[0].quote_number)});
          }catch(err){await client.query('ROLLBACK');throw err;}finally{client.release();}
        }
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
        const uploadMatch=pathname.match(/^\/api\/quotes\/([0-9a-f-]{36})\/uploads\/([0-9a-f-]{36})$/i);
        if(uploadMatch&&req.method==='GET'){
          if(!['super_admin','manager','sales','workshop'].includes(user.role))return json(res,403,{error:'Access denied'});
          const result=await pool.query('SELECT original_filename,file_data FROM enquiry_uploads WHERE quote_id=$1 AND id=$2',[uploadMatch[1],uploadMatch[2]]);
          if(!result.rowCount)return json(res,404,{error:'File not found'});
          const row=result.rows[0];res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':"attachment; filename*=UTF-8''"+encodeURIComponent(row.original_filename),'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'});return res.end(row.file_data);
        }
        const uploadsMatch=pathname.match(/^\/api\/quotes\/([0-9a-f-]{36})\/uploads$/i);
        if(uploadsMatch&&req.method==='GET'){
          if(!['super_admin','manager','sales','workshop'].includes(user.role))return json(res,403,{error:'Access denied'});
          const result=await pool.query('SELECT id,original_filename,byte_size,created_at FROM enquiry_uploads WHERE quote_id=$1 ORDER BY created_at',[uploadsMatch[1]]);
          return json(res,200,{uploads:result.rows});
        }
        if(pathname==='/api/quotes'&&req.method==='GET'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const result=await pool.query("SELECT q.id,q.quote_number,q.status,q.total_pence,q.created_at,c.name AS customer_name,c.company_name,CASE WHEN q.internal_notes LIKE 'Online cut-list submission%' THEN 'Online cut list' WHEN q.internal_notes LIKE 'Website enquiry%' OR q.internal_notes LIKE 'Online enquiry%' THEN 'Website enquiry' ELSE 'Manual / other' END AS source FROM quotes q JOIN customers c ON c.id=q.customer_id ORDER BY q.created_at DESC LIMIT 100");
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
        const quoteMatch=pathname.match(/^\/api\/quotes\/([0-9a-f-]{36})$/i);
        if(quoteMatch&&req.method==='GET'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const q=await pool.query('SELECT q.*,c.name AS customer_name,c.company_name,c.email AS customer_email,c.phone AS customer_phone,c.address_line1,c.address_line2,c.city,c.postcode FROM quotes q JOIN customers c ON c.id=q.customer_id WHERE q.id=$1',[quoteMatch[1]]);
          if(!q.rowCount)return json(res,404,{error:'Quotation not found'});
          const items=await pool.query('SELECT id,description,quantity,unit,unit_price_pence,line_total_pence,sort_order FROM quote_items WHERE quote_id=$1 ORDER BY sort_order',[quoteMatch[1]]);
          return json(res,200,{quote:q.rows[0],items:items.rows});
        }
        if(quoteMatch&&req.method==='PUT'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req);
          const statuses=['draft','sent','accepted','declined','expired','converted'];
          if(!statuses.includes(data.status))return json(res,400,{error:'Invalid quotation status'});
          if(!Array.isArray(data.items)||!data.items.length||data.items.length>100)return json(res,400,{error:'Include 1–100 items'});
          const items=[];
          for(const x of data.items){
            const description=String(x.description||'').trim().slice(0,500),quantity=Number(x.quantity),unitPrice=Number(x.unit_price_pence);
            if(!description||!Number.isFinite(quantity)||quantity<=0||quantity>100000||!Number.isSafeInteger(unitPrice)||unitPrice<0||unitPrice>100000000)return json(res,400,{error:'Invalid item'});
            const total=Math.round(quantity*unitPrice);
            if(!Number.isSafeInteger(total))return json(res,400,{error:'Invalid line total'});
            items.push({description,quantity,unitPrice,total,unit:String(x.unit||'each').slice(0,30)});
          }
          const subtotal=items.reduce((a,x)=>a+x.total,0),discount=Number(data.discount_pence||0),vat=Number(data.vat_pence||0);
          if(!Number.isSafeInteger(subtotal)||!Number.isSafeInteger(discount)||discount<0||discount>subtotal||!Number.isSafeInteger(vat)||vat<0)return json(res,400,{error:'Invalid totals'});
          if(['sent','accepted','converted'].includes(data.status)&&(items.some(x=>x.unitPrice<=0)||subtotal-discount+vat<=0))return json(res,409,{error:'Review and price every item before marking this quotation sent or accepted.'});
          const client=await pool.connect();
          try{
            await client.query('BEGIN');
            const updated=await client.query('UPDATE quotes SET status=$2,subtotal_pence=$3,discount_pence=$4,vat_pence=$5,total_pence=$6,customer_notes=$7,updated_by=$8,updated_at=now() WHERE id=$1 RETURNING id,quote_number,status,total_pence',[quoteMatch[1],data.status,subtotal,discount,vat,subtotal-discount+vat,String(data.customer_notes||'').slice(0,2000),user.id]);
            if(!updated.rowCount){await client.query('ROLLBACK');return json(res,404,{error:'Quotation not found'});}
            await client.query('DELETE FROM quote_items WHERE quote_id=$1',[quoteMatch[1]]);
            for(let i=0;i<items.length;i++){const x=items[i];await client.query('INSERT INTO quote_items(quote_id,sort_order,description,quantity,unit,unit_price_pence,line_total_pence) VALUES($1,$2,$3,$4,$5,$6,$7)',[quoteMatch[1],i,x.description,x.quantity,x.unit,x.unitPrice,x.total]);}
            await client.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'quote',$2,'update')",[user.id,quoteMatch[1]]);
            await client.query('COMMIT');return json(res,200,{quote:updated.rows[0]});
          }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
        }
        if(pathname==='/api/staff'&&req.method==='GET'){
          const result=await pool.query("SELECT id,email,full_name,role FROM staff_users WHERE is_active=true ORDER BY full_name NULLS LAST,email");
          return json(res,200,{staff:result.rows});
        }
        if(pathname==='/api/jobs'&&req.method==='GET'){
          const result=await pool.query("SELECT j.id,j.status,j.due_date,j.production_notes,j.assigned_to,j.created_at,c.name AS customer_name,q.quote_number,s.email AS assigned_email FROM jobs j JOIN customers c ON c.id=j.customer_id LEFT JOIN quotes q ON q.id=j.quote_id LEFT JOIN staff_users s ON s.id=j.assigned_to ORDER BY j.created_at DESC LIMIT 100");
          return json(res,200,{jobs:result.rows});
        }
        if(pathname==='/api/jobs'&&req.method==='POST'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req);
          if(typeof data.quote_id!=='string'||!/^[0-9a-f-]{36}$/i.test(data.quote_id))return json(res,400,{error:'Select a valid quotation'});
          const client=await pool.connect();
          try{
            await client.query('BEGIN');
            const q=await client.query('SELECT id,customer_id,status FROM quotes WHERE id=$1 FOR UPDATE',[data.quote_id]);
            if(!q.rowCount){await client.query('ROLLBACK');return json(res,404,{error:'Quote not found'});}
            if(!['accepted','converted'].includes(q.rows[0].status)){await client.query('ROLLBACK');return json(res,409,{error:'Accept the quotation before creating a job'});}
            const pricing=await client.query('SELECT total_pence FROM quotes WHERE id=$1',[data.quote_id]);const unpriced=await client.query('SELECT 1 FROM quote_items WHERE quote_id=$1 AND unit_price_pence<=0 LIMIT 1',[data.quote_id]);if(Number(pricing.rows[0].total_pence)<=0||unpriced.rowCount){await client.query('ROLLBACK');return json(res,409,{error:'Quotation has unpriced items. Review pricing before production.'});}
            const created=await client.query("INSERT INTO jobs(quote_id,customer_id,status) VALUES($1,$2,'new') ON CONFLICT (quote_id) DO NOTHING RETURNING id,status",[data.quote_id,q.rows[0].customer_id]);
            if(!created.rowCount){await client.query('ROLLBACK');return json(res,409,{error:'This quote already has a job'});}
            await client.query("UPDATE quotes SET status='converted',updated_at=now(),updated_by=$2 WHERE id=$1",[data.quote_id,user.id]);
            await client.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'job',$2,'create')",[user.id,created.rows[0].id]);
            await client.query('COMMIT');return json(res,201,{job:created.rows[0]});
          }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
        }
        const jobMatch=pathname.match(/^\/api\/jobs\/([0-9a-f-]{36})$/i);
        if(jobMatch&&req.method==='PUT'){
          if(!['super_admin','manager','workshop'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req),statuses=['new','approved','in_production','ready','dispatched','completed','cancelled'];
          if(!statuses.includes(data.status))return json(res,400,{error:'Invalid job status'});
          const assigned=data.assigned_to||null;
          if(assigned&&!/^[0-9a-f-]{36}$/i.test(assigned))return json(res,400,{error:'Invalid staff member'});
          if(data.due_date&&!/^\d{4}-\d{2}-\d{2}$/.test(data.due_date))return json(res,400,{error:'Invalid due date'});
          const result=await pool.query("UPDATE jobs SET status=$2,assigned_to=$3,due_date=$4,production_notes=$5,updated_at=now() WHERE id=$1 RETURNING id,status",[jobMatch[1],data.status,assigned,data.due_date||null,String(data.production_notes||'').slice(0,4000)]);
          if(!result.rowCount)return json(res,404,{error:'Job not found'});
          await pool.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'job',$2,'update')",[user.id,jobMatch[1]]);
          return json(res,200,{job:result.rows[0]});
        }
        if(pathname==='/api/costing'&&req.method==='GET'){
          const [settings,materials]=await Promise.all([pool.query('SELECT key,value_pence FROM costing_settings ORDER BY key'),pool.query('SELECT material_name,thickness_mm,sheet_length_mm,sheet_width_mm,price_pence,supplier_cost_pence FROM material_sheet_prices ORDER BY material_name,thickness_mm')]);
          return json(res,200,{settings:settings.rows,materials:materials.rows});
        }
        if(pathname==='/api/costing/supplier-cost'&&req.method==='PUT'){
          if(user.role!=='super_admin')return json(res,403,{error:'Administrator only'});
          const data=await body(req);
          const material=String(data.material_name||'').trim(),thickness=Number(data.thickness_mm),cost=Number(data.supplier_cost_pence);
          if(!material||!Number.isFinite(thickness)||thickness<=0||!Number.isSafeInteger(cost)||cost<0||cost>100000000)return json(res,400,{error:'Invalid supplier cost'});
          const result=await pool.query('UPDATE material_sheet_prices SET supplier_cost_pence=$1,updated_at=now() WHERE material_name=$2 AND thickness_mm=$3 RETURNING id',[cost,material,thickness]);
          return result.rowCount?json(res,200,{ok:true}):json(res,404,{error:'Save material selling price first'});
        }
        if(pathname==='/api/costing/bulk'&&req.method==='POST'){
          if(user.role!=='super_admin')return json(res,403,{error:'Only the administrator can import pricing'});
          const data=await body(req,2000000);
          if(!Array.isArray(data.rows)||!data.rows.length||data.rows.length>1000)return json(res,400,{error:'Import 1 to 1000 material rows'});
          const validated=[];const seen=new Set();
          for(let i=0;i<data.rows.length;i++){
            const row=data.rows[i],material=String(row.material_name||'').trim(),thickness=Number(row.thickness_mm),price=Number(row.price_pence),length=Number(row.sheet_length_mm),width=Number(row.sheet_width_mm);
            if(!material||material.length>150||![thickness,price,length,width].every(Number.isFinite)||thickness<=0||thickness>100||!Number.isSafeInteger(price)||price<0||price>100000000||!Number.isInteger(length)||!Number.isInteger(width)||length<100||width<100||length>10000||width>10000)return json(res,400,{error:'Invalid price or sheet dimensions on row '+(i+1)});
            if(/fire\\s*[- ]?rated\\s*mdf/i.test(material)&&![12,18].includes(thickness))return json(res,400,{error:'Fire-rated MDF only supports 12mm and 18mm (row '+(i+1)+')'});
            const key=material.toLowerCase()+'|'+thickness;if(seen.has(key))return json(res,400,{error:'Duplicate material and thickness on row '+(i+1)});seen.add(key);
            validated.push([material,thickness,length,width,price]);
          }
          const client=await pool.connect();try{await client.query('BEGIN');for(const row of validated)await client.query('INSERT INTO material_sheet_prices(material_name,thickness_mm,sheet_length_mm,sheet_width_mm,price_pence) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_name,thickness_mm) DO UPDATE SET sheet_length_mm=EXCLUDED.sheet_length_mm,sheet_width_mm=EXCLUDED.sheet_width_mm,price_pence=EXCLUDED.price_pence,updated_at=now()',row);await client.query('COMMIT');return json(res,200,{ok:true,imported:validated.length});}catch(err){await client.query('ROLLBACK');throw err;}finally{client.release();}
        }
        if(pathname==='/api/costing'&&req.method==='PUT'){
          if(user.role!=='super_admin')return json(res,403,{error:'Only the administrator can edit pricing'});
          const data=await body(req);
          if(data.type==='rate'){
            if(!['edgebanding_per_metre','cutting_per_metre'].includes(data.key)||!Number.isSafeInteger(data.value_pence)||data.value_pence<0||data.value_pence>10000000)return json(res,400,{error:'Invalid rate'});
            await pool.query('INSERT INTO costing_settings(key,value_pence) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value_pence=EXCLUDED.value_pence,updated_at=now()',[data.key,data.value_pence]);
          }else if(data.type==='material'){
            const material=String(data.material_name||'').trim().slice(0,150),thickness=Number(data.thickness_mm),price=Number(data.price_pence);
            if(!material||!Number.isFinite(thickness)||thickness<=0||thickness>100||!Number.isSafeInteger(price)||price<0||price>100000000)return json(res,400,{error:'Invalid material price'});
            const small=/\b(mdf|plywood|ply)\b/i.test(material);
            await pool.query('INSERT INTO material_sheet_prices(material_name,thickness_mm,sheet_length_mm,sheet_width_mm,price_pence) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_name,thickness_mm) DO UPDATE SET sheet_length_mm=EXCLUDED.sheet_length_mm,sheet_width_mm=EXCLUDED.sheet_width_mm,price_pence=EXCLUDED.price_pence,updated_at=now()',[material,thickness,small?2440:2800,small?1220:2070,price]);
          }else return json(res,400,{error:'Invalid costing type'});
          return json(res,200,{ok:true});
        }
        // Staff-only, non-binding estimate for submitted public cut lists.
        // Never updates a quotation or exposes prices to customers.
        const quoteEstimateMatch=pathname.match(/^\/api\/quotes\/([0-9a-f-]{36})\/estimate$/i);
        if(quoteEstimateMatch&&req.method==='GET'){
          if(!['super_admin','manager','sales'].includes(user.role))return json(res,403,{error:'Access denied'});
          const [items,prices,rates]=await Promise.all([
            pool.query('SELECT specifications,quantity FROM quote_items WHERE quote_id=$1 ORDER BY sort_order',[quoteEstimateMatch[1]]),
            pool.query('SELECT material_name,thickness_mm,price_pence,supplier_cost_pence FROM material_sheet_prices'),
            pool.query('SELECT key,value_pence FROM costing_settings')
          ]);
          if(!items.rowCount)return json(res,404,{error:'Quote not found or has no items'});
          const parts=[];let edgeMm=0,cutMm=0,cncRequired=false;
          for(const item of items.rows){
            const p=item.specifications||{},qty=Number(item.quantity),length=Number(p.length),width=Number(p.width),thickness=Number(p.thickness);
            if(!p.material||![qty,length,width,thickness].every(Number.isFinite)||qty<1||length<=0||width<=0||thickness<=0)return json(res,422,{error:'Quotation has incomplete panel specifications; manual pricing required'});
            const sign=/foamex|aluminium composite|dibond/i.test(p.material);
            if(sign&&(p.l1||p.l2||p.w1||p.w2))return json(res,422,{error:'Sign material cannot be edged'});
            if(/cnc/i.test(String(p.service||'')))cncRequired=true;
            parts.push({id:crypto.randomUUID(),part_name:p.part||'Panel',material:String(p.material),thickness_mm:thickness,length_mm:length,width_mm:width,quantity:qty,grain_direction:'none'});
            edgeMm+=qty*((p.l1?length:0)+(p.l2?length:0)+(p.w1?width:0)+(p.w2?width:0));
            cutMm+=qty*2*(length+width);
          }
          let layout;try{layout=nestParts(parts);}catch(e){return json(res,422,{error:e.message});}
          const rate=Object.fromEntries(rates.rows.map(x=>[x.key,Number(x.value_pence)]));
          const sheets=layout.sheets.map(sh=>{
            const match=prices.rows.find(p=>p.material_name.toLowerCase()===sh.material.toLowerCase()&&Number(p.thickness_mm)===Number(sh.thickness_mm));
            return {material:sh.material,thickness_mm:sh.thickness_mm,quantity:1,sheet_price_pence:match?Number(match.price_pence):null,supplier_cost_pence:match&&match.supplier_cost_pence!==null?Number(match.supplier_cost_pence):null};
          });
          const missing_materials=[...new Set(sheets.filter(x=>x.sheet_price_pence===null).map(x=>x.material+' '+x.thickness_mm+'mm'))];
          const missing_supplier_costs=[...new Set(sheets.filter(x=>x.supplier_cost_pence===null).map(x=>x.material+' '+x.thickness_mm+'mm'))];
          const supplier_material_cost_pence=missing_supplier_costs.length?null:sheets.reduce((sum,x)=>sum+x.supplier_cost_pence,0);
          const cutting_rate=rate.cutting_per_metre||0;
          const edging_rate=rate.edgebanding_per_metre;
          const material_pence=missing_materials.length?null:sheets.reduce((sum,x)=>sum+x.sheet_price_pence,0);
          const cutting_pence=cutting_rate>0?Math.round(cutMm/1000*cutting_rate):null;
          const edging_pence=Number.isSafeInteger(edging_rate)?Math.round(edgeMm/1000*edging_rate):null;
          const ready=material_pence!==null&&cutting_pence!==null&&edging_pence!==null&&!layout.unplaced.length&&!cncRequired;
          return json(res,200,{quote_id:quoteEstimateMatch[1],sheets,unplaced_count:layout.unplaced.length,missing_materials,cnc_pricing_required:cncRequired,material_pence,cutting_pence,edging_pence,cutting_metres:Math.round(cutMm/10)/100,edging_metres:Math.round(edgeMm/10)/100,total_pence:ready?material_pence+cutting_pence+edging_pence:null,ready_for_review:ready,missing_supplier_costs,supplier_material_cost_pence,indicative_material_spread_pence:ready&&supplier_material_cost_pence!==null?material_pence-supplier_material_cost_pence:null,notice:'Internal indicative estimate only. Verify nesting, grain direction, machining and final prices before sending a quote.'});
        }
        const estimateMatch=pathname.match(/^\/api\/jobs\/([0-9a-f-]{36})\/estimate$/i);
        if(estimateMatch&&req.method==='GET'){
          const [parts,prices,rates]=await Promise.all([pool.query('SELECT * FROM job_parts WHERE job_id=$1',[estimateMatch[1]]),pool.query('SELECT * FROM material_sheet_prices'),pool.query('SELECT key,value_pence FROM costing_settings')]);
          let layout;try{layout=nestParts(parts.rows);}catch(e){return json(res,400,{error:e.message});}
          const rate=Object.fromEntries(rates.rows.map(r=>[r.key,Number(r.value_pence)]));
          const breakdown=layout.sheets.map(sh=>{const match=prices.rows.find(p=>p.material_name.toLowerCase()===String(sh.material).toLowerCase()&&Number(p.thickness_mm)===Number(sh.thickness_mm));const used=sh.placements.reduce((n,p)=>n+p.width*p.height,0),area=sh.sheetLength*sh.sheetWidth;return {material:sh.material,thickness_mm:sh.thickness_mm,sheet_length_mm:sh.sheetLength,sheet_width_mm:sh.sheetWidth,used_area_mm2:used,waste_percent:Math.round((1-used/area)*10000)/100,sheet_price_pence:match?Number(match.price_pence):null};});
          const edgeMm=parts.rows.reduce((n,p)=>n+Number(p.quantity)*((p.edge_top?Number(p.length_mm):0)+(p.edge_bottom?Number(p.length_mm):0)+(p.edge_left?Number(p.width_mm):0)+(p.edge_right?Number(p.width_mm):0)),0);
          const cutMm=parts.rows.reduce((n,p)=>n+Number(p.quantity)*2*(Number(p.length_mm)+Number(p.width_mm)),0);
          const edging_pence=Math.round(edgeMm/1000*(rate.edgebanding_per_metre||0)),cutting_pence=Math.round(cutMm/1000*(rate.cutting_per_metre||0));
          const material_pence=breakdown.every(x=>x.sheet_price_pence!==null)?breakdown.reduce((n,x)=>n+x.sheet_price_pence,0):null;
          return json(res,200,{sheets:breakdown,sheet_count:breakdown.length,unplaced_count:layout.unplaced.length,edging_metres:Math.round(edgeMm/10)/100,cutting_metres:Math.round(cutMm/10)/100,edging_pence,cutting_pence,material_pence,total_pence:material_pence===null?null:material_pence+edging_pence+cutting_pence,notice:'Indicative only; cutting length is panel perimeter, not an optimised toolpath. Missing sheet prices prevent a final total.'});
        }
        const nestMatch=pathname.match(/^\/api\/jobs\/([0-9a-f-]{36})\/nest$/i);
        if(nestMatch&&req.method==='GET'){
          const result=await pool.query('SELECT * FROM job_parts WHERE job_id=$1 ORDER BY sort_order,created_at',[nestMatch[1]]);
          const options={sheetLength:Number(url.searchParams.get('length')||2800),sheetWidth:Number(url.searchParams.get('width')||2070),margin:Number(url.searchParams.get('margin')||25),gap:12};
          try{return json(res,200,nestParts(result.rows,options));}catch(e){return json(res,400,{error:e.message});}
        }
        const partsMatch=pathname.match(/^\/api\/jobs\/([0-9a-f-]{36})\/parts$/i);
        if(partsMatch&&req.method==='GET'){
          const result=await pool.query('SELECT * FROM job_parts WHERE job_id=$1 ORDER BY sort_order,created_at',[partsMatch[1]]);
          return json(res,200,{parts:result.rows});
        }
        if(partsMatch&&req.method==='POST'){
          if(!['super_admin','manager','workshop'].includes(user.role))return json(res,403,{error:'Access denied'});
          const data=await body(req);
          const name=String(data.part_name||'').trim().slice(0,200),material=String(data.material||'').trim().slice(0,200);
          const thickness=Number(data.thickness_mm),length=Number(data.length_mm),width=Number(data.width_mm),qty=Number(data.quantity);
          if(!name||!material||![thickness,length,width].every(x=>Number.isFinite(x)&&x>0&&x<=10000)||!Number.isInteger(qty)||qty<1||qty>10000)return json(res,400,{error:'Invalid panel dimensions, material or quantity'});
          const grain=['none','length','width'].includes(data.grain_direction)?data.grain_direction:'none';
          const exists=await pool.query('SELECT id FROM jobs WHERE id=$1',[partsMatch[1]]);
          if(!exists.rowCount)return json(res,404,{error:'Job not found'});
          const result=await pool.query('INSERT INTO job_parts(job_id,part_name,material,thickness_mm,length_mm,width_mm,quantity,grain_direction,edge_top,edge_bottom,edge_left,edge_right,notes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *',[partsMatch[1],name,material,thickness,length,width,qty,grain,data.edge_top===true,data.edge_bottom===true,data.edge_left===true,data.edge_right===true,String(data.notes||'').slice(0,1000)]);
          await pool.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'job',$2,'add_part')",[user.id,partsMatch[1]]);
          return json(res,201,{part:result.rows[0]});
        }
        const partDelete=pathname.match(/^\/api\/jobs\/([0-9a-f-]{36})\/parts\/([0-9a-f-]{36})$/i);
        if(partDelete&&req.method==='DELETE'){
          if(!['super_admin','manager','workshop'].includes(user.role))return json(res,403,{error:'Access denied'});
          const result=await pool.query('DELETE FROM job_parts WHERE id=$1 AND job_id=$2 RETURNING id',[partDelete[2],partDelete[1]]);
          if(!result.rowCount)return json(res,404,{error:'Part not found'});
          await pool.query("INSERT INTO audit_log(actor_id,entity_type,entity_id,action) VALUES($1,'job',$2,'delete_part')",[user.id,partDelete[1]]);
          return json(res,200,{ok:true});
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
