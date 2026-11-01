// Isolated integration test; run against the disposable CI database only.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {spawn}=require('node:child_process');
const {Pool}=require('pg');
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const port=39741;
const base='http://127.0.0.1:'+port;
const password='test-password-long-enough';
const hash=(p)=>{const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(p,salt,64).toString('hex');};
const users=['super_admin','manager','sales','workshop'];
let server;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function request(url,opts={}){const res=await fetch(base+url,opts);const data=await res.json();return {status:res.status,data,cookie:res.headers.get('set-cookie')?.split(';')[0]};}
test('authenticated costing API enforces confidential pricing access',async()=>{
 try{
  for(const role of users)await pool.query('INSERT INTO staff_users(email,role,password_hash,is_active) VALUES($1,$2,$3,true)',[role+'@example.invalid',role,hash(password)]);
  await pool.query("INSERT INTO costing_settings(key,value_pence) VALUES ('internal_cutting_cost_per_metre',123),('cutting_per_metre',247) ON CONFLICT(key) DO UPDATE SET value_pence=EXCLUDED.value_pence");
  await pool.query("INSERT INTO material_sheet_prices(material_name,thickness_mm,sheet_length_mm,sheet_width_mm,price_pence,supplier_cost_pence) VALUES ('API TEST BOARD',18,2800,2070,8000,4100) ON CONFLICT DO NOTHING");
  server=spawn(process.execPath,['backend/server.js'],{env:{...process.env,PORT:String(port)},stdio:'ignore'});
  let ready=false;
  for(let i=0;i<50;i++){if(server.exitCode!==null)break;try{const x=await request('/api/health');if(x.status===200){ready=true;break;}}catch{}await sleep(200);}
  assert.ok(ready,'Backend did not start');
  const anonymous=await request('/api/costing');assert.equal(anonymous.status,401);
  const customer=await pool.query("INSERT INTO customers(name) VALUES ('Permission test customer') RETURNING id");
  const job=await pool.query('INSERT INTO jobs(customer_id) VALUES($1) RETURNING id',[customer.rows[0].id]);
  const jobId=job.rows[0].id;
  for(const role of users){
   const login=await request('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:role+'@example.invalid',password})});
   assert.equal(login.status,200,'login '+role);
   const headers={Cookie:login.cookie};
   const result=await request('/api/costing',{headers});
   assert.equal(result.status,200,'costing '+role);
   const material=result.data.materials.find(x=>x.material_name==='API TEST BOARD');
   assert.ok(material,'test material exists');
   const settings=result.data.settings;
   if(role==='sales'||role==='workshop'){
    assert.equal(Object.hasOwn(material,'supplier_cost_pence'),false,role+' supplier cost leak');
    assert.equal(settings.some(x=>x.key==='internal_cutting_cost_per_metre'),false,role+' internal rate leak');
   }else{
    assert.equal(Number(material.supplier_cost_pence),4100,role+' supplier cost');
    assert.equal(settings.some(x=>x.key==='internal_cutting_cost_per_metre'),true,role+' internal rate');
   }
   const jobCosts=await request('/api/jobs/'+jobId+'/actual-costs',{headers});
   const jobReview=await request('/api/jobs/'+jobId+'/cost-review',{headers});
   const contribution=await request('/api/reports/job-contribution',{headers});
   const expected=role==='sales'||role==='workshop'?403:200;
   assert.equal(jobCosts.status,expected,'actual costs access '+role);
   assert.equal(jobReview.status,expected,'cost review access '+role);
   assert.equal(contribution.status,expected,'contribution report access '+role);
   const update=await request('/api/costing/supplier-cost',{method:'PUT',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({material_name:'API TEST BOARD',thickness_mm:18,supplier_cost_pence:4100})});
   assert.equal(update.status,role==='super_admin'?200:403,'supplier cost update '+role);
  }
 }finally{
  if(server){server.kill();await sleep(150);}
  await pool.end();
 }
});
