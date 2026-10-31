// Transactional regression test: all changes are rolled back, including on success.
// Usage: DATABASE_URL=... TEST_JOB_ID=<existing UUID> node tests/job-cost-review.js
// Prefer staging; on production this temporarily locks the selected job's review row.
const {Client}=require('pg');
const assert=require('node:assert/strict');
const id=process.env.TEST_JOB_ID;
if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id||'')){
 console.error('Set TEST_JOB_ID to an existing test job UUID');process.exit(2);
}
if(!process.env.DATABASE_URL){console.error('DATABASE_URL required');process.exit(2);}
const client=new Client({connectionString:process.env.DATABASE_URL});
(async()=>{
 await client.connect();
 try{
  await client.query('BEGIN');
  const job=await client.query('SELECT id FROM jobs WHERE id=$1 FOR UPDATE',[id]);
  assert.equal(job.rowCount,1,'Test job not found');
  const markReviewed=()=>client.query(`INSERT INTO job_cost_reviews(job_id,material_checked,machining_checked,labour_checked,overhead_checked,reviewed_at)
   VALUES($1,true,true,true,true,now()) ON CONFLICT(job_id) DO UPDATE SET
   material_checked=true,machining_checked=true,labour_checked=true,overhead_checked=true,reviewed_at=now()`,[id]);
  const checkReset=async()=>{
   const r=await client.query('SELECT material_checked,machining_checked,labour_checked,overhead_checked,reviewed_at FROM job_cost_reviews WHERE job_id=$1',[id]);
   assert.equal(r.rowCount,1);
   for(const key of ['material_checked','machining_checked','labour_checked','overhead_checked'])assert.equal(r.rows[0][key],false,key);
   assert.equal(r.rows[0].reviewed_at,null);
  };
  await markReviewed();
  const added=await client.query(`INSERT INTO job_actual_costs(job_id,category,description,amount_pence)
   VALUES($1,'other','Temporary rollback-only test cost',12345) RETURNING id`,[id]);
  await checkReset();
  await markReviewed();
  await client.query('UPDATE job_actual_costs SET voided_at=now(),void_reason=$2 WHERE id=$1',[''+added.rows[0].id,'Transactional test void']);
  await checkReset();
  const active=await client.query('SELECT count(*)::int AS count FROM job_actual_costs WHERE id=$1 AND voided_at IS NULL',[added.rows[0].id]);
  assert.equal(active.rows[0].count,0,'Voided cost must not be counted');
  // Verify aggregation excludes voided entries while retaining valid costs.
  const activeCost=await client.query(`INSERT INTO job_actual_costs(job_id,category,description,amount_pence)
   VALUES($1,'material','Test active sheet cost',2500) RETURNING id`,[id]);
  const aggregate=await client.query(`SELECT COALESCE(SUM(amount_pence),0)::bigint AS total,COUNT(*)::integer AS entries
   FROM job_actual_costs WHERE job_id=$1 AND voided_at IS NULL AND id IN ($2,$3)`,[id,added.rows[0].id,activeCost.rows[0].id]);
  assert.equal(Number(aggregate.rows[0].total),2500,'Only active cost should contribute');
  assert.equal(aggregate.rows[0].entries,1,'Only active cost should be counted');
  await checkReset();
  console.log('PASS: review invalidation and active-cost financial aggregation');
 }finally{
  await client.query('ROLLBACK').catch(()=>{});
  await client.end();
 }
})().catch(e=>{console.error('FAIL:',e.message);process.exitCode=1;});
