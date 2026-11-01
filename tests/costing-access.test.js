const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../backend/server.js'),'utf8');
test('staff costing response uses an explicit public rate allowlist',()=>{
 assert.match(source,/const canSeeInternalCosts=\['super_admin','manager'\]\.includes\(user\.role\)/);
 assert.match(source,/WHERE key IN \('edgebanding_per_metre','cutting_per_metre','minimum_job_charge','cnc_machine_hourly_rate'\)/);
 assert.doesNotMatch(source,/WHERE key NOT LIKE 'internal_%'/);
});
test('non-manager costing response omits supplier purchase cost',()=>{
 const start=source.indexOf("if(pathname==='/api/costing'&&req.method==='GET')");
 const end=source.indexOf("if(pathname==='/api/costing/supplier-cost'",start);
 assert.ok(start>=0&&end>start);
 const route=source.slice(start,end);
 assert.match(route,/canSeeInternalCosts\?'SELECT material_name/);
 assert.match(route,/:\s*'SELECT material_name,thickness_mm,sheet_length_mm,sheet_width_mm,price_pence FROM material_sheet_prices/);
});
test('supplier cost updates require super administrator',()=>{
 const start=source.indexOf("if(pathname==='/api/costing/supplier-cost'&&req.method==='PUT')");
 assert.ok(start>=0);
 assert.match(source.slice(start,start+220),/if\(user\.role!=='super_admin'\)return json\(res,403/);
});

test('sales quote estimate strips supplier costs and internal contribution',()=>{
 const start=source.indexOf('const quoteEstimateMatch=');
 const end=source.indexOf('const estimateMatch=',start);
 assert.ok(start>=0&&end>start);
 const route=source.slice(start,end);
 assert.match(route,/if\(user\.role==='sales'\)return json\(res,200/);
 assert.match(route,/sheets:sheets\.map\(\(\{supplier_cost_pence,\.\.\.publicSheet\}\)=>publicSheet\)/);
 const salesBranch=route.slice(route.indexOf("if(user.role==='sales')"),route.indexOf('return json(res,200,{quote_id:',route.indexOf("if(user.role==='sales')")+5));
 assert.doesNotMatch(salesBranch,/internal_total_cost_pence|supplier_material_cost_pence|indicative_job_contribution_pence/);
});
