// Deterministic rectangular shelf-packing preview.
// Coordinates are millimetres. This is NOT CNC toolpath generation.
function nestParts(parts, opts = {}) {
  const sheetLength=Number(opts.sheetLength||2800),sheetWidth=Number(opts.sheetWidth||2070);
  const margin=Number(opts.margin??25),gap=Number(opts.gap??12);
  if(![sheetLength,sheetWidth,margin,gap].every(Number.isFinite)||sheetLength<=0||sheetWidth<=0||margin<0||gap<0||margin*2>=Math.min(sheetLength,sheetWidth))throw Error('Invalid sheet settings');
  if(sheetLength>10000||sheetWidth>10000||gap>100||margin>500)throw Error('Sheet settings out of range');
  const sheets=[],unplaced=[],maxX=sheetLength-margin,maxY=sheetWidth-margin;
  const expanded=[];
  for(const p of parts){
    const qty=Number(p.quantity),length=Number(p.length_mm),width=Number(p.width_mm);
    if(!Number.isInteger(qty)||qty<1||qty>10000||!Number.isFinite(length)||!Number.isFinite(width)||length<=0||width<=0)throw Error('Invalid part');
    if(expanded.length+qty>1000)throw Error('Preview limit: 1000 pieces');
    for(let i=0;i<qty;i++)expanded.push({id:p.id,part_name:p.part_name,material:p.material,thickness_mm:p.thickness_mm,length,width,grain:p.grain_direction||'none',piece:i+1});
  }
  // Group material and thickness to prevent different boards sharing a sheet.
  const groups=new Map();
  for(const p of expanded){const key=JSON.stringify([p.material,p.thickness_mm]);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(p);}
  for(const [key,items] of groups){
    items.sort((a,b)=>Math.max(b.length,b.width)-Math.max(a.length,a.width));
    const groupSheets=[];
    for(const p of items){
      const orientations=[{w:p.length,h:p.width,rotated:false}];
      if(p.grain==='none'&&p.length!==p.width)orientations.push({w:p.width,h:p.length,rotated:true});
      let best=null;
      for(const sheet of groupSheets){
        for(const orientation of orientations){
          let x=sheet.x,y=sheet.y,rowHeight=sheet.rowHeight;
          if(x+orientation.w>maxX){x=margin;y+=rowHeight+gap;rowHeight=0;}
          if(y+orientation.h<=maxY){
            const candidate={sheet,x,y,rowHeight,orientation,score:y*sheetLength+x};
            if(!best||candidate.score<best.score)best=candidate;
          }
        }
      }
      if(!best){
        const orientation=orientations.find(o=>o.w<=sheetLength-2*margin&&o.h<=sheetWidth-2*margin);
        if(!orientation){unplaced.push(p);continue;}
        const sheet={material:p.material,thickness_mm:p.thickness_mm,x:margin,y:margin,rowHeight:0,placements:[]};
        groupSheets.push(sheet);
        best={sheet,x:margin,y:margin,rowHeight:0,orientation};
      }
      const {sheet,x,y,orientation}=best;
      sheet.placements.push({part_id:p.id,part_name:p.part_name,piece:p.piece,x,y,width:orientation.w,height:orientation.h,rotated:orientation.rotated});
      sheet.x=x+orientation.w+gap;sheet.y=y;sheet.rowHeight=Math.max(best.rowHeight,orientation.h);
    }
    for(const sheet of groupSheets)sheets.push({material:sheet.material,thickness_mm:sheet.thickness_mm,placements:sheet.placements});
  }
  return {sheetLength,sheetWidth,margin,gap,sheets,unplaced,notice:'Visual estimate only. Verify material, grain, clamps, tool clearance and actual CNC toolpaths before cutting.'};
}
module.exports={nestParts};
