const fs=require('node:fs');
const assert=require('node:assert/strict');
const root='.github/matched';
const {inputs}=JSON.parse(fs.readFileSync(root+'/digest-fixture.json','utf8'));
assert.equal(inputs.cache,null);
let result;
if(process.env.ARM==='agent'){
  const calls=fs.readFileSync('evidence/tools.jsonl','utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual([...new Set(calls.slice(0,-1).map(row=>row.args.name))].sort(),Object.keys(inputs).sort());
  assert.equal(calls.at(-1).name,'publish_result');
  assert(calls.every(row=>!row.error));
  result=JSON.parse(calls.at(-1).args.body);
}else{
  result=JSON.parse(fs.readFileSync('evidence/go-result.json','utf8'));
}
assert.equal(result.status,'baseline_noop');
assert.equal(result.writes,0);
const state=result.state;
assert.deepEqual(state.pending_issue_numbers,[]);
assert.equal(state.pending_since,'');
assert.equal(state.last_run_at,inputs.clock);
const numbers=[...state.reported_issue_numbers].sort((a,b)=>a-b);
assert.deepEqual(numbers,inputs.issues.map(row=>row.number).sort((a,b)=>a-b));
const normalized={
  reported_issue_numbers:numbers,pending_issue_numbers:[],pending_since:'',last_run_at:inputs.clock,
};
fs.mkdirSync('digest-cache');
fs.writeFileSync('digest-cache/reported-issues.json',JSON.stringify(normalized,null,2)+'\n');
fs.writeFileSync('evidence/decision.json',JSON.stringify({status:'baseline_noop',writes:0,state:normalized}));
