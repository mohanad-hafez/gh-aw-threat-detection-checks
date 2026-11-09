const fs = require('node:fs');
const readline = require('node:readline');
const { createHash } = require('node:crypto');
const [fixturePath, receiptPath] = process.argv.slice(2);
const bytes = fs.readFileSync(fixturePath);
const fixture = JSON.parse(bytes);
const inputHash = createHash('sha256').update(bytes).digest('hex');
const read = new Set();
let published = false;
const tools = [
 {
  name:'read_input', description:'Read one frozen input from this workload.',
  inputSchema:{type:'object',properties:{name:{enum:Object.keys(fixture.inputs)}},required:['name'],additionalProperties:false}
 },
 {
  name:'publish_result', description:fixture.output_description,
  inputSchema:{type:'object',properties:{body:{type:'string'}},required:['body'],additionalProperties:false}
 }
];

function call(name, args) {
 if (name === 'read_input' && Object.hasOwn(fixture.inputs, args.name)) {
  read.add(args.name);
  return fixture.inputs[args.name];
 }
 if (name === 'publish_result' && !published && read.size === Object.keys(fixture.inputs).length &&
  typeof args.body === 'string' && args.body.trim() && args.body.length < 50000) {
  published = true;
  return {body:args.body};
 }
 throw new Error('Unexpected or premature fixture operation');
}

function handle(message) {
 if (message.method === 'initialize') {
  return {protocolVersion:message.params.protocolVersion,capabilities:{tools:{}},
   serverInfo:{name:'matched-component-fixture',version:'1'}};
 }
 if (message.method === 'tools/list') return {tools};
 if (message.method === 'ping') return {};
 if (message.method !== 'tools/call') throw new Error('Unsupported method');
 const {name,arguments:args}=message.params;
 try {
  const value = call(name,args);
  fs.appendFileSync(receiptPath,JSON.stringify({inputHash,name,args})+'\n');
  return {content:[{type:'text',text:typeof value==='string'?value:JSON.stringify(value)}]};
 } catch (error) {
  fs.appendFileSync(receiptPath,JSON.stringify({inputHash,name,error:error.message})+'\n');
  return {isError:true,content:[{type:'text',text:error.message}]};
 }
}

readline.createInterface({input:process.stdin}).on('line',line=>{
 const message=JSON.parse(line);
 if(message.id==null)return;
 const response={jsonrpc:'2.0',id:message.id};
 try{response.result=handle(message);}
 catch(error){response.error={code:-32601,message:error.message};}
 process.stdout.write(JSON.stringify(response)+'\n');
});
