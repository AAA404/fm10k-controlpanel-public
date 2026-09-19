/* Exercise real draft transformations and validate every resulting payload. */
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const {spawnSync} = require('node:child_process')
const ts = require('../frontend/node_modules/typescript')
const root = path.resolve(__dirname,'..')
const python = process.env.FM10K_PYTHON || 'python3'
const env = {...process.env,PYTHONPATH:path.join(root,'backend')}
const source = fs.readFileSync(path.join(root,'frontend/src/portModes.ts'),'utf8')
const compiled = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}})
const helpers = {}
new Function('exports',compiled.outputText)(helpers)
const {changeGroupMode,inactiveReferences} = helpers
const seed = spawnSync(python,['-c','from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],{cwd:root,env,encoding:'utf8'})
assert.equal(seed.status,0,seed.stderr)
const initial = JSON.parse(seed.stdout), cases = [], clone = value => structuredClone(value)
function split() {
  const c=clone(initial), group=c.groups[1]
  group.mode='split'; group.lane_speeds=[10,25,10,25]
  c.vlans=[1,10,20,30,40].map(id=>({id,name:'VLAN '+id}))
  for(let id=5;id<=8;id++) Object.assign(c.ports[id],{enabled:id!==7,pvid:10,vlan_mode:'trunk',tagged_vlans:[20,30]})
  c.ports[6].tagged_vlans=[20]; c.ports[8].tagged_vlans=[20,40]
  return c
}
function keep(name,configuration) {cases.push({name,configuration:clone(configuration)})}
let c=split(), before=clone(c), group=c.groups[1]
changeGroupMode(c,group,'100g')
assert.equal(group.mode,'100g')
assert.equal(group.split_vlan_backup.length,4)
assert.equal(c.ports[5].pvid,10);assert.deepEqual(c.ports[5].tagged_vlans,[20])
assert.equal(c.ports[5].enabled,true)
for(const id of [6,7,8]) {assert.equal(c.ports[id].enabled,false);assert.equal(c.ports[id].pvid,null);assert.deepEqual(c.ports[id].tagged_vlans,[])}
for(let id=1;id<=24;id++) if(id<5||id>8) assert.deepEqual(c.ports[id],before.ports[id])
assert.deepEqual(c.groups.filter(g=>g.epl!==1),before.groups.filter(g=>g.epl!==1))
assert.deepEqual(c.vlans,before.vlans)
keep('common VLAN intersection and child removals',c)
const backup=clone(group.split_vlan_backup)
changeGroupMode(c,group,'40g');assert.deepEqual(group.split_vlan_backup,backup)
changeGroupMode(c,group,'100g');assert.deepEqual(group.split_vlan_backup,backup)
keep('aggregate speed changes preserve the split record',c)
c=JSON.parse(JSON.stringify(c));group=c.groups[1]
changeGroupMode(c,group,'split')
assert.deepEqual(c,before,'split roundtrip restores native/tagged/filtering/admin and original lane speeds')
keep('reload and split restore all four profiles',c)

c=split();before=clone(c);group=c.groups[1]
for(let id=5;id<=8;id++) Object.assign(c.ports[id],{vlan_mode:'access',pvid:id===5?10:20,tagged_vlans:[]})
const primary=clone(c.ports[5])
changeGroupMode(c,group,'40g')
assert.deepEqual(c.ports[5],primary,'no common VLAN retains the primary port profile')
keep('no common VLAN has an explicit primary fallback',c)
changeGroupMode(c,group,'split')
assert.equal(c.ports[6].pvid,20);assert.equal(c.ports[7].enabled,false)
keep('distinct VLANs restore without joining them together',c)

c=split();group=c.groups[1]
Object.assign(c.ports[8],{vlan_mode:'access',pvid:40,tagged_vlans:[],enabled:true})
changeGroupMode(c,group,'100g')
c.vlans=c.vlans.filter(vlan=>vlan.id!==40)
keep('dormant history does not prevent VLAN deletion',c)
changeGroupMode(c,group,'split')
assert.equal(c.ports[8].pvid,null);assert.equal(c.ports[8].enabled,false)
assert.equal(c.ports[6].enabled,true)
keep('deleted VLAN is skipped and the unassigned port stays closed',c)

c=clone(initial);group=c.groups[1]
changeGroupMode(c,group,'split')
assert([6,7,8].every(id=>!c.ports[id].enabled&&c.ports[id].pvid===null))
keep('legacy merged configuration has safe split defaults',c)

c=split();group=c.groups[1]
c.lags=[{name:'ae0',members:[6,7],mode:'active',minimum_links:1,periodic:'fast'}]
changeGroupMode(c,group,'100g')
assert.deepEqual(inactiveReferences(c,group),['P6：ae0','P7：ae0'])
assert.deepEqual(c.lags[0].members,[6,7],'unrelated references are reported, never silently deleted')

const checked = spawnSync(python,['-c',`
import json,sys
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.netlab_codec import compile_configuration,decode_configuration,parse_xml
for case in json.load(sys.stdin):
 c=SwitchConfiguration.model_validate(case['configuration'])
 xml=compile_configuration(c)
 assert decode_configuration(xml)==c,case['name']
 if c.groups[1].mode!='split':
  interfaces={n.findtext('name'):n for n in parse_xml(xml).findall('./interfaces/interface')}
  for port in (6,7,8):
   assert not interfaces['et-0/0/'+str(port-1)].findall('./unit'),case['name']
print('all transformed payloads validate and persist; merged child VLANs are absent from native leaves')
`],{cwd:root,env,encoding:'utf8',input:JSON.stringify(cases)})
assert.equal(checked.status,0,checked.stdout+checked.stderr)
console.log(JSON.stringify({passed:true,cases:cases.map(c=>c.name),native_projection:checked.stdout.trim()}))
