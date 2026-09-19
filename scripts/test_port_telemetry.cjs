/* Sampling age must not depend on the workstation wall clock or imply Link Down. */
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const ts = require('../frontend/node_modules/typescript')
const source = fs.readFileSync(path.join(__dirname,'../frontend/src/portTelemetry.ts'),'utf8')
const compiled = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}})
const helpers = {}
new Function('exports',compiled.outputText)(helpers)
const {advanceSampleClock,portFreshness,portLinkLabel} = helpers
const sample = {active:true,link:'up',quality:'valid',state_quality:'valid',counter_quality:'valid',sampled_at:100}
for(const clock of [1700000000,1700000000-86400,1700000000+86400]) {
  const port = {...sample,sampled_at:clock}
  const now = advanceSampleClock(clock,1000,2500)
  assert.equal(portFreshness(port,now).age,1.5)
  assert.equal(portFreshness(port,now).delayed,false)
}
assert.equal(advanceSampleClock(null,0,100),null)
assert.equal(advanceSampleClock(100,2500,1000),100)
assert.equal(portFreshness(sample,103).delayed,false)
for(const age of [0,0.5,1,1.5,2,2.9,3])
  assert.equal(portFreshness(sample,100+age).label,'采样正常','normal sampling must not change its label during the three-second window')
const old = portFreshness(sample,104)
assert.equal(old.delayed,true)
assert.match(old.label,/4 秒未更新/)
assert.equal(portLinkLabel(sample,old.delayed),'上次：已连接')
assert.equal(portLinkLabel({...sample,link:'down'}),'未连接')
assert.equal(portLinkLabel({...sample,active:false},true),'合口占用')
assert.equal(portLinkLabel({...sample,state_quality:'unavailable'}),'未知')
assert.equal(portLinkLabel({...sample,degraded:true}),'故障关闭')
assert.equal(portFreshness({...sample,quality:'stale'},100).label,'采样延迟')
assert.equal(portFreshness(sample,100,3,'network failed').label,'更新失败')
assert.equal(portFreshness({...sample,quality:'unavailable',counter_quality:'unavailable'},100).label,'统计未取得')
assert.equal(portFreshness({...sample,quality:'unavailable',state_quality:'unavailable'},100).label,'状态未取得')
assert.equal(portFreshness(undefined,100).label,'等待采样')
assert.equal(portFreshness({...sample,sampled_at:0},100).label,'等待采样')
assert.equal(portFreshness({...sample,sampled_at:200},200).delayed,false)
console.log('Port sampling: device clock offsets, monotonic elapsed age, stale boundary, read failures, partial data, last-known links and recovery passed.')
