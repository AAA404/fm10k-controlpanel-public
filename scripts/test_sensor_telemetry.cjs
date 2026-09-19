const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const ts = require('../frontend/node_modules/typescript')
function load(name) {
  const source = fs.readFileSync(path.join(__dirname, '../frontend/src', name), 'utf8')
  const result = {}
  new Function('exports', ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS}}).outputText)(result)
  return result
}
const {sensorQuality} = load('sensorTelemetry.ts')
const {advanceSampleClock} = load('portTelemetry.ts')
for (const deviceTime of [1789620939, 1789620939 - 23040, 1789620939 + 23040]) {
  assert.equal(sensorQuality('valid', deviceTime, advanceSampleClock(deviceTime, 1000, 3000)), 'valid')
  assert.equal(sensorQuality('valid', deviceTime, advanceSampleClock(deviceTime, 1000, 16000)), 'valid')
  assert.equal(sensorQuality('valid', deviceTime, advanceSampleClock(deviceTime, 1000, 17000)), 'stale')
  assert.equal(sensorQuality('valid', deviceTime + 16, deviceTime + 16), 'valid')
}
for (const state of ['unavailable', 'pending', 'stale', 'invalid_tach'])
  assert.equal(sensorQuality(state, 100, 200), state)
for (const timestamp of [null, undefined, NaN, 0])
  assert.equal(sensorQuality('valid', timestamp, 100), 'pending')
assert.equal(sensorQuality('valid', 100, null), 'pending')
assert.equal(sensorQuality('simulated', 100, 101), 'simulated')
console.log('Sensor freshness: device clock offsets, 15-second boundary, stopped updates, recovery and unavailable data passed.')
