/* Isolated HTTP fixtures: never connects to a switch or starts a real scan. */
const {chromium} = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const {spawnSync} = require('node:child_process')
const fs = require('node:fs/promises'), path = require('node:path'), assert = require('node:assert/strict')
;(async()=>{
  const root=path.resolve(__dirname,'..'), base='http://127.0.0.1:18129'
  const seed=spawnSync(process.env.FM10K_PYTHON || 'python3',['-c',
    'from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
    {cwd:root,env:{...process.env,PYTHONPATH:path.join(root,'backend')},encoding:'utf8'})
  assert.equal(seed.status,0,seed.stderr)
  const configuration=JSON.parse(seed.stdout), errors=[], writes=[]
  let synchronized=false, startup='control', supported=true, attempts=0, job=null, available=true
  const integration=()=>({'startup-mode':startup,'board-hal':synchronized?'bound':'unbound',
    synchronized:String(synchronized),...(supported?{recovery:'active-replay-v1'}:{})})
  const browser=await chromium.launch({headless:true,channel:process.env.FM10K_BROWSER_CHANNEL || 'msedge'})
  const page=await browser.newPage({viewport:{width:1280,height:900},locale:'zh-CN'})
  page.on('pageerror',e=>errors.push(e.message)); page.setDefaultTimeout(10000)
  try {
    await page.route('**/*',async route=>{
      const req=route.request(), url=new URL(req.url())
      assert.equal(url.origin,base)
      const send=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)})
      if(req.method()!=='GET') writes.push(url.pathname)
      switch(url.pathname) {
        case '/api/v1/auth/session': return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:'netlab'})
        // Deliberately stale: the live telemetry contract must take precedence.
        case '/api/v1/capabilities': return send({mode:'netlab',native_integration:{'startup-mode':'control','board-hal':'bound',synchronized:'true'}})
        case '/api/v1/config': return send({configuration,revision:33,pending:null})
        case '/api/v1/updates': return send({enabled:false,state:'reserved'})
        case '/api/v1/telemetry': return send({native_integration:integration(),control_available:available,ports:[],sensors:{temperatures:[],fan:{}},optics:[]})
        case '/api/v1/control/recover':
          assert.equal(req.method(),'POST'); assert.equal(req.headers()['x-csrf-token'],'fixture')
          job={id:'recovery-'+ ++attempts,kind:'control_recovery',state:'running',message:'正在恢复保存配置并核对硬件'}
          return send(job,202)
      }
      if(url.pathname.startsWith('/api/v1/jobs/')) return send(job)
      assert(!url.pathname.startsWith('/api/'),url.pathname)
      const name=url.pathname==='/'?'index.html':url.pathname.slice(1)
      return route.fulfill({contentType:name.endsWith('.js')?'text/javascript':name.endsWith('.css')?'text/css':'text/html',body:await fs.readFile(path.join(root,'frontend/dist',name))})
    })
    await page.goto(base)
    const recovery=page.getByRole('button',{name:'恢复控制',exact:true})
    await recovery.waitFor()
    assert(!await page.getByText('当前为硬件观测模式',{exact:false}).count())
    await recovery.click()
    const running=page.getByRole('button',{name:'正在恢复…',exact:true})
    await running.waitFor(); assert(await running.isDisabled())
    job={...job,state:'failed',message:'恢复未完成，控制保持锁定',error:'fixture: reload failed'}
    await recovery.waitFor(); assert(await recovery.isEnabled())
    assert.equal(attempts,1)
    await recovery.click(); await running.waitFor()
    synchronized=true; job={...job,state:'done',message:'硬件已同步，控制已恢复'}
    await recovery.waitFor({state:'detached'})
    await page.getByText('硬件已同步，控制已恢复。',{exact:true}).waitFor()
    available=false
    await recovery.waitFor()
    await page.setViewportSize({width:320,height:800})
    await page.waitForTimeout(350) // Wait for the responsive sidebar transition.
    const box=await recovery.boundingBox(); assert(box.x>=0 && box.x+box.width<=320)
    await fs.mkdir(path.join(root,'artifacts/control-recovery'),{recursive:true})
    await page.screenshot({path:path.join(root,'artifacts/control-recovery/recovery-mobile.png')})
    supported=false
    await page.getByText('需要配套原生更新才能使用恢复按钮。',{exact:true}).waitFor()
    assert(await recovery.isDisabled())
    startup='observe'
    await recovery.waitFor({state:'detached'})
    await page.getByText('当前为硬件观测模式，配置编辑尚未开放。',{exact:true}).waitFor()
    assert.deepEqual(writes,['/api/v1/control/recover','/api/v1/control/recover'])
    assert.deepEqual(errors,[])
    console.log('PASS: live control state, failure/retry, duplicate prevention, recovery refresh, old native and observe gates, 320px layout')
  } finally { await browser.close() }
})().catch(e=>{console.error(e);process.exitCode=1})
