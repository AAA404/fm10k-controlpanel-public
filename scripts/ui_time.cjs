/* Isolated UI state coverage: no real clock or NTP server changes. */
const {chromium} = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const {spawnSync} = require('node:child_process')
const fs=require('node:fs/promises'), path=require('node:path'), assert=require('node:assert/strict')
;(async()=>{
  const root=path.resolve(__dirname,'..'), base='http://127.0.0.1:18131'
  const raw=spawnSync(process.env.FM10K_PYTHON || 'python3',['-c','from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],{cwd:root,env:{...process.env,PYTHONPATH:path.join(root,'backend')},encoding:'utf8'})
  assert.equal(raw.status,0,raw.stderr)
  const configuration=JSON.parse(raw.stdout), errors=[]
  let failRead=false, failSync=false, synchronized=false, reads=0, writes=[]
  let readGate=null
  let servers=['ntp.example.com']
  const status=()=>({available:true,provider:'systemd-timesyncd',state:synchronized?'synchronized':'waiting',enabled:true,synchronized,
    server_time:Date.now()/1000-86400,timezone:'Asia/Shanghai',servers,selected_server:'ntp.example.com',server_address:'192.0.2.1',
    last_synchronized_at:synchronized?Date.now()/1000-86400:null,message:synchronized?'系统时钟已同步。':'请检查 UDP 123 连通性。'})
  const browser=await chromium.launch({headless:true,...(process.env.FM10K_BROWSER_CHANNEL?{channel:process.env.FM10K_BROWSER_CHANNEL}:{})})
  const deadline=setTimeout(()=>{console.error('Time UI test timeout');process.exitCode=1;void browser.close()},90000)
  try {
    const page=await browser.newPage({viewport:{width:1440,height:1080},locale:'zh-CN'})
    page.setDefaultTimeout(15000);page.on('pageerror',e=>errors.push(e.message))
    await page.route('**/*',async route=>{
      const req=route.request(),url=new URL(req.url());assert.equal(url.origin,base)
      const send=(value,code=200)=>route.fulfill({status:code,contentType:'application/json',body:JSON.stringify(value)})
      switch(url.pathname){
        case '/api/v1/auth/session':return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:'netlab'})
        case '/api/v1/capabilities':return send({mode:'netlab',version:'0.1.0~timesync1'})
        case '/api/v1/config':return send({configuration,revision:68,pending:null})
        case '/api/v1/updates':return send({enabled:false,state:'reserved'})
        case '/api/v1/telemetry':return send({ports:[],sensors:{temperatures:[],fan:{}},optics:[]})
        case '/api/v1/system':return send({hostname:'fixture',version:'0.1.0~timesync1'})
        case '/api/v1/system/time': {
          reads++
          const snapshot=status(), gate=readGate
          readGate=null
          if(gate){gate.started();await gate.promise}
          return failRead?send({detail:'时间服务暂时不可用'},503):send(snapshot)
        }
        case '/api/v1/system/time/sync':
          assert.equal(req.headers()['x-csrf-token'],'fixture');writes.push(req.postDataJSON())
          if(failSync)return send({detail:'同步操作失败，已恢复原设置'},503)
          servers=req.postDataJSON().servers||servers;synchronized=false
          return send({...status(),message:'已发起同步，正在等待时间服务器响应。'})
      }
      assert(!url.pathname.startsWith('/api/'),url.pathname)
      const file=url.pathname==='/'?'index.html':url.pathname.slice(1)
      return route.fulfill({contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',body:await fs.readFile(path.join(root,'frontend/dist',file))})
    })
    await page.goto(base)
    await page.getByRole('button',{name:'系统与维护',exact:true}).click()
    const card=page.locator('.time-settings')
    await card.getByText('等待服务器响应',{exact:true}).waitFor()
    assert.equal(await card.getByText('已同步',{exact:true}).count(),0)
    const presets=card.getByLabel('国内常用时间服务器',{exact:true})
    for (const host of ['ntp.aliyun.com','ntp.tencent.com','ntp.ntsc.ac.cn','cn.pool.ntp.org'])
      assert.equal(await presets.locator(`option[value="${host}"]`).count(),1)
    await presets.selectOption('ntp.aliyun.com')
    await card.getByRole('button',{name:'添加到列表',exact:true}).click()
    assert.equal(await card.getByLabel('时间服务器',{exact:true}).inputValue(),'ntp.example.com\nntp.aliyun.com')
    assert.equal(writes.length,0,'adding a preset only edits the draft')
    await presets.selectOption('ntp.aliyun.com')
    assert(await card.getByRole('button',{name:'添加到列表',exact:true}).isDisabled())
    await card.getByLabel('时间服务器',{exact:true}).fill('a\nb\nc\nd')
    await presets.selectOption('ntp.tencent.com')
    assert(await card.getByRole('button',{name:'添加到列表',exact:true}).isDisabled())
    await card.getByLabel('时间服务器',{exact:true}).fill('time.example.net\n192.168.100.1')
    assert(await card.getByRole('button',{name:'立即同步',exact:true}).isDisabled())
    const previous=reads
    let releaseRead, pollStarted
    const started=new Promise(resolve=>{pollStarted=resolve})
    readGate={started:pollStarted,promise:new Promise(resolve=>{releaseRead=resolve})}
    synchronized=true // The delayed GET must not overwrite the following sync response.
    await started
    assert(reads>previous)
    assert(await card.getByRole('button',{name:'保存并同步',exact:true}).isEnabled(),'background refresh must keep save enabled')
    assert(await card.getByRole('button',{name:'刷新状态',exact:true}).isEnabled(),'background refresh must not flash the refresh button')
    assert.equal(await card.getByLabel('时间服务器',{exact:true}).inputValue(),'time.example.net\n192.168.100.1')
    await card.getByRole('button',{name:'保存并同步',exact:true}).click()
    await card.getByText('已发起同步，正在等待时间服务器响应。',{exact:true}).last().waitFor()
    assert.deepEqual(writes[0],{servers:['time.example.net','192.168.100.1']})
    const staleRead=page.waitForResponse(r=>r.url().endsWith('/api/v1/system/time'))
    releaseRead()
    await staleRead
    await page.waitForTimeout(100)
    assert.equal(await card.getByLabel('时间服务器',{exact:true}).inputValue(),'time.example.net\n192.168.100.1','older read must not replace saved servers')
    assert.equal(await card.getByText('已同步',{exact:true}).count(),0)
    synchronized=true
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByText('已同步',{exact:true}).waitFor()
    failRead=true
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByText('时间服务暂时不可用',{exact:true}).waitFor()
    assert.equal(await card.getByText('已同步',{exact:true}).count(),0)
    failRead=false;failSync=true
    await card.getByRole('button',{name:'立即同步',exact:true}).click()
    await card.getByText('同步操作失败，已恢复原设置',{exact:true}).waitFor()
    assert.deepEqual(writes[1],{})
    const beforePoll=reads
    await page.waitForTimeout(5500)
    assert(reads>beforePoll)
    assert(await card.getByText('同步操作失败，已恢复原设置',{exact:true}).isVisible(),'successful polling must not erase a failed user action')
    await card.getByLabel('时间服务器',{exact:true}).fill('a\nb\nc\nd\ne')
    await card.getByRole('button',{name:'保存并同步',exact:true}).click()
    await card.getByText('请填写 1～4 个时间服务器，每行一个。',{exact:true}).waitFor()
    assert.equal(writes.length,2)
    await fs.mkdir(path.join(root,'artifacts/time-ui'),{recursive:true})
    await page.screenshot({path:path.join(root,'artifacts/time-ui/desktop.png'),fullPage:true})
    await page.setViewportSize({width:390,height:844})
    await card.getByLabel('时间服务器',{exact:true}).fill('ntp.example.com')
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByText('已同步',{exact:true}).waitFor()
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth))
    await page.screenshot({path:path.join(root,'artifacts/time-ui/mobile.png'),fullPage:true})
    await page.setViewportSize({width:1440,height:1080})
    await page.getByRole('button',{name:'设备概览',exact:true}).click()
    const stopped=reads
    await page.waitForTimeout(5500)
    assert.equal(reads,stopped)
    assert.deepEqual(errors,[])
    console.log('PASS: time status, stable polling controls, save during polling, stale read isolation, draft preservation, save/retry, verified sync only, errors, server limit, page exit and responsive layout')
  } finally {clearTimeout(deadline);await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1})
