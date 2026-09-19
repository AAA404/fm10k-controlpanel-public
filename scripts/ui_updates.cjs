/* All browser requests are intercepted; no GitHub, board or service operations. */
const {chromium}=require(process.env.FM10K_PLAYWRIGHT_MODULE||'../frontend/node_modules/playwright')
const {spawnSync}=require('node:child_process')
const fs=require('node:fs/promises'),path=require('node:path'),assert=require('node:assert/strict')
;(async()=>{
  const root=path.resolve(__dirname,'..'),base='http://127.0.0.1:18133'
  const raw=spawnSync(process.env.FM10K_PYTHON||'python3',['-c','from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
    {cwd:root,env:{...process.env,PYTHONPATH:path.join(root,'backend')},encoding:'utf8'})
  assert.equal(raw.status,0,raw.stderr)
  const configuration=JSON.parse(raw.stdout),errors=[],checks=[],installs=[]
  let state={enabled:true,state:'idle',current_version:'0.1.0',candidate:null,job:null,message:'可以检查 GitHub 的最新稳定版本。'}
  let failRead=false,loseInstallReply=false,nextVersion='0.2.0'
  const candidate=version=>({version,manifest_sha256:'a'.repeat(64),release_url:'https://github.com/AAA404/fm10k-controlpanel-public/releases/tag/v'+version})
  const browser=await chromium.launch({headless:true,...(process.env.FM10K_BROWSER_CHANNEL?{channel:process.env.FM10K_BROWSER_CHANNEL}:{})})
  const deadline=setTimeout(()=>{process.exitCode=1;void browser.close()},90000)
  try {
    const page=await browser.newPage({viewport:{width:1440,height:1080},locale:'zh-CN'})
    page.setDefaultTimeout(15000);page.on('pageerror',error=>errors.push(error.message))
    await page.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url());assert.equal(url.origin,base,'external requests are forbidden')
      const send=(value,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)})
      switch(url.pathname){
        case '/api/v1/auth/session':return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:'netlab'})
        case '/api/v1/capabilities':return send({mode:'netlab',version:state.current_version})
        case '/api/v1/config':return send({configuration,revision:1,pending:null})
        case '/api/v1/telemetry':return send({ports:[],sensors:{temperatures:[],fan:{}},optics:[]})
        case '/api/v1/system':return send({hostname:'fixture',version:state.current_version})
        case '/api/v1/system/time':return send({available:false,state:'unavailable',enabled:false,synchronized:false,server_time:Date.now()/1000,servers:[],message:'fixture'})
        case '/api/v1/updates':return failRead?send({detail:'service restarting'},503):send(state)
        case '/api/v1/updates/check':
          assert.equal(request.headers()['x-csrf-token'],'fixture');checks.push(request.postDataJSON())
          state={...state,state:'available',candidate:candidate(nextVersion),message:'发现可用稳定版本。'}
          return send(state)
        case '/api/v1/updates/install':
          assert.equal(request.headers()['x-csrf-token'],'fixture');installs.push(request.postDataJSON())
          assert.equal(installs.at(-1).confirm_restart,true)
          state={...state,state:'queued',job:{id:'job-'+installs.length,version:nextVersion,state:'queued'},message:'更新已排队。'}
          return loseInstallReply?route.abort():send(state,202)
      }
      assert(!url.pathname.startsWith('/api/'),url.pathname)
      const file=url.pathname==='/'?'index.html':url.pathname.slice(1)
      return route.fulfill({contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html',body:await fs.readFile(path.join(root,'frontend/dist',file))})
    })
    await page.goto(base)
    await page.getByRole('button',{name:'系统与维护',exact:true}).click()
    const card=page.locator('.ota-updates')
    await card.getByRole('button',{name:'检查更新',exact:true}).waitFor()
    assert.equal(checks.length,0,'opening maintenance must not contact GitHub')
    await card.getByRole('button',{name:'检查更新',exact:true}).click()
    const install=card.getByRole('button',{name:'安装 0.2.0',exact:true})
    await install.waitFor()
    assert(await install.isDisabled(),'restart acknowledgment is mandatory')
    assert.equal(await card.locator('input[type=password],input[type=text]').count(),0,'no credential UI')
    await card.getByRole('checkbox').check()
    await install.click()
    await card.getByText('更新已排队。',{exact:true}).waitFor()
    assert.equal(installs.length,1)
    assert.deepEqual(installs[0],{version:'0.2.0',manifest_sha256:'a'.repeat(64),confirm_restart:true})
    assert(await card.getByRole('button',{name:'检查更新',exact:true}).isDisabled())
    failRead=true
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByRole('alert').waitFor()
    assert.match(await card.innerText(),/正在重新读取更新状态/)
    failRead=false
    state={...state,state:'succeeded',current_version:'0.2.0',candidate:null,job:{...state.job,state:'succeeded'},message:'配置与健康检查通过。'}
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByText('配置与健康检查通过。',{exact:true}).waitFor()
    assert.equal(await card.getByRole('alert').count(),0)
    assert.equal(installs.length,1,'reconnection must not repeat installation')
    nextVersion='0.3.0'
    await card.getByRole('button',{name:'检查更新',exact:true}).click()
    await card.getByRole('button',{name:'安装 0.3.0',exact:true}).waitFor()
    assert(await card.getByRole('button',{name:'安装 0.3.0',exact:true}).isDisabled())
    await card.getByRole('checkbox').check()
    loseInstallReply=true
    await card.getByRole('button',{name:'安装 0.3.0',exact:true}).click()
    await card.getByRole('alert').waitFor()
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    assert.equal(installs.length,2)
    assert.match(await card.getByRole('alert').innerText(),/不要重复提交/,'a successful poll must not erase an uncertain write')
    state={...state,state:'rolled_back',current_version:'0.2.0',candidate:null,job:{...state.job,state:'rolled_back'},message:'更新失败，已恢复并验证原版本。'}
    await card.getByRole('button',{name:'刷新状态',exact:true}).click()
    await card.getByText('更新失败，已恢复并验证原版本。',{exact:true}).waitFor()
    assert.equal(await card.getByRole('alert').count(),0,'only the matching new job terminal result resolves a lost reply')
    const output=path.join(root,'artifacts/update-ui');await fs.mkdir(output,{recursive:true})
    await page.screenshot({path:path.join(output,'update-status.png'),fullPage:true})
    await page.setViewportSize({width:390,height:844})
    await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth)
    await page.screenshot({path:path.join(output,'update-mobile.png'),fullPage:true})
    assert.deepEqual(checks,[{},{}]);assert.deepEqual(errors,[])
    const report={passed:true,hardware_access:false,github_access:false,checks:['explicit check','CSRF','maintenance acknowledgment','restart reconnect','no repeat after lost response','checkpoint rollback state','mobile layout']}
    await fs.writeFile(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n')
    console.log(JSON.stringify(report))
  } finally {clearTimeout(deadline);await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1})
