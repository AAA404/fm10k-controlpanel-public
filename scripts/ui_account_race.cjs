/* Deterministically deliver an old polling 401 around an account update. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')
function deferred() { let open; const promise = new Promise(resolve => { open=resolve }); return {open,promise} }
async function deadline(promise) {
  let timer
  try { return await Promise.race([promise,new Promise((_,reject) => { timer=setTimeout(() => reject(new Error('fixture request not received')),15000) })]) }
  finally { clearTimeout(timer) }
}
;(async () => {
  const root=path.resolve(__dirname,'..'), output=path.join(root,'artifacts/account-race')
  const seed=spawnSync(process.env.FM10K_PYTHON || 'python3',['-c','from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
    {cwd:root,env:{...process.env,PYTHONPATH:path.join(root,'backend')},encoding:'utf8'})
  assert.equal(seed.status,0,seed.stderr || String(seed.error || 'seed failed'))
  const configuration=JSON.parse(seed.stdout), checks=[]
  const browser=await chromium.launch({headless:true,...(process.env.FM10K_BROWSER_CHANNEL ? {channel:process.env.FM10K_BROWSER_CHANNEL} : {})})
  await fs.mkdir(output,{recursive:true})
  try {
    for (const order of ['before','after']) {
      const page=await browser.newPage({viewport:{width:1440,height:1000},locale:'zh-CN'})
      page.setDefaultTimeout(10000)
      const base='http://127.0.0.1:18116', pollEntered=deferred(), pollReply=deferred(), accountEntered=deferred(), accountReply=deferred()
      let holdPoll=false, expireFresh=false, posts=0
      try {
        await page.route('**/*',async route => {
          const request=route.request(), url=new URL(request.url())
          if(url.origin!==base) return route.abort()
          const send=(value,status=200) => route.fulfill({status,contentType:'application/json',body:JSON.stringify(value)})
          switch(url.pathname) {
            case '/api/v1/auth/session': return send({initialized:true,authenticated:true,username:'fixture',csrf:'csrf-before',mode:'mock'})
            case '/api/v1/capabilities': return send({mode:'mock',version:'account-race',profile:configuration.profile})
            case '/api/v1/config': return send({configuration,revision:1,pending:null})
            case '/api/v1/updates': return send({enabled:false,state:'reserved'})
            case '/api/v1/system': return send({version:'account-race',backend:'mock'})
            case '/api/v1/system/time': return send({available:true,provider:'simulator',state:'simulated',enabled:false,synchronized:false,
              server_time:Date.now()/1000,timezone:'UTC',servers:[],selected_server:null,server_address:null,last_synchronized_at:null,message:'模拟时间状态'})
            case '/api/v1/telemetry':
              if(expireFresh) {
                assert.equal((await request.allHeaders())['x-csrf-token'],'csrf-after')
                return send({detail:'replacement session has expired'},401)
              }
              if(holdPoll) { holdPoll=false; pollEntered.open(); await pollReply.promise; return send({detail:'old session revoked'},401) }
              return send({ports:[],sensors:{quality:'pending',temperatures:[],fan:{}},optics:[]})
            case '/api/v1/auth/administrator':
              ++posts
              assert.equal((await request.allHeaders())['x-csrf-token'],'csrf-before')
              assert.equal(request.postDataJSON().username,'renamed')
              accountEntered.open(); await accountReply.promise
              return send({username:'renamed',csrf:'csrf-after',expires:Date.now()/1000+3600})
          }
          if(url.pathname.startsWith('/api/')) throw new Error('Unexpected API '+url.pathname)
          const relative=url.pathname==='/'?'index.html':url.pathname.slice(1)
          assert(!relative.includes('..'))
          return route.fulfill({contentType:relative.endsWith('.js')?'text/javascript':relative.endsWith('.css')?'text/css':'text/html',body:await fs.readFile(path.join(root,'frontend/dist',relative))})
        })
        await page.goto(base)
        await page.getByRole('button',{name:'系统与维护',exact:true}).click()
        const account=page.locator('.administrator-settings')
        await account.getByLabel('管理员用户名',{exact:true}).fill('renamed')
        await account.getByLabel('当前密码',{exact:true}).fill('fixture-password-only')
        holdPoll=true
        await deadline(pollEntered.promise)
        await account.getByRole('button',{name:'保存管理员信息',exact:true}).click()
        await deadline(accountEntered.promise)
        if(order==='before') {
          pollReply.open()
          await page.waitForTimeout(200) // Let the intentionally early 401 reach the application.
          assert(await account.isVisible(),'old polling 401 logged out the browser during account rotation')
        }
        accountReply.open()
        await account.getByText('管理员信息已更新，其他登录会话已失效。',{exact:true}).waitFor()
        if(order==='after') { pollReply.open(); await page.waitForTimeout(200) }
        assert(await account.isVisible(),'late old polling 401 invalidated the replacement session')
        assert.equal(await account.getByLabel('管理员用户名',{exact:true}).inputValue(),'renamed')
        assert.equal(await page.locator('.login-screen').count(),0)
        assert.equal(posts,1,'account writes must never be automatically retried')
        await page.screenshot({path:path.join(output,order+'-rotation.png'),fullPage:true})
        checks.push('old polling 401 '+order+' account response preserves replacement session')
        expireFresh=true
        await page.getByRole('heading',{name:'登录控制面板',exact:true}).waitFor()
        checks.push('a current-session 401 still requires login ('+order+')')
      } catch(error) {
        await page.screenshot({path:path.join(output,order+'-failure.png'),fullPage:true}).catch(()=>{})
        throw error
      } finally { pollReply.open(); accountReply.open(); await page.close() }
    }
    const report={passed:true,hardware_access:false,real_network:false,checks}
    await fs.writeFile(path.join(output,'ui-report.json'),JSON.stringify(report,null,2)+'\n')
    console.log(JSON.stringify(report))
  } finally { await browser.close() }
})().catch(error => {console.error(error);process.exitCode=1})
