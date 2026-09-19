/* Real browser + private ASGI simulator: no TCP listener or hardware access. */
const {chromium} = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const {spawn,spawnSync} = require('node:child_process')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const readline = require('node:readline')
const {once} = require('node:events')
const assert = require('node:assert/strict')

;(async () => {
  const root=path.resolve(__dirname,'..'), output=path.join(root,'artifacts/port-vlan-modes')
  const state=await fs.mkdtemp(path.join(os.tmpdir(),'fm10k-vlan-modes-'))
  const python=process.env.FM10K_PYTHON || 'python3'
  const env={...process.env,PYTHONPATH:path.join(root,'backend'),PANEL_BACKEND:'mock'}
  const seed=spawnSync(python,['-c',`
import sys
from pathlib import Path
from fm10k_controlpanel.models import SwitchConfiguration
from fm10k_controlpanel.simulator import MockConfigd
c=SwitchConfiguration().model_dump()
c['vlans']=[{'id':v,'name':'VLAN '+str(v)} for v in (1,10,20,30,40)]
c['groups'][1].update(mode='split',lane_speeds=[10,25,10,25])
for p in range(5,9):
 c['ports'][p].update(enabled=p!=7,pvid=10,vlan_mode='trunk',tagged_vlans=[20])
c['ports'][5]['tagged_vlans']=[20,30]
c['ports'][8]['tagged_vlans']=[20,40]
b=MockConfigd(Path(sys.argv[1]))
b.apply(SwitchConfiguration.model_validate(c),1,'a'*32,60)
b.confirm('a'*32)
print(b.configuration.model_dump_json())
b.close()
`,state],{cwd:root,env,encoding:'utf8'})
  assert.equal(seed.status,0,seed.stderr)
  const original=JSON.parse(seed.stdout), pending=new Map(), errors=[]
  let server, sequence=0, serverOutput=''
  const base='http://127.0.0.1:18081'
  async function startServer() {
    let ready=false
    server=spawn(python,['-u','scripts/asgi_bridge.py',state],{cwd:root,env,stdio:['pipe','pipe','pipe']})
    server.stderr.on('data',chunk=>{serverOutput+=chunk.toString()})
    readline.createInterface({input:server.stdout}).on('line',line=>{
      const response=JSON.parse(line)
      if(response.ready) ready=true
      else {const item=pending.get(response.id); if(item){pending.delete(response.id);item(response)}}
    })
    for(let i=0;i<100&&!ready;i++) {
      if(server.exitCode!==null) throw Error(serverOutput)
      await new Promise(resolve=>setTimeout(resolve,50))
    }
    assert(ready,'ASGI bridge did not start')
  }
  async function stopServer() {
    if(server&&server.exitCode===null) {const stopped=once(server,'exit');server.kill('SIGTERM');await stopped}
  }
  let browser
  await fs.mkdir(output,{recursive:true})
  try {
    await startServer()
    browser=await chromium.launch({headless:true,...(process.env.FM10K_BROWSER_CHANNEL?{channel:process.env.FM10K_BROWSER_CHANNEL}:{})})
    const page=await browser.newPage({viewport:{width:1440,height:1080},locale:'zh-CN'})
    page.setDefaultTimeout(15000)
    page.on('pageerror',error=>errors.push(error.message))
    await page.route('**/*',async route=>{
      const request=route.request(),url=new URL(request.url())
      if(url.origin!==base) return route.abort()
      const id=++sequence
      const response=await new Promise((resolve,reject)=>{
        const timeout=setTimeout(()=>{pending.delete(id);reject(Error('ASGI bridge timeout'))},30000)
        pending.set(id,result=>{clearTimeout(timeout);resolve(result)})
        server.stdin.write(JSON.stringify({id,method:request.method(),path:url.pathname+url.search,headers:request.headers(),body:(request.postDataBuffer()||Buffer.alloc(0)).toString('base64')})+'\n')
      })
      await route.fulfill({status:response.status,headers:response.headers,body:Buffer.from(response.body,'base64')})
    })
    async function login(setup=false) {
      await page.goto(base)
      await page.getByLabel('用户名',{exact:true}).fill('vlan-test')
      await page.getByLabel('密码',{exact:true}).fill('Local-vlan-test-only-2026!')
      await page.getByRole('button',{name:setup?'创建管理员并进入':'登录',exact:true}).click()
      await page.getByRole('heading',{name:'设备概览',exact:true}).waitFor()
      await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    }
    const config=()=>page.evaluate(async()=>{const r=await fetch('/api/v1/config');if(!r.ok)throw Error('config read failed');return r.json()})
    async function settingsMode(mode) {
      await page.locator('#port-settings-trigger-1').click()
      const dialog=page.getByRole('dialog',{name:'P5 · 端口设置',exact:true})
      await dialog.getByRole('combobox',{name:'端口组模式',exact:true}).selectOption(mode)
      return dialog
    }
    async function preview() {
      await page.getByRole('button',{name:'完成设置',exact:true}).click()
      await page.getByRole('button',{name:'预览并校验',exact:true}).click()
      const review=page.locator('.preview-modal')
      await review.getByRole('heading',{name:'检查配置变更',exact:true}).waitFor()
      const ack=review.getByRole('checkbox',{name:/已了解标称带宽/})
      if(await ack.count()) await ack.check()
      return review
    }
    async function submitAndFinish(review,action) {
      await review.getByRole('button',{name:'提交配置',exact:true}).click()
      const transaction=page.locator('.transaction-modal')
      await transaction.getByRole('button',{name:'确认保留',exact:true}).waitFor()
      await transaction.getByRole('button',{name:action==='confirm'?'确认保留':'恢复原配置',exact:true}).click()
      await transaction.waitFor({state:'hidden'})
      await page.waitForFunction(()=>!document.querySelector('.save-bar'))
    }
    await login(true)
    let dialog=await settingsMode('100g')
    assert.match(await dialog.getByLabel('EPL VLAN 调整',{exact:true}).innerText(),/共同 VLAN：10, 20/)
    let review=await preview()
    const changes=review.getByLabel('EPL 与 VLAN 联动变更',{exact:true})
    assert.equal(await changes.locator('tbody tr').count(),4)
    for(const id of [6,7,8]) assert.match(await changes.getByRole('row').filter({has:page.getByRole('rowheader',{name:'P'+id,exact:true})}).innerText(),/移除 VLAN 成员/)
    await review.locator('.modal-scroll').evaluate(element=>{element.scrollTop=0})
    await review.screenshot({path:path.join(output,'merge-vlan-preview.png')})
    await submitAndFinish(review,'confirm')
    let current=(await config()).configuration
    assert.equal(current.groups[1].mode,'100g')
    assert.deepEqual(current.ports[5].tagged_vlans,[20])
    assert.deepEqual(current.groups[1].split_vlan_backup.map(p=>p.tagged_vlans),[[20,30],[20],[20],[20,40]])
    const saved=structuredClone(current.groups[1].split_vlan_backup)
    await page.goto('about:blank')
    await stopServer();await startServer();await login()
    current=(await config()).configuration
    assert.deepEqual(current.groups[1].split_vlan_backup,saved,'confirmed history survives a backend restart and a new login')
    dialog=await settingsMode('40g')
    review=await preview();await submitAndFinish(review,'confirm')
    assert.deepEqual((await config()).configuration.groups[1].split_vlan_backup,saved)
    dialog=await settingsMode('split')
    assert.match(await dialog.getByLabel('EPL VLAN 调整',{exact:true}).innerText(),/恢复拆分口 VLAN/)
    review=await preview()
    await review.locator('.modal-scroll').evaluate(element=>{element.scrollTop=0})
    await review.screenshot({path:path.join(output,'split-vlan-preview.png')})
    await submitAndFinish(review,'rollback')
    current=(await config()).configuration
    assert.equal(current.groups[1].mode,'40g');assert.deepEqual(current.groups[1].split_vlan_backup,saved)
    await settingsMode('split');review=await preview();await submitAndFinish(review,'confirm')
    current=(await config()).configuration
    assert.equal(current.groups[1].mode,'split');assert.equal(current.groups[1].split_vlan_backup,undefined)
    for(let id=5;id<=8;id++) assert.deepEqual(current.ports[id],original.ports[id],'P'+id+' restores its original settings')
    assert.deepEqual(current.groups[1].lane_speeds,original.groups[1].lane_speeds)
    assert.deepEqual(errors,[])
    const report={passed:true,real_network:false,hardware_access:false,checks:[
      'merge previews every removed child VLAN','common native/tagged VLANs are retained',
      'confirmed split history survives backend restart and re-login','40G/100G changes retain history',
      'rolling back a split restores the merged configuration and its history','confirmed split restores each original port VLAN and enable state']}
    await fs.writeFile(path.join(output,'ui-report.json'),JSON.stringify(report,null,2)+'\n')
    console.log(JSON.stringify(report))
  } catch(error) {
    if(browser) await browser.contexts()[0]?.pages()[0]?.screenshot({path:path.join(output,'failure.png')}).catch(()=>{})
    throw error
  } finally {
    if(browser) await browser.close()
    await stopServer()
  }
})().catch(error=>{console.error(error);process.exitCode=1})
