/* Optical diagnostics against intercepted fixtures only; no hardware/network writes. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')

;(async () => {
  const root = path.resolve(__dirname,'..'), output = path.join(root,'artifacts/port-optics')
  const seed = spawnSync(process.env.FM10K_PYTHON || 'python3',['-c',`
import json
from pathlib import Path
from fm10k_controlpanel.models import SwitchConfiguration, PortGroup
from fm10k_controlpanel.optics import decode_phy
c = SwitchConfiguration().model_dump(mode='json')
for index, group in enumerate(c['groups']):
    group['mode'] = 'split' if index < 2 else '40g' if index == 2 else '100g'
    for lane in range(4):
        p = c['ports'][str(index*4+lane+1)]
        p['enabled'] = index < 2 or lane == 0
        p['pvid'] = 1 if p['enabled'] else None
phy = decode_phy(Path('tests/fixtures/phy-p13-100g.xml').read_bytes(), PortGroup(epl=5), wall=2000, monotonic_ms=19655055)
print(json.dumps({'configuration':SwitchConfiguration.model_validate(c).model_dump(mode='json'),'phy':phy}))
`],{cwd:root,env:{...process.env,PYTHONPATH:path.join(root,'backend')},encoding:'utf8'})
  assert.equal(seed.status,0,seed.stderr)
  const {configuration,phy:captured} = JSON.parse(seed.stdout)
  const base='http://127.0.0.1:18119', epls=[0,1,2,5,6,7]
  let scenario='pending-once', moduleQuality='valid', held=null, revision=32
  let powerMode='unqualified'
  const serverTime=()=>Date.now()/1000+86400 // Device clock is one day ahead of the workstation.
  const requests=[], writes=[], errors=[], layouts=[], checks=[]
  let eye=null, eyeAll=[], eyeReads=0
  function eyeReply() {
    if(!eye) return {state:'idle',source:'simulator'}
    if(eye.state==='running') {
      eye.columns_done=Math.min(eye.x_points,eye.columns_done+40)
      eye.state=eye.columns_done===eye.x_points?'complete':'running'
      eye.restored=eye.state==='complete'
      eye.elapsed_ms+=1000
      eye.errors=eyeAll.slice(0,eye.columns_done)
    }
    return eye
  }
  const browser=await chromium.launch({headless:true,
    ...(process.env.FM10K_BROWSER_CHANNEL?{channel:process.env.FM10K_BROWSER_CHANNEL}:{})})
  const page=await browser.newPage({viewport:{width:1440,height:1080},locale:'zh-CN'})
  page.setDefaultTimeout(12000)
  page.on('pageerror',error=>errors.push(error.message))
  await fs.mkdir(output,{recursive:true})
  try {
    await page.route('**/*',async route=>{
      const request=route.request(), url=new URL(request.url())
      if(url.origin!==base) return route.abort()
      const send=(body,status=200)=>route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)})
      if(request.method()!=='GET') writes.push(url.pathname)
      if(url.pathname==='/api/v1/optics/eye') { ++eyeReads; return send(eyeReply()) }
      const eyeStart=url.pathname.match(/^\/api\/v1\/optics\/ports\/(\d+)\/eye$/)
      if(eyeStart && request.method()==='POST') {
        assert.equal(request.headers()['x-csrf-token'],'fixture')
        const body=request.postDataJSON(), port=Number(eyeStart[1]), nx=body.x_resolution*2+1, ny=256/body.y_step
        eyeAll=Array.from({length:nx},(_,x)=>Array.from({length:ny},(_,y)=>{
          const phase=Math.abs((x-body.x_resolution)/body.x_resolution), dac=Math.abs(-128+y*body.y_step)
          return Math.round(body.dwell_bits*Math.min(.5,10**Math.min(0,(dac-Math.max(0,1-phase*2)*80)/12-5)))
        }))
        eye={id:body.request_id,source:'simulator',state:'running',port,epl:epls[Math.floor((port-1)/4)],lane:body.lane,
          signal_source:body.signal_source==='internal_loopback'?'internal_prbs31_loopback':'external',
          x_points:nx,y_points:ny,x_resolution:body.x_resolution,y_step:body.y_step,y_min:-128,dwell_bits:body.dwell_bits,
          columns_done:0,received_columns:0,errors:[],started_at:serverTime(),elapsed_ms:0,speed_mbps:25000,restored:false,restore_failed:false,
          measurement:'offset-sampler-xor',vertical_unit:'DAC'}
        return send(eye,202)
      }
      if(/\/optics\/eyes\/[0-9a-f]+\/cancel$/.test(url.pathname)) {
        eye.state='cancelled';eye.restored=true;eye.message='采集已取消。'
        return send(eye,202)
      }
      if(/\/optics\/eyes\/[0-9a-f]+\/export$/.test(url.pathname)) {
        if(url.searchParams.get('format')==='csv') return route.fulfill({status:200,contentType:'text/csv',body:'phase_ui,threshold_dac,errors,sampled_bits\n-1,-128,50000,100000\n'})
        return send(eye)
      }
      const opticsMatch=url.pathname.match(/^\/api\/v1\/optics\/ports\/(\d+)$/)
      if(opticsMatch) {
        const port=Number(opticsMatch[1]), group=configuration.groups[Math.floor((port-1)/4)]
        requests.push({port,scenario})
        const empty={quality:'pending',sampled_at:null,pcs:null,lanes:[]}
        const value={port,epl:group.epl,mpo:port<13?1:2,owner_port:Math.floor((port-1)/4)*4+1,
          mode:group.mode,profile:configuration.profile,revision,server_time:serverTime(),
          refresh_seconds:5,stale_after_seconds:15,refreshing:false,capabilities:{},
          phy:{...structuredClone(captured),sampled_at:serverTime()}}
        if(group.mode==='split') value.phy={...empty,quality:'unsupported',reason:'split_mode'}
        else if(scenario==='pending-once') {value.phy=empty;value.refreshing=true;scenario='valid'}
        else if(scenario==='partial') {value.phy.quality='partial';value.phy.lanes[0].rx_ready=null;value.phy.pcs.high_ber=null}
        else if(scenario==='stale') value.phy.sampled_at-=20
        else if(scenario==='simulated') value.phy.quality='simulated'
        else if(scenario==='unavailable') {
          value.mode=null;value.profile=null;value.phy={...empty,quality:'unavailable',error:'测试：配置快照暂不可读'}
        } else if(scenario==='mode-mismatch') value.mode=group.mode==='100g'?'40g':'100g'
        else if(scenario==='mode-pending') value.phy={...empty,reason:'mode_changed'}
        else if(scenario==='http-error') return send({detail:'测试：诊断服务暂不可读'},503)
        if(group.mode==='40g' && value.phy.lanes.length) value.phy.lanes[0].tx_cursor=40
        if(scenario==='hold') return new Promise(resolve=>{held={port,release:async()=>{await send(value);resolve()}}})
        return send(value)
      }
      switch(url.pathname) {
        case '/api/v1/auth/session': return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:'mock'})
        case '/api/v1/capabilities': return send({mode:'mock',version:'0.1.0~rc16',profile:configuration.profile})
        case '/api/v1/config': return send({configuration,revision,pending:null})
        case '/api/v1/updates': return send({enabled:false,state:'reserved'})
        case '/api/v1/telemetry': return send({server_time:serverTime(),port_sample_interval_seconds:1,port_stale_after_seconds:3,
          ports:Array.from({length:24},(_,i)=>{
            const group=configuration.groups[Math.floor(i/4)], active=group.mode==='split'||i%4===0
            return {id:i+1,epl:group.epl,mpo:i<12?1:2,lane:i%4,active,enabled:active,name:'',link:'down',
              speed_gbps:active?(group.mode==='split'?25:parseInt(group.mode)):0,quality:'valid',state_quality:'valid',counter_quality:'valid',
              sampled_at:serverTime(),rx_errors:i+100,tx_errors:i+200,crc_errors:i===16?null:i+300,rx_bytes:0,tx_bytes:0}
          }),sensors:{quality:'valid',temperatures:[{id:'obt1',celsius:48.5},{id:'obt2',celsius:51.25}],fan:{}},
          optics:[1,2].map(mpo=>({mpo,quality:moduleQuality,sampled_at:serverTime(),vendor:'FCI / Amphenol',
            part_number:'10124588-24A',serial_number:'fixture-'+mpo,tx_enable_mask:mpo===1?0x5a5:0xa5a,
            tx_power_quality:powerMode==='unqualified'?'not_exposed':'unsupported',
            rx_power_quality:['zero','stale'].includes(powerMode)?'valid':powerMode,
            rx_power_sampled_at:serverTime()-(powerMode==='stale'?20:0),
            rx_power:powerMode==='unqualified'?null:Array.from({length:12},(_,channel)=>{
              const raw=powerMode==='zero'?0:mpo*100+channel
              return {channel,raw,microwatts:raw/10,dbm:raw?10*Math.log10(raw/10000):null}
            })}))})
      }
      assert(!url.pathname.startsWith('/api/'),'Unexpected API request: '+url.pathname)
      const relative=url.pathname==='/'?'index.html':url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({contentType:relative.endsWith('.js')?'text/javascript':relative.endsWith('.css')?'text/css':'text/html',
        body:await fs.readFile(path.join(root,'frontend/dist',relative))})
    })
    const optics=page.locator('.port-optics'), status=optics.locator('.optics-section-heading .tag')
    const row=name=>optics.locator('.optics-values>div').filter({has:page.locator('dt').getByText(name,{exact:true})}).locator('dd')
    const rowText=async name=>row(name).innerText()
    async function label(text) {await status.filter({hasText:text}).waitFor()}
    async function showPort(port) {
      const detail=page.locator('#port-details-'+epls[Math.floor((port-1)/4)])
      if(!await detail.isVisible() || !await detail.getByRole('heading',{name:'P'+port+' · 端口详情',exact:true}).isVisible())
        await page.locator('#port-tile-'+port).click()
      await detail.getByRole('heading',{name:'P'+port+' · 端口详情',exact:true}).waitFor()
      await detail.getByRole('tab',{name:'光模块',exact:true}).click()
      await optics.locator('.optics-channel-heading').waitFor()
    }
    async function reopen(kind) {
      scenario=kind
      await page.locator('.expanded-port-detail').getByRole('tab',{name:'端口详情',exact:true}).click()
      await page.locator('.expanded-port-detail').getByRole('tab',{name:'光模块',exact:true}).click()
    }
    async function waitHeld() {
      for(let i=0;i<100&&!held;i++) await new Promise(resolve=>setTimeout(resolve,20))
      assert(held,'Expected one delayed diagnostics request')
    }
    const positions=()=>page.locator('.epl-box').evaluateAll(elements=>{
      const origin=document.querySelector('.port-groups-view').getBoundingClientRect()
      return elements.map(element=>{const b=element.getBoundingClientRect();return {x:b.x-origin.x,y:b.y-origin.y,width:b.width,height:b.height}})
    })
    await page.goto(base)
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    const baseline=await positions()
    assert.equal(requests.length,0,'diagnostics must be on demand')
    await showPort(17)
    await label('等待诊断')
    await label('PHY 已更新')
    assert.equal(await rowText('TX / RX 就绪'),'是 / 是')
    assert.equal(await rowText('发射开关'),'开启')
    assert.deepEqual(await optics.locator('.optics-power-grid strong').allTextContents(),['未提供','未校验'])
    assert.equal(await optics.getByRole('button',{name:'开始采集',exact:true}).count(),1)
    assert.equal(await optics.locator('canvas,svg').count(),0,'no fabricated eye graph')
    const beforeLane=requests.length
    await optics.getByRole('button',{name:'查看 Lane 3 光学诊断',exact:true}).click()
    assert.equal(await rowText('DFE 粗调 / 精调'),'已完成 / 已完成')
    assert.equal(await rowText('发射开关'),'关闭')
    assert.equal(await rowText('码块锁定 / AM 锁定'),'0/4 / 0/4')
    assert.equal(requests.length,beforeLane,'lane selection uses the same aggregate snapshot')
    await optics.getByText('均衡参数与采样信息',{exact:true}).click()
    assert.equal(await rowText('TX 前游标 / 主游标 / 后游标'),'0 / 0 / -1')
    await optics.getByText('均衡参数与采样信息',{exact:true}).click()
    assert.deepEqual(await positions(),baseline,'optical diagnostics must keep every EPL in place')
    checks.push('pending to real snapshot; clock skew; Lane selection, signed equalization and unsupported metrics')

    const power=optics.locator('.optics-power-grid')
    powerMode='valid'
    await power.getByText('-16.84 dBm',{exact:true}).waitFor()
    assert.match(await optics.innerText(),/20\.7 µW · 模块通道 7/)
    assert.equal(await power.locator('strong').first().innerText(),'模块不支持')
    powerMode='zero';await power.getByText('0 µW',{exact:true}).waitFor()
    assert.match(await optics.innerText(),/零读数不能换算为有限 dBm/)
    powerMode='stale';await power.getByText('上次 RX 读数',{exact:true}).waitFor()
    assert.equal(await power.locator('.text-warning').innerText(),'-16.84 dBm')
    powerMode='not_ready';await power.locator('strong').getByText('模块尚未就绪',{exact:true}).waitFor()
    assert(!await power.innerText().then(text=>text.includes('dBm')))
    powerMode='valid';await power.getByText('-16.84 dBm',{exact:true}).waitFor()
    checks.push('RX Lane mapping, dBm and microwatts, zero, stale, not-ready and unsupported TX power')

    for(const width of [1440,1101,761,390,320]) {
      await page.setViewportSize({width,height:1080})
      await page.locator('#epl-box-6').scrollIntoViewIfNeeded()
      await optics.evaluate(element=>{element.closest('.port-detail-body').scrollTop=0})
      const metrics=await optics.evaluate(element=>{
        const body=element.closest('.port-detail-body'), card=element.closest('.epl-box'), box=card.getBoundingClientRect()
        return {width:innerWidth,horizontalOverflow:document.documentElement.scrollWidth>innerWidth,
          contentOverflow:element.scrollWidth>element.clientWidth+1,selectorHeight:card.querySelector('.port-tile-grid').getBoundingClientRect().height,
          summaryVisible:element.querySelector('.optics-signal-column>.optics-values').getBoundingClientRect().bottom<=body.getBoundingClientRect().bottom,
          bodyHeight:body.clientHeight,scrollable:body.scrollHeight>body.clientHeight,cardHeight:box.height,areaRatio:box.width*box.height/(innerWidth*innerHeight)}
      })
      layouts.push(metrics)
      assert(!metrics.horizontalOverflow&&!metrics.contentOverflow,JSON.stringify(metrics))
      assert(metrics.bodyHeight>=150&&metrics.selectorHeight<=50,JSON.stringify(metrics))
      assert(metrics.summaryVisible,'the four primary Lane readings must fit without scrolling: '+JSON.stringify(metrics))
      if(width>=1101) assert(metrics.areaRatio<.26)
      for(const summary of ['均衡参数与采样信息','P17 端口累计计数','模块信息与读取限制']) {
        await optics.getByText(summary,{exact:true}).click()
        assert(await optics.evaluate(element=>element.scrollWidth<=element.clientWidth+1),'expanded diagnostic fields overflow')
        await optics.getByText(summary,{exact:true}).click()
      }
      await optics.evaluate(element=>{element.closest('.port-detail-body').scrollTop=0})
      if([1440,390,320].includes(width)) await page.locator('#epl-box-6').screenshot({path:path.join(output,'optics-'+width+'.png')})
    }
    await page.setViewportSize({width:1440,height:1080})
    checks.push('five responsive widths, 48px selector and in-card scrollable diagnostics')

    await reopen('partial');await label('部分数据缺失')
    assert.equal(await rowText('TX / RX 就绪'),'是 / 未读取')
    assert.equal(await rowText('高误码指示'),'未读取')
    await reopen('stale');await label('上次诊断')
    assert.match(await optics.innerText(),/超过 15 秒未取得新快照/)
    await reopen('unavailable');await label('读取失败')
    assert.match(await optics.innerText(),/配置快照暂不可读/,'configuration failures without mode metadata stay visible')
    assert.equal(await rowText('TX / RX 就绪'),'未读取 / 未读取')
    await reopen('mode-mismatch');await label('等待模式更新')
    assert.equal(await rowText('TX / RX 就绪'),'未读取 / 未读取','mismatched mode values must be hidden')
    await reopen('mode-pending');await label('等待模式更新')
    await reopen('http-error');await label('读取失败')
    assert.match(await optics.innerText(),/诊断服务暂不可读/)
    await reopen('simulated');await label('模拟诊断')
    await reopen('valid');await label('PHY 已更新')
    scenario='http-error'
    await label('上次诊断')
    assert.equal(await rowText('TX / RX 就绪'),'是 / 是','transport failure retains clearly marked historical values')
    checks.push('partial, stale, unavailable, mode cache mismatch, HTTP failure, simulation and recovery')

    await reopen('valid');await label('PHY 已更新')
    moduleQuality='stale'
    await page.waitForResponse(response=>response.url().endsWith('/api/v1/telemetry'))
    await row('发射开关').filter({hasText:'未读取'}).waitFor()
    moduleQuality='valid'
    await page.waitForResponse(response=>response.url().endsWith('/api/v1/telemetry'))
    await row('发射开关').filter({hasText:'开启'}).waitFor()

    // A delayed response for P17 must never overwrite a newer P18 selection.
    await reopen('hold');await waitHeld()
    const portResponse=held;held=null;scenario='valid'
    await showPort(18);await label('PHY 已更新')
    assert.match(await optics.locator('.optics-channel-heading').innerText(),/P17 · L1/)
    assert.equal(await optics.locator('.optics-channel-heading>strong').getAttribute('title'),'合口 P17 的 Lane 1')
    await portResponse.release()
    await page.waitForTimeout(100)
    assert.equal(await optics.getByRole('button',{name:'查看 Lane 1 光学诊断',exact:true}).getAttribute('aria-pressed'),'true')
    assert.equal(await rowText('发射开关'),'关闭')

    // Simulate an applied mode update through a configuration reload. The old
    // response was captured before the reload and arrives after the new one.
    await showPort(17);await label('PHY 已更新')
    await reopen('hold');await waitHeld()
    const modeResponse=held;held=null
    await page.getByRole('button',{name:'设置端口 P17',exact:true}).click()
    await page.getByRole('dialog').getByLabel('端口组模式',{exact:true}).selectOption('40g')
    await page.getByRole('dialog').getByRole('button',{name:'完成设置',exact:true}).click()
    configuration.groups[4].mode='40g';revision++;scenario='valid'
    await page.locator('.save-bar').getByRole('button',{name:'丢弃修改',exact:true}).click()
    await page.waitForFunction(()=>document.querySelector('#epl-box-6>.epl-box-heading>.tag').textContent==='40G')
    await label('PHY 已更新')
    await modeResponse.release()
    await page.waitForTimeout(100)
    await optics.getByText('均衡参数与采样信息',{exact:true}).click()
    assert.equal(await rowText('TX 前游标 / 主游标 / 后游标'),'0 / 40 / 0')
    checks.push('stale module mask hidden; delayed replies ignored after port and applied-mode changes')

    await showPort(16);await label('PHY 已更新')
    assert.match(await optics.locator('.optics-channel-heading').innerText(),/P13 · L3/)
    assert.equal(await rowText('发射开关'),'开启')
    await optics.getByText('P13 端口累计计数',{exact:true}).click()
    assert.equal(await rowText('RX / TX 错误'),'112 / 212','inactive child uses aggregate owner counters')
    await showPort(2);await label('PHY 暂不可用')
    assert.equal(await optics.locator('.optics-lane-selector').count(),0)
    assert.equal(await optics.locator('.optics-pcs').count(),0)
    assert.match(await optics.locator('.optics-channel-heading').innerText(),/P2 · L1/)
    assert.equal(await rowText('发射开关'),'关闭')
    await optics.getByText('P2 端口累计计数',{exact:true}).click()
    assert.equal(await rowText('RX / TX 错误'),'101 / 201')
    await showPort(6);await label('PHY 暂不可用')
    assert.equal(await rowText('发射开关'),'开启','OBT1 group position is applied to TX mask')
    await showPort(24);await label('PHY 已更新')
    assert.equal(await rowText('发射开关'),'开启','OBT2 final group position is applied to TX mask')
    checks.push('aggregate child ownership, split capability limits and both OBT mask mappings')

    await page.locator('.expanded-port-detail').getByRole('tab',{name:'端口详情',exact:true}).click()
    const afterClose=requests.length
    await page.waitForTimeout(5300)
    assert.equal(requests.length,afterClose,'closing the optical tab stops diagnostic polling')
    assert.deepEqual(writes,[],'read-only diagnostics must not submit hardware changes')
    assert.equal(eyeReads,0,'opening and switching ports must not automatically attach to an old eye scan')
    assert.deepEqual(errors,[])
    checks.push('polling stops on unmount; no hardware write or browser error')

    await showPort(13);await label('PHY 已更新')
    const eyePanel=optics.locator('.eye-diagram')
    await optics.getByRole('button',{name:'查看 Lane 2 光学诊断',exact:true}).click()
    assert.equal(await eyePanel.locator('canvas:visible').count(),0)
    await eyePanel.getByRole('button',{name:'开始采集',exact:true}).click()
    const runningEye=eye.id, inspector=page.locator('.port-inspector-dialog[open]')
    const opticalElement=await optics.elementHandle()
    await page.getByRole('button',{name:'放大端口详情',exact:true}).click()
    await inspector.waitFor()
    await inspector.getByRole('button',{name:'最大化端口详情',exact:true}).click()
    await inspector.getByRole('button',{name:'还原窗口大小',exact:true}).click()
    assert.equal(eye.id,runningEye,'resizing must not start a replacement eye scan')
    assert.equal(await optics.getByRole('button',{name:'查看 Lane 2 光学诊断',exact:true}).getAttribute('aria-pressed'),'true')
    assert(await opticalElement.evaluate(el=>el===document.querySelector('.port-inspector-dialog .port-optics')),'the optical component stays mounted during resizing')
    await inspector.getByRole('button',{name:'回到卡片',exact:true}).click()
    await eyePanel.locator('.tag').filter({hasText:'采集完成'}).waitFor({timeout:15000})
    assert.match(await eyePanel.innerText(),/模拟数据/)
    const graph=eyePanel.locator('canvas:visible')
    const unique=await graph.evaluate(c=>{
      const d=c.getContext('2d').getImageData(64,42,648,300).data, colors=new Set()
      for(let i=0;i<d.length;i+=4) colors.add(d.slice(i,i+3).join(','))
      return colors.size
    })
    assert(unique>50,'heatmap must contain measured count differences')
    await graph.scrollIntoViewIfNeeded()
    const bounds=await graph.boundingBox()
    await page.mouse.move(bounds.x+bounds.width*.5,bounds.y+bounds.height*.45)
    assert.match(await eyePanel.locator('.eye-point:visible').innerText(),/UI.*DAC/)
    await eyePanel.getByRole('button',{name:'放大眼图',exact:true}).click()
    const big=page.getByRole('dialog',{name:'放大的接收眼图'})
    await big.waitFor()
    assert((await big.boundingBox()).width>700)
    await big.screenshot({path:path.join(output,'eye-expanded.png')})
    await big.getByRole('button',{name:'关闭',exact:true}).click()
    for(const format of ['PNG','CSV','JSON']) {
      const downloaded=page.waitForEvent('download')
      await eyePanel.getByRole('button',{name:'导出 '+format,exact:true}).click()
      const file=await downloaded
      await file.saveAs(path.join(output,'eye-fixture.'+format.toLowerCase()))
    }
    assert((await fs.readFile(path.join(output,'eye-fixture.png'))).subarray(1,4).equals(Buffer.from('PNG')))
    assert.equal(JSON.parse(await fs.readFile(path.join(output,'eye-fixture.json'),'utf8')).source,'simulator')
    const canvasElement=await graph.elementHandle()
    await page.getByRole('button',{name:'放大端口详情',exact:true}).click()
    await inspector.waitFor()
    assert(await canvasElement.evaluate(el=>el===document.querySelector('.port-inspector-dialog .eye-diagram>canvas')),'the acquired canvas survives enlarging')
    assert.equal(await optics.getByRole('button',{name:'查看 Lane 2 光学诊断',exact:true}).getAttribute('aria-pressed'),'true')
    const columns=await optics.evaluate(el=>{
      const status=el.querySelector('.optics-signal-column').getBoundingClientRect(),eye=el.querySelector('.optics-eye-column').getBoundingClientRect()
      return {sideBySide:eye.left>=status.right,aligned:Math.abs(eye.top-status.top)<1}
    })
    assert(columns.sideBySide&&columns.aligned,'a wide inspector places signal state next to the eye diagram')
    await inspector.screenshot({path:path.join(output,'inspector-optics-desktop.png')})
    await eyePanel.getByRole('button',{name:'放大眼图',exact:true}).click();await big.waitFor()
    await page.keyboard.press('Escape');await big.waitFor({state:'hidden'})
    assert(await inspector.isVisible(),'Escape closes only the nested eye dialog')
    await inspector.getByRole('button',{name:'回到卡片',exact:true}).click()
    await inspector.waitFor({state:'hidden'})
    assert(await canvasElement.evaluate(el=>el===document.querySelector('#epl-box-5 .eye-diagram>canvas')),'returning restores the existing eye canvas to its EPL')
    checks.push('resizing retains Lane, running scan and acquired canvas; wide optical columns and nested eye Escape')
    await eyePanel.getByRole('combobox',{name:'眼图信号来源',exact:true}).selectOption('internal_loopback')
    await eyePanel.getByRole('button',{name:'开始采集',exact:true}).click()
    assert.equal(eye.signal_source,'internal_prbs31_loopback')
    assert.match(await eyePanel.innerText(),/内部 PRBS31 回环/)
    await eyePanel.getByRole('button',{name:'取消',exact:true}).click()
    await eyePanel.locator('.tag').filter({hasText:'已取消'}).waitFor()
    assert.deepEqual(writes,['/api/v1/optics/ports/13/eye','/api/v1/optics/ports/13/eye','/api/v1/optics/eyes/'+eye.id+'/cancel'])
    if(process.env.FM10K_EYE_CAPTURE) {
      eye=JSON.parse(await fs.readFile(process.env.FM10K_EYE_CAPTURE,'utf8'))
      eyeAll=eye.errors
      assert.equal(eye.source,'serdes-hardware')
      assert.equal(eye.state,'complete')
      await showPort(eye.port)
      if(eye.lane) await optics.getByRole('button',{name:'查看 Lane '+eye.lane+' 光学诊断',exact:true}).click()
      await eyePanel.locator('.tag').filter({hasText:'采集完成'}).waitFor()
      if(eye.signal_source==='internal_prbs31_loopback') assert.match(await eyePanel.innerText(),/内部 PRBS31 回环/)
      await eyePanel.getByRole('button',{name:'放大眼图',exact:true}).click()
      await big.waitFor();await big.screenshot({path:path.join(output,'eye-hardware-expanded.png')})
      await big.getByRole('button',{name:'关闭',exact:true}).click()
      const downloaded=page.waitForEvent('download')
      await eyePanel.getByRole('button',{name:'导出 PNG',exact:true}).click()
      await (await downloaded).saveAs(path.join(output,'eye-hardware.png'))
    }
    assert.deepEqual(errors,[])
    checks.push('eye start, progress, 2D heatmap, sample hover, enlarged chart, PNG/CSV/JSON and cancellation')

    await fs.writeFile(path.join(output,'report.json'),JSON.stringify({passed:true,checks,layouts,requests,writes,errors},null,2)+'\n')
    console.log(JSON.stringify({passed:true,checks,layouts,requests:requests.length},null,2))
  } catch(error) {
    await page.screenshot({path:path.join(output,'failure.png'),fullPage:true}).catch(()=>{})
    await fs.writeFile(path.join(output,'failure.json'),JSON.stringify({message:error.message,errors,requests,layouts},null,2)+'\n')
    throw error
  } finally {
    await browser.close()
  }
})().catch(error=>{console.error(error);process.exitCode=1})
