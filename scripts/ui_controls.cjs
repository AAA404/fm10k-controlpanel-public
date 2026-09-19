/* New controls against HTTP fixtures. No switch or GitHub network is contacted. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')

;(async () => {
  const root = path.resolve(__dirname, '..'), output = path.join(root, 'artifacts/ui-controls')
  const seed = spawnSync(process.env.FM10K_PYTHON || 'python3', ['-c',
    'from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
  { cwd: root, env: { ...process.env, PYTHONPATH: path.join(root, 'backend') }, encoding: 'utf8' })
  assert.equal(seed.status, 0, seed.stderr)
  const configuration = JSON.parse(seed.stdout), errors = [], epls = [0,1,2,5,6,7]
  const stamp = () => Date.now()/1000
  const base = 'http://127.0.0.1:18114'
  let previewRequest
  const writes = []
  const updates = { enabled:false,state:'reserved',current_version:'0.1.0~rc3' }
  const browser = await chromium.launch({ headless:true,
    ...(process.env.FM10K_BROWSER_CHANNEL ? { channel:process.env.FM10K_BROWSER_CHANNEL } : {}) })
  try {
    const page = await browser.newPage({ viewport:{width:1440,height:1080}, locale:'zh-CN' })
    page.setDefaultTimeout(15000)
    page.on('pageerror', e => errors.push(e.message))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== base) return route.abort()
      if (request.method() !== 'GET') writes.push(url.pathname)
      const send = (body,status=200) => route.fulfill({status,contentType:'application/json',body:JSON.stringify(body)})
      switch (url.pathname) {
        case '/api/v1/auth/session': return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:'mock'})
        case '/api/v1/capabilities': return send({mode:'mock',version:'0.1.0~rc3',profile:configuration.profile})
        case '/api/v1/config': return send({configuration,revision:7,pending:null})
        case '/api/v1/updates': return send(updates)
        case '/api/v1/system': return send({version:'0.1.0~rc3',backend:'mock'})
        case '/api/v1/system/time': return send({available:true,provider:'simulator',state:'simulated',enabled:false,synchronized:false,
          server_time:stamp(),timezone:'UTC',servers:[],selected_server:null,server_address:null,last_synchronized_at:null,message:'模拟时间状态'})
        case '/api/v1/telemetry':
          return send({ports:Array.from({length:24}, (_,i) => ({id:i+1,epl:epls[Math.floor(i/4)],mpo:i<12?1:2,lane:i%4,
            active:i%4===0,name:'',enabled:i%4===0,speed_gbps:i%4===0?100:0,scheduler_speed_gbps:i%4===0?96:0,
            ethernet_mode:i%4===0?'100GBase-SR4':'DISABLED',link:i%4===0?'up':'down',quality:'simulated',sampled_at:stamp(),
            rx_bytes:1024,tx_bytes:4096,rx_packets:16,tx_packets:32,rx_errors:0,tx_errors:0,crc_errors:0,rx_drops:0,tx_drops:0})),
            sensors:{quality:'simulated',sampled_at:stamp(),temperatures:[
              {id:'fm10840_core',label:'FM10840 核心',celsius:49,source:'LM96163',quality:'simulated',sampled_at:stamp()},
              {id:'atom_cpu',label:'Intel Atom CPU',celsius:43.5,source:'Linux coretemp · Package id 0',quality:'simulated',sampled_at:stamp()}],
              fan:{pwm_percent:57,rpm:1800,quality:'simulated',mode:'hardware_lut'}},optics:[]})
        case '/api/v1/config/preview':
          previewRequest = request.postDataJSON()
          return send({id:'fixture',changes:[{path:'/fan',before:configuration.fan,after:previewRequest.configuration.fan}],affected_epls:[]})
      }
      if (url.pathname.startsWith('/api/')) throw new Error('Unexpected request: '+url.pathname)
      const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({contentType:relative.endsWith('.js')?'text/javascript':relative.endsWith('.css')?'text/css':'text/html',
        body:await fs.readFile(path.join(root,'frontend/dist',relative))})
    })
    await fs.mkdir(output,{recursive:true})
    await page.goto(base)
    await page.getByRole('heading',{name:'设备概览',exact:true}).waitFor()
    assert(await page.getByText('Intel Atom CPU').count() >= 1)
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    assert.equal(await page.locator('.obt-port-section').count(),2)
    assert.equal(await page.locator('.epl-box').count(),6)
    assert.equal(await page.locator('.port-tile').count(),24)
    for (let i=0;i<6;++i) {
      const box = page.locator('#epl-box-'+epls[i])
      for (let lane=0;lane<4;++lane) assert.equal(await box.locator('#port-tile-'+(i*4+lane+1)).count(),1)
    }
    await page.screenshot({path:path.join(output,'ports-grouped.png'),fullPage:true})
    await page.getByRole('button',{name:'查看端口 P17，OBT 2，EPL 6',exact:true}).click()
    const detail = page.locator('#port-details-6')
    await detail.getByRole('heading',{name:'P17 · 端口详情',exact:true}).waitFor()
    assert.equal(await page.locator('.epl-box.expanded').count(),1)
    assert.match(await detail.innerText(),/100 Gbps/)
    assert.match(await detail.innerText(),/96 Gbps/)
    assert.equal(await detail.locator('input,select,textarea').count(),0,'expanded details are read-only')
    await detail.getByRole('tab',{name:'收发统计',exact:true}).click()
    assert.match(await detail.innerText(),/CRC \/ FCS 错误/)
    await detail.getByRole('tab',{name:'收发统计',exact:true}).press('ArrowRight')
    assert.equal(await detail.getByRole('tab',{name:'VLAN 状态',exact:true}).getAttribute('aria-selected'),'true')

    // Sample real browser frames during interrupted enter/leave transitions. Sibling
    // rectangles must never overlap, and outgoing content must not steal tile hits.
    const animation = await page.evaluate(async () => {
      const actions = [1,5,13,17,18,18,18,9,9,24,17]
      const violations = [], started = performance.now()
      let frames = 0, next = 0
      while (performance.now()-started < 1500) {
        await new Promise(requestAnimationFrame)
        const elapsed = performance.now()-started
        if (next < actions.length && elapsed >= next*65) document.getElementById('port-tile-'+actions[next++]).click()
        const cards = [...document.querySelectorAll('.epl-box')].filter(card => card.getBoundingClientRect().height > 0)
        for (let a=0;a<cards.length;a++) for (let b=a+1;b<cards.length;b++) {
          const first = cards[a].getBoundingClientRect(), second = cards[b].getBoundingClientRect()
          if (Math.min(first.right,second.right)-Math.max(first.left,second.left)>1 && Math.min(first.bottom,second.bottom)-Math.max(first.top,second.top)>1)
            violations.push('overlapping cards: '+cards[a].id+' / '+cards[b].id)
        }
        for (const tile of document.querySelectorAll('.port-tile')) {
          const bounds = tile.getBoundingClientRect(), x = bounds.x+bounds.width/2, y = bounds.y+bounds.height/2
          if (x < 0 || x >= innerWidth || y < 70 || y >= innerHeight-100) continue
          const hit = document.elementFromPoint(x,y)
          if (hit?.closest('.expanded-port-detail') && !tile.closest('.epl-box').contains(hit)) violations.push('detail covers '+tile.id)
        }
        frames++
      }
      const card = document.querySelector('.epl-box.expanded').getBoundingClientRect()
      return {frames,actions:next,violations,areaRatio:card.width*card.height/(innerWidth*innerHeight),heightRatio:card.height/innerHeight}
    })
    assert(animation.frames >= 20,'animation must be checked across browser frames')
    assert.equal(animation.actions,11)
    assert.deepEqual(animation.violations,[])
    assert(animation.areaRatio <= .26,'expanded EPL should occupy at most about one quarter of the desktop')
    assert(animation.heightRatio <= .51,'desktop detail height should stay within half the viewport')
    await detail.getByRole('heading',{name:'P17 · 端口详情',exact:true}).waitFor()
    assert.equal(await page.locator('.expanded-port-detail').count(),1,'rapid switching must settle on one detail panel')
    await page.getByRole('button',{name:'设置端口 P17',exact:true}).click()
    const settings = page.getByRole('dialog')
    await settings.getByLabel('端口组模式',{exact:true}).selectOption('split')
    await settings.getByLabel('PVID / Native VLAN',{exact:true}).selectOption('1')
    await settings.getByLabel('配置端口',{exact:true}).selectOption('18')
    assert.equal(await settings.getByLabel('管理启用 / 光发射启用',{exact:true}).isChecked(),false)
    await settings.getByLabel('用户名称',{exact:true}).fill('未提交子口名称')
    await page.screenshot({path:path.join(output,'port-settings.png')})
    await settings.getByRole('button',{name:'完成设置',exact:true}).click()
    assert.equal(await detail.getByText('待提交',{exact:true}).count(),1)
    const pvid = detail.locator('.port-runtime-grid > div').filter({has:page.getByText('PVID / Native VLAN',{exact:true})})
    assert.equal(await pvid.locator('strong').innerText(),'未配置','unapplied VLAN membership must not appear in status')
    await page.getByRole('button',{name:'设置端口 P17',exact:true}).click()
    assert.equal(await settings.getByLabel('端口组模式',{exact:true}).inputValue(),'split')
    await settings.getByLabel('配置端口',{exact:true}).selectOption('18')
    assert.equal(await settings.getByLabel('用户名称',{exact:true}).inputValue(),'未提交子口名称')
    await settings.getByRole('button',{name:'关闭端口设置',exact:true}).focus()
    await page.keyboard.press('Shift+Tab')
    assert.equal(await settings.getByRole('button',{name:'完成设置',exact:true}).evaluate(element => element === document.activeElement),true,'native dialog traps keyboard focus')
    await page.keyboard.press('Escape')
    await settings.waitFor({state:'detached'})
    assert.equal(await page.getByRole('button',{name:'设置端口 P17',exact:true}).evaluate(element => element === document.activeElement),true)
    await detail.getByRole('tab',{name:'端口详情',exact:true}).click()
    await page.screenshot({path:path.join(output,'port-expanded.png'),fullPage:true})
    await page.screenshot({path:path.join(output,'port-detail-desktop.png')})
    await page.getByRole('button',{name:'收起端口详情',exact:true}).click()
    await detail.waitFor({state:'detached'})
    await page.waitForFunction(() => !document.querySelector('.epl-box.expanded'))
    assert.equal(await page.locator('#port-tile-17').evaluate(element => element === document.activeElement),true)
    await page.getByRole('button',{name:'设置端口 P1',exact:true}).click()
    assert.equal(await page.locator('.epl-box.expanded').count(),0,'settings can open independently of details')
    await page.keyboard.press('Escape')
    await page.locator('.save-bar').getByRole('button',{name:'丢弃修改',exact:true}).click()

    await page.getByRole('button',{name:'温度与风扇',exact:true}).click()
    assert(await page.getByText('Intel Atom CPU').count() >= 1)
    const chart = page.locator('.fan-curve-editor')
    const handle = chart.getByRole('slider',{name:'负载折点，左右键调温度，上下键调PWM',exact:true})
    const bounds = await handle.boundingBox()
    const before = await handle.getAttribute('aria-valuetext')
    await page.mouse.move(bounds.x+bounds.width/2,bounds.y+bounds.height/2)
    await page.mouse.down()
    await page.mouse.move(bounds.x+bounds.width/2+24,bounds.y+bounds.height/2+14,{steps:5})
    await page.mouse.up()
    assert.notEqual(await handle.getAttribute('aria-valuetext'),before,'drag must update curve coordinates')
    await chart.getByLabel('负载点温度',{exact:true}).fill('72')
    await chart.getByLabel('负载点温度',{exact:true}).press('Tab')
    assert.match(await handle.getAttribute('aria-valuetext'),/^72摄氏度/)
    await chart.locator('.curve-tabs button').nth(0).click()
    await chart.getByLabel('闲置点PWM',{exact:true}).fill('10')
    await chart.getByLabel('闲置点PWM',{exact:true}).press('Tab')
    assert.equal(await chart.getByLabel('闲置点PWM',{exact:true}).inputValue(),'25')
    await chart.locator('.curve-tabs button').nth(2).click()
    assert.equal(await chart.getByLabel('满速点PWM',{exact:true}).isDisabled(),true)
    await page.screenshot({path:path.join(output,'fan-curve-desktop.png'),fullPage:true})
    await page.getByRole('button',{name:'预览并校验',exact:true}).click()
    await page.getByRole('heading',{name:'检查配置变更',exact:true}).waitFor()
    assert.equal(previewRequest.configuration.fan.idle_speed_percent,25)
    assert.equal(previewRequest.configuration.fan.load_temperature_c,72)
    await page.getByRole('button',{name:'返回编辑',exact:true}).click()
    await page.locator('.save-bar').getByRole('button',{name:'丢弃修改',exact:true}).click()
    await page.setViewportSize({width:390,height:844})
    await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 0)
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),'fan chart mobile overflow')
    await chart.locator('.curve-tabs button').nth(1).click()
    await page.screenshot({path:path.join(output,'fan-curve-mobile.png'),fullPage:true})
    await page.getByRole('button',{name:'展开导航',exact:true}).click()
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    await page.getByRole('button',{name:'查看端口 P5，OBT 1，EPL 1',exact:true}).click()
    await page.waitForFunction(() => !document.querySelector('.port-expand-enter-active, .port-expand-leave-active'))
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),'expanded port mobile overflow')
    await page.screenshot({path:path.join(output,'ports-mobile.png'),fullPage:true})
    await page.screenshot({path:path.join(output,'port-detail-mobile.png')})
    await page.getByRole('button',{name:'设置端口 P5',exact:true}).click()
    assert(await settings.evaluate(element => {
      const bounds = element.getBoundingClientRect()
      return bounds.left >= 0 && bounds.right <= innerWidth && bounds.top >= 0 && bounds.bottom <= innerHeight && element.scrollWidth <= element.clientWidth
    }),'settings dialog fits the mobile viewport')
    await page.screenshot({path:path.join(output,'port-settings-mobile.png')})
    await page.keyboard.press('Escape')
    const responsive = []
    for (const width of [320,834,1024,1280]) {
      await page.setViewportSize({width,height:900})
      await page.waitForFunction(() => document.documentElement.scrollWidth <= innerWidth)
      const metrics = await page.locator('#port-details-1 .port-detail-body').evaluate(element => ({width:innerWidth,height:element.clientHeight,overflow:document.documentElement.scrollWidth>innerWidth}))
      assert(metrics.height >= 80,'read-only content must remain usable at '+width+'px')
      assert.equal(metrics.overflow,false)
      responsive.push(metrics)
    }
    await page.emulateMedia({reducedMotion:'reduce'})
    await page.locator('#port-tile-9').click()
    await page.locator('#port-details-2').waitFor()
    await page.locator('#port-tile-9').click()
    await page.waitForFunction(() => !document.querySelector('.expanded-port-detail') && !document.querySelector('.epl-box.expanded'))
    await page.emulateMedia({reducedMotion:'no-preference'})
    await page.setViewportSize({width:1440,height:1080})
    await page.getByRole('button',{name:'系统与维护',exact:true}).click()
    const ota = page.locator('.ota-updates')
    assert.equal(await ota.getByRole('button',{name:'在线升级尚未启用',exact:true}).isDisabled(),true)
    assert.equal(await ota.locator('input').count(),0,'no private credential configuration')
    assert.equal(await page.getByRole('button',{name:'导出备份',exact:true}).count(),0)
    assert.match(await ota.innerText(),/待项目公开后接入/)
    await page.screenshot({path:path.join(output,'maintenance-reserved.png'),fullPage:true})
    await ota.getByRole('button',{name:'查看备份中心',exact:true}).click()
    assert.equal(await page.getByRole('button',{name:'导出备份',exact:true}).count(),1)
    assert.deepEqual(writes,['/api/v1/config/preview'],'reserved OTA must issue no write or credential requests')
    assert.deepEqual(errors,[])
    const report = {passed:true,real_network:false,hardware_access:false,animation,responsive,checks:[
      'two OBT and six EPL groups map all 24 logical slots','compact read-only status, statistics, VLAN and optics tabs',
      'interrupted transitions do not overlap sibling cards or intercept their tiles','expanded desktop area stays below one quarter of the viewport',
      'separate settings dialog preserves drafts and traps/restores keyboard focus','VLAN status retains applied values during draft edits',
      'settings work with details collapsed','reduced-motion expand and same-port collapse',
      'new breakout children remain disabled','Atom temperature on overview and thermal pages',
      'fan pointer drag and bounded numeric coordinates','critical point stays full speed',
      'mobile port and curve layout','OTA reserved until repository is public',
      'no private credential or installation controls','unified configuration backup entry']}
    await fs.writeFile(path.join(output,'ui-report.json'),JSON.stringify(report,null,2)+'\n')
    console.log(JSON.stringify(report))
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode=1 })
