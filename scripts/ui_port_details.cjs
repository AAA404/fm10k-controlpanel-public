/* Compact port details and inline rates against intercepted HTTP fixtures only. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')

;(async () => {
  const root = path.resolve(__dirname, '..'), output = path.join(root,'artifacts/port-details')
  const python = process.env.FM10K_PYTHON || 'python3'
  const env = {...process.env,PYTHONPATH:path.join(root,'backend')}
  const seed = spawnSync(python,['-c',`
from fm10k_controlpanel.models import SwitchConfiguration
c = SwitchConfiguration().model_dump(mode='json')
c['vlans'] = [{'id': v, 'name': name} for v,name in [(1,'管理网络'),(10,'业务网络'),(20,'访客网络与终端隔离'),(30,'')]]
for index, group in enumerate(c['groups']):
    group['mode'] = 'split' if index < 2 else '40g'
    group['lane_speeds'] = [25,25,25,25]
    for lane in range(4):
        p = c['ports'][str(index*4+lane+1)]
        p['enabled'] = index < 2 or lane == 0
        p['pvid'] = 1 if p['enabled'] else None
    c['ports'][str(index*4+1)]['name'] = 'MPO%d-EPL%d-100G' % (1 if index < 3 else 2, group['epl'])
c['ports']['1'].update(vlan_mode='trunk',tagged_vlans=[10,20])
c['ports']['5']['pvid'] = 30
print(SwitchConfiguration.model_validate(c).model_dump_json())
`],{cwd:root,env,encoding:'utf8'})
  assert.equal(seed.status,0,seed.stderr)
  const configuration = JSON.parse(seed.stdout), errors = [], writes = [], layouts = [], cardClicks = [], positions = [], resizes = [], freshnessChecks = [], rateGeometry = []
  const base = 'http://127.0.0.1:18116'
  let previewRequest, readOnly = false
  let sampleSerial = 0
  let sampleOptions = {age:0,offset:0,quality:'simulated',stateQuality:'valid',counterQuality:'valid',link:'down',error:null,fail:false,empty:false}
  const browser = await chromium.launch({headless:true,
    ...(process.env.FM10K_BROWSER_CHANNEL ? {channel:process.env.FM10K_BROWSER_CHANNEL} : {})})
  const page = await browser.newPage({viewport:{width:1440,height:1080},locale:'zh-CN'})
  page.setDefaultTimeout(12000)
  page.on('pageerror',error => errors.push(error.message))
  await fs.mkdir(output,{recursive:true})
  try {
    const handleRoute = async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== base) return route.abort()
      const send = body => route.fulfill({contentType:'application/json',body:JSON.stringify(body)})
      if (request.method() !== 'GET') writes.push(url.pathname)
      switch(url.pathname) {
        case '/api/v1/auth/session': return send({initialized:true,authenticated:true,username:'fixture',csrf:'fixture',mode:readOnly?'netlab':'mock'})
        case '/api/v1/capabilities': return send({mode:readOnly?'netlab':'mock',version:'0.1.0~rc7',profile:configuration.profile})
        case '/api/v1/config': return send({configuration,revision:24,pending:null})
        case '/api/v1/updates': return send({enabled:false,state:'reserved'})
        case '/api/v1/telemetry': {
          if(sampleOptions.fail) return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:'测试：遥测请求失败',fixture_case:sampleSerial})})
          const serverNow=Date.now()/1000+sampleOptions.offset
          return send({fixture_case:sampleSerial,server_time:serverNow,port_sample_interval_seconds:1,port_stale_after_seconds:3,error:sampleOptions.error,
            ports:sampleOptions.empty?[]:Array.from({length:24},(_,index) => {
          const group = configuration.groups[Math.floor(index/4)], active = group.mode === 'split' || index%4 === 0
          const rate = active ? group.mode === 'split' ? group.lane_speeds[index%4] : 40 : 0
          return {id:index+1,epl:group.epl,mpo:index<12?1:2,lane:index%4,active,enabled:active,
            name:configuration.ports[index+1].name,speed_gbps:rate,scheduler_speed_gbps:rate,
            ethernet_mode:active?rate+'GBase-SR':'DISABLED',link:sampleOptions.link,quality:sampleOptions.quality,sampled_at:serverNow-sampleOptions.age,
            state_quality:sampleOptions.stateQuality,counter_quality:sampleOptions.counterQuality,
            rx_bytes:123456789012345,tx_bytes:4096,rx_packets:16,tx_packets:32,rx_errors:0,tx_errors:0,crc_errors:null,rx_drops:0,tx_drops:0}
        }),sensors:{temperatures:[],fan:{},quality:'simulated'},optics:[]})
        }
        case '/api/v1/config/preview': {
          previewRequest = request.postDataJSON()
          const checked = spawnSync(python,['-c','import sys; from fm10k_controlpanel.models import Proposal; Proposal.model_validate_json(sys.stdin.read())'],
            {cwd:root,env,encoding:'utf8',input:JSON.stringify(previewRequest)})
          assert.equal(checked.status,0,checked.stderr)
          return send({id:'rate-preview',affected_epls:[0,2],changes:[{path:'/groups',before:configuration.groups,after:previewRequest.configuration.groups}]})
        }
      }
      assert(!url.pathname.startsWith('/api/'),'Unexpected request: '+url.pathname)
      const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({contentType:relative.endsWith('.js')?'text/javascript':relative.endsWith('.css')?'text/css':'text/html',
        body:await fs.readFile(path.join(root,'frontend/dist',relative))})
    }
    await page.route('**/*',handleRoute)
    await page.goto(base)
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    async function clickCard(id, part) {
      await page.waitForFunction(() => !document.querySelector('.port-expand-enter-active,.port-expand-leave-active'))
      const tile = page.locator('#port-tile-'+id).locator('..')
      await tile.scrollIntoViewIfNeeded()
      const point = await tile.evaluate((element,part) => {
        const bounds = element.getBoundingClientRect()
        const target = part === 'state' ? element.querySelector('.port-tile-state') : part === 'name' ? element.querySelector('.port-tile-name') : part === 'speed' ? element.querySelector('.port-tile-speed') : null
        if (target) {
          const rect=target.getBoundingClientRect()
          if (!rect.width || !rect.height) throw new Error('Cannot click hidden '+part)
          return {x:rect.left+Math.min(12,rect.width/2),y:rect.top+rect.height/2}
        }
        return {x:bounds.left+12,y:part==='header'?bounds.top+18:bounds.bottom-8}
      },part)
      await page.mouse.move(point.x,point.y)
      const hit = await page.evaluate(async point => {
        await new Promise(requestAnimationFrame); await new Promise(requestAnimationFrame)
        const element=document.elementFromPoint(point.x,point.y)
        const button=element?.closest('button')
        return {tag:element?.tagName,button:button?.id || null,filter:button?getComputedStyle(button).filter:null}
      },point)
      await page.mouse.click(point.x,point.y)
      await page.evaluate(async () => {await new Promise(requestAnimationFrame);await new Promise(requestAnimationFrame)})
      const selected=await page.locator('#port-tile-'+id).getAttribute('aria-expanded')
      cardClicks.push({id,part,hit,selected})
      await fs.writeFile(path.join(output,'card-click-report.json'),JSON.stringify(cardClicks,null,2)+'\n')
      assert.equal(selected,'true','clicking '+part+' of P'+id+' must select that port: '+JSON.stringify(hit))
    }
    for (const [id,part] of [[1,'state'],[1,'name'],[2,'bottom']]) {
      await clickCard(id,part)
      await page.getByRole('button',{name:'收起端口详情',exact:true}).click()
      await page.waitForFunction(() => !document.querySelector('.epl-box.expanded'))
    }
    await clickCard(2,'bottom')
    await page.locator('#port-tile-1').click()
    const detail = page.locator('#port-details-0')
    await require('./check_port_inspector.cjs')(page,output,writes)
    await detail.getByRole('tab',{name:'VLAN 状态',exact:true}).click()
    const nativeVlan = inspector => inspector.locator('.port-vlan-grid>div').filter({has:page.getByText('PVID / Native VLAN',{exact:true})})
    assert.equal(await nativeVlan(detail).locator('strong').innerText(),'1 · 管理网络')
    assert.deepEqual(await detail.locator('.port-vlan-memberships li').allTextContents(),['10 · 业务网络','20 · 访客网络与终端隔离'])
    await page.locator('#port-tile-5').click()
    assert.equal(await nativeVlan(page.locator('#port-details-1')).locator('strong').innerText(),'30 · 未命名')
    await page.locator('#port-tile-10').click()
    assert.equal(await nativeVlan(page.locator('#port-details-2')).locator('strong').innerText(),'未配置')
    assert.equal(await page.locator('#port-details-2 .port-vlan-memberships').count(),0)
    await page.locator('#port-tile-1').click()
    await detail.getByRole('tab',{name:'端口详情',exact:true}).click()
    for (const viewport of [{width:1440,height:1080},{width:1050,height:900},{width:2193,height:1435},{width:1920,height:2160}]) {
      await page.setViewportSize(viewport)
      await page.getByRole('button',{name:'收起端口详情',exact:true}).click()
      await page.waitForFunction(() => !document.querySelector('.port-expand-enter-active,.port-expand-leave-active,.epl-box.expanded'))
      const baseline = await page.evaluate(() => {
        const origin=document.querySelector('.port-groups-view').getBoundingClientRect()
        return [...document.querySelectorAll('.epl-box')].map(card => {const b=card.getBoundingClientRect();return {id:card.id,x:b.x-origin.x,y:b.y-origin.y,width:b.width,height:b.height}})
      })
      for (const port of [1,5,9,13,17,21]) {
        await page.locator('#port-tile-'+port).click()
        const frames=await page.evaluate(async () => {
          const frames=[]
          for(let i=0;i<16;i++) {
            await new Promise(requestAnimationFrame)
            const origin=document.querySelector('.port-groups-view').getBoundingClientRect()
            frames.push([...document.querySelectorAll('.epl-box')].map(card=>{const b=card.getBoundingClientRect();return {id:card.id,x:b.x-origin.x,y:b.y-origin.y,width:b.width,height:b.height}}))
          }
          return frames
        })
        for(const frame of frames) for(let i=0;i<baseline.length;i++) for(const key of ['x','y','width','height'])
          assert(Math.abs(frame[i][key]-baseline[i][key])<1,'opening P'+port+' moved '+baseline[i].id+' '+key)
        positions.push({viewport,port,stable:true})
        if(port===17&&viewport.width===1440) await page.locator('.obt-port-section').nth(1).screenshot({path:path.join(output,'epl6-details-in-place.png')})
      }
      await page.locator('#port-tile-1').click()
      for (const tab of ['端口详情','收发统计','VLAN 状态']) {
        await detail.getByRole('tab',{name:tab,exact:true}).click()
        await page.waitForFunction(() => !document.querySelector('.port-expand-enter-active,.port-expand-leave-active'))
        await detail.evaluate(async element => { await Promise.all(element.closest('.epl-box').getAnimations({subtree:true}).map(animation => animation.finished.catch(() => {}))) })
        const metrics = await detail.evaluate(element => {
          const card = element.closest('.epl-box'), section = card.closest('.obt-port-section'), body = element.querySelector('.port-detail-body')
          const bounds = card.getBoundingClientRect(), sectionBounds = section.getBoundingClientRect(), bodyBounds = body.getBoundingClientRect()
          const bottom = Math.max(...[...section.querySelectorAll('.epl-box')].map(box => box.getBoundingClientRect().bottom))
          const cardStyle = getComputedStyle(card), sectionStyle = getComputedStyle(section)
          return {width:innerWidth,height:innerHeight,cardHeight:bounds.height,areaRatio:bounds.width*bounds.height/(innerWidth*innerHeight),
            cardTail:bounds.bottom-parseFloat(cardStyle.paddingBottom)-Math.min(bodyBounds.bottom,body.lastElementChild.getBoundingClientRect().bottom),
            sectionTail:sectionBounds.bottom-bottom-parseFloat(sectionStyle.paddingBottom)-parseFloat(sectionStyle.borderBottomWidth),
            horizontalOverflow:document.documentElement.scrollWidth>innerWidth}
        })
        layouts.push({tab,...metrics})
        await fs.writeFile(path.join(output,'layout-report.json'),JSON.stringify(layouts,null,2)+'\n')
        assert(metrics.sectionTail <= 4,'unused space below EPL grid: '+JSON.stringify(metrics))
        assert(metrics.areaRatio <= .26,'expanded card exceeds a quarter screen')
        assert.equal(metrics.horizontalOverflow,false)
        if (viewport.width === 2193) await page.locator('.obt-port-section').first().screenshot({path:path.join(output,tab+'.png')})
      }
    }
    await page.locator('#port-tile-17').click()
    const resizedDetail = page.locator('#port-details-6')
    await resizedDetail.getByRole('tab',{name:'端口详情',exact:true}).click()
    for (const viewport of [{width:1440,height:1080},{width:1280,height:720},{width:1101,height:760},
      {width:1050,height:900},{width:900,height:700},{width:761,height:650},{width:700,height:700},
      {width:390,height:844},{width:320,height:844},{width:1440,height:1080}]) {
      await page.setViewportSize(viewport)
      await resizedDetail.scrollIntoViewIfNeeded()
      const metrics = await resizedDetail.evaluate(async element => {
        await new Promise(requestAnimationFrame)
        const card=element.closest('.epl-box'), body=element.querySelector('.port-detail-body')
        body.scrollTop=0
        const bounds=body.getBoundingClientRect(), selector=card.querySelector('.port-tile-grid')
        const fields=[...body.querySelectorAll('.port-runtime-grid>div')]
        const cards=[...document.querySelectorAll('.epl-box')].map(card=>card.getBoundingClientRect())
        const heading=[...card.querySelectorAll('.epl-label-chip,.epl-box-heading>.tag,.port-settings-trigger,.epl-box-heading>.icon-button')]
          .map(item=>item.getBoundingClientRect()).filter(rect=>rect.width)
        return {width:innerWidth,height:innerHeight,cardWidth:card.getBoundingClientRect().width,
          selectorHeight:selector.getBoundingClientRect().height,detailHeight:bounds.height,
          headingOverlaps:heading.some((rect,index)=>heading.slice(index+1).some(next=>rect.right>next.left)),
          visibleFields:fields.filter(field=>{const b=field.getBoundingClientRect();return b.top>=bounds.top&&b.bottom<=bounds.bottom}).length,
          cardsOverlap:cards.some((a,i)=>cards.slice(i+1).some(b=>a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top)),
          horizontalOverflow:document.documentElement.scrollWidth>innerWidth||body.scrollWidth>body.clientWidth+1,
          tilesOverflow:[...selector.children].some(tile=>tile.scrollWidth>tile.clientWidth+1),
          separateRateAction:!selector.querySelector('.port-rate-trigger,.port-speed-select') &&
            card.querySelector('.port-detail-rate-trigger').getBoundingClientRect().top>=selector.getBoundingClientRect().bottom}
      })
      resizes.push(metrics)
      await fs.writeFile(path.join(output,'resize-report.json'),JSON.stringify(resizes,null,2)+'\n')
      assert.equal(await page.locator('#port-tile-17').getAttribute('aria-expanded'),'true','resizing must retain the selected port')
      assert(metrics.selectorHeight<=50,'expanded selectors must fit the requested two-line height: '+JSON.stringify(metrics))
      assert(metrics.detailHeight>=160,'resizing must preserve a readable detail area: '+JSON.stringify(metrics))
      assert(metrics.visibleFields>=4,'at least the first four fields must be fully visible: '+JSON.stringify(metrics))
      assert.equal(metrics.cardsOverlap,false,'EPL cards must stay in separate grid cells after resizing')
      assert.equal(metrics.headingOverlaps,false,'EPL identity and header actions must remain separate')
      assert.equal(metrics.horizontalOverflow,false)
      assert.equal(metrics.tilesOverflow,false,'compact selector content must fit at every grid breakpoint')
      assert(metrics.separateRateAction,'speed text and the explicit rate action must not overlap')
      if ([1440,1101,320].includes(viewport.width)) await page.locator('#epl-box-6').screenshot({path:path.join(output,'resized-epl6-'+viewport.width+'.png')})
    }
    await page.setViewportSize({width:1440,height:1080})
    await page.locator('#port-tile-1').click()
    const rate = id => page.getByRole('combobox',{name:'P'+id+' 端口速率',exact:true})
    const trigger = id => page.getByRole('button',{name:'调整 P'+id+' 速率',exact:true})
    const shownRate = id => page.locator('#port-tile-'+id+' .port-tile-speed')
    const editor = id => page.getByRole('group',{name:'P'+id+' 速率调整',exact:true})
    async function beginRate(id) {
      await trigger(id).click();await rate(id).waitFor()
      assert(await editor(id).evaluate(element => {
        const tile=element.closest('.port-tile'), box=element.closest('.epl-box'), bounds=element.getBoundingClientRect()
        const above=tile?tile.querySelector('.port-tile-heading'):box.querySelector('.port-tile-grid')
        return bounds.top>=above.getBoundingClientRect().bottom && bounds.left>=box.getBoundingClientRect().left && bounds.right<=box.getBoundingClientRect().right
      }),'rate editor must stay inside the EPL and below its port selection target')
    }
    async function stageRate(id,value) {
      await beginRate(id)
      await rate(id).selectOption(value)
      await editor(id).getByRole('button',{name:'暂存',exact:true}).click()
      await editor(id).waitFor({state:'detached'})
    }
    for (const [id,part] of [[2,'bottom'],[1,'speed'],[2,'speed'],[1,'header'],[2,'header'],[1,'bottom']]) await clickCard(id,part)
    assert.equal(await page.locator('.port-speed-select').count(),0,'viewing any card region must not expose speed inputs')
    assert.equal(await trigger(10).count(),0,'merged child slots cannot adjust speed independently')
    await beginRate(1)
    assert.deepEqual(await rate(1).locator('option').allTextContents(),['10G','25G'])
    assert(await editor(1).getByRole('button',{name:'暂存',exact:true}).isDisabled(),'opening the editor does not stage a change')
    await rate(1).selectOption('10')
    assert.equal(await page.locator('.save-bar').count(),0,'choosing a rate alone must not modify the shared draft')
    assert.equal(await page.locator('#port-tile-1').getAttribute('aria-expanded'),'true')
    await editor(1).getByRole('button',{name:'取消',exact:true}).click()
    assert.equal(await shownRate(1).innerText(),'25G')
    await beginRate(1)
    await rate(1).selectOption('10')
    await page.keyboard.press('Escape')
    await editor(1).waitFor({state:'detached'})
    assert.equal(await page.locator('#port-tile-1').getAttribute('aria-expanded'),'true','Escape cancels rate editing without closing details')
    assert(await trigger(1).evaluate(element => element === document.activeElement))
    assert.equal(await shownRate(1).innerText(),'25G')

    await beginRate(1)
    await rate(1).selectOption('10')
    await clickCard(2,'bottom')
    assert.equal(await editor(1).count(),0,'switching cards cancels the unconfirmed rate choice')
    assert.equal(await shownRate(1).innerText(),'25G')
    assert.equal(await trigger(1).count(),0,'expanded EPL exposes rate editing for the selected port only')
    await clickCard(1,'speed')
    await stageRate(1,'10')
    assert.equal(await page.locator('#port-tile-1').getAttribute('aria-expanded'),'true','rate editing keeps the chosen port open')
    assert.equal(await page.getByRole('dialog').count(),0,'rate editing stays inside the card')
    assert.equal(await shownRate(2).innerText(),'25G','editing one lane must preserve sibling speeds')
    assert.equal(await shownRate(5).innerText(),'25G','editing one EPL must preserve other EPLs')
    assert.match(await page.locator('#port-tile-1').getAttribute('aria-description'),/待提交 10G，当前 25G/)
    assert(await page.locator('#port-tile-1 .port-rate-pending-marker').isVisible(),'compact selectors must visibly distinguish pending rates')
    assert(await page.locator('#port-tile-1').locator('..').evaluate(element =>
      element.getBoundingClientRect().height<=50 && !element.querySelector('.port-rate-trigger')),
      'pending rates must stay compact with no editing control inside the selection target')
    for (const width of [761,320]) {
      await page.setViewportSize({width,height:844})
      assert(await page.locator('#port-tile-1').locator('..').evaluate(element => {
        const row=element.querySelector('.port-tile-rate')
        const heading=[...element.closest('.epl-box').querySelectorAll('.epl-label-chip,.epl-box-heading>.tag,.port-settings-trigger,.epl-box-heading>.icon-button')]
          .map(item=>item.getBoundingClientRect()).filter(rect=>rect.width)
        return element.getBoundingClientRect().height<=50 && element.scrollWidth<=element.clientWidth+1 &&
          row.scrollWidth<=row.clientWidth+1 && !element.querySelector('.port-rate-trigger') &&
          heading.every((rect,index)=>heading.slice(index+1).every(next=>rect.right<=next.left))
      }),'split headers and pending markers must fit narrow selectors without covering controls')
      await page.locator('#epl-box-0').screenshot({path:path.join(output,'pending-rate-'+width+'.png')})
    }
    await page.setViewportSize({width:1440,height:1080})
    await detail.getByRole('tab',{name:'端口详情',exact:true}).click()
    assert.match(await detail.innerText(),/25 Gbps/,'runtime information retains the current hardware rate')
    await beginRate(9)
    assert.deepEqual(await rate(9).locator('option').allTextContents(),['40G','100G'])
    await rate(9).selectOption('100')
    await editor(9).getByRole('button',{name:'暂存',exact:true}).click()
    assert.equal(await page.locator('#port-tile-1').getAttribute('aria-expanded'),'true')
    assert.equal(await shownRate(13).innerText(),'40G')
    assert.deepEqual(writes,[],'staging a rate must not send hardware requests')

    await page.getByRole('button',{name:'设置端口 P1',exact:true}).click()
    const settings = page.getByRole('dialog')
    assert.equal(await settings.getByLabel('P1 / Lane 0').inputValue(),'10','settings share the staged rate')
    await settings.getByLabel('P2 / Lane 1').selectOption('10')
    await settings.getByRole('button',{name:'完成设置',exact:true}).click()
    assert.equal(await shownRate(2).innerText(),'10G','settings changes appear on the card')
    await page.getByRole('button',{name:'设置端口 P9',exact:true}).click()
    assert.equal(await settings.getByLabel('端口组模式',{exact:true}).inputValue(),'100g')
    await settings.getByRole('button',{name:'完成设置',exact:true}).click()

    await page.getByRole('button',{name:'预览并校验',exact:true}).click()
    await page.getByRole('heading',{name:'检查配置变更',exact:true}).waitFor()
    const expected = JSON.parse(JSON.stringify(configuration))
    expected.groups[0].lane_speeds = [10,10,25,25]
    expected.groups[2].mode = '100g'
    assert.deepEqual(previewRequest.configuration,expected,'only the chosen rates may change')
    assert.deepEqual(writes,['/api/v1/config/preview'])
    await page.getByRole('button',{name:'返回编辑',exact:true}).click()
    await page.locator('.save-bar').getByRole('button',{name:'丢弃修改',exact:true}).click()
    await page.waitForFunction(() => document.querySelector('#port-tile-1 .port-tile-speed').textContent.trim() === '25G' && !document.querySelector('.port-rate-note.pending'))
    assert.equal(await shownRate(1).innerText(),'25G')
    assert.equal(await shownRate(2).innerText(),'25G')
    assert.equal(await shownRate(9).innerText(),'40G')
    await page.locator('#port-tile-1').focus()
    for(const id of [2,3,4]) {
      await page.keyboard.press('Tab')
      assert(await page.locator('#port-tile-'+id).evaluate(element=>element===document.activeElement),'keyboard navigation traverses the compact selectors')
    }
    await page.keyboard.press('Tab')
    assert(await trigger(1).evaluate(element => element === document.activeElement),'keyboard focus moves to the explicit rate action')
    await trigger(1).press('Enter')
    await rate(1).waitFor()
    assert(await rate(1).evaluate(element => element === document.activeElement),'opening the editor focuses its speed input')
    await rate(1).selectOption('10')
    await page.keyboard.press('Escape')
    await editor(1).waitFor({state:'detached'})
    assert.equal(await shownRate(1).innerText(),'25G')

    for(const width of [1440,1101,761,390,320]) {
      await page.setViewportSize({width,height:900})
      if(await page.locator('#port-tile-9').getAttribute('aria-expanded')!=='true') await page.locator('#port-tile-9').click()
      await page.locator('#port-details-2').waitFor()
      for(const id of [9,13]) {
        await beginRate(id)
        await rate(id).selectOption('100')
        await editor(id).scrollIntoViewIfNeeded()
        const metrics=await editor(id).evaluate(element=>{
          const select=element.querySelector('select'), style=getComputedStyle(select), bounds=select.getBoundingClientRect()
          const arrow=element.querySelector('.port-speed-chevron').getBoundingClientRect(), label=element.querySelector('.port-rate-label').getBoundingClientRect()
          const context=document.createElement('canvas').getContext('2d'); context.font=style.font
          const textWidth=Math.max(...[...select.options].map(option=>context.measureText(option.textContent).width))
          const available=select.clientWidth-parseFloat(style.paddingLeft)-parseFloat(style.paddingRight)
          const focusExtent=style.outlineStyle==='none'?0:Math.max(0,parseFloat(style.outlineWidth)+parseFloat(style.outlineOffset))
          const card=element.closest('.epl-box').getBoundingClientRect(), actions=element.querySelector('.port-rate-actions').getBoundingClientRect()
          return {width:innerWidth,id:select.id,value:select.value,textWidth,available,selectWidth:bounds.width,
            arrowClear:bounds.left+parseFloat(style.borderLeftWidth)+parseFloat(style.paddingLeft)+textWidth+2<=arrow.left,
            labelClear:!label.width||label.bottom<=bounds.top||label.right<=bounds.left-focusExtent,
            actionsClear:!element.classList.contains('port-rate-inline')||bounds.right+focusExtent<=actions.left,
            insideCard:element.getBoundingClientRect().left>=card.left&&element.getBoundingClientRect().right<=card.right,
            selectionHeight:element.closest('.epl-box').classList.contains('expanded')?element.closest('.epl-box').querySelector('.port-tile-grid').getBoundingClientRect().height:null}
        })
        rateGeometry.push(metrics)
        await fs.writeFile(path.join(output,'rate-geometry.json'),JSON.stringify(rateGeometry,null,2)+'\n')
        assert(metrics.textWidth<=metrics.available,'all speed labels must fit the input: '+JSON.stringify(metrics))
        assert(metrics.arrowClear&&metrics.labelClear&&metrics.actionsClear&&metrics.insideCard,'text, arrow, focus ring and actions must stay separate: '+JSON.stringify(metrics))
        if(id===9) {
          assert.equal(metrics.selectionHeight,48,'editing 100G must not increase the port selector height')
          if([1440,320,761].includes(width)) await page.locator('#epl-box-2').screenshot({path:path.join(output,'rate-100g-'+width+'.png')})
        }
        await page.keyboard.press('Escape')
        await editor(id).waitFor({state:'detached'})
        assert.equal(await shownRate(id).innerText(),'40G','cancelling the layout check must preserve the configured rate')
      }
    }
    await page.setViewportSize({width:1440,height:1080})
    await page.locator('#port-tile-1').click()
    await detail.waitFor()

    for (const width of [390,320]) {
      await page.setViewportSize({width,height:844})
      for (const tab of ['端口详情','收发统计','VLAN 状态']) {
        await detail.getByRole('tab',{name:tab,exact:true}).click()
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),'narrow screen must not overflow')
        assert(await detail.locator('.port-detail-body').evaluate(element => element.clientHeight >= 80 && element.scrollWidth <= element.clientWidth+1),'detail content stays readable and scrolls vertically')
        if (width === 390) await page.screenshot({path:path.join(output,'mobile-'+tab+'.png')})
      }
    }
    await page.setViewportSize({width:1440,height:1080})
    await page.getByRole('textbox',{name:'查找端口',exact:true}).fill('EPL0')
    assert.equal(await page.locator('.epl-box:visible').count(),1,'filtering keeps only the selected EPL')
    await page.getByRole('textbox',{name:'查找端口',exact:true}).fill('')

    const phone = await browser.newPage({viewport:{width:390,height:844},hasTouch:true,locale:'zh-CN'})
    phone.on('pageerror',error => errors.push(error.message))
    await phone.route('**/*',handleRoute)
    await phone.goto(base)
    await phone.getByRole('button',{name:'展开导航',exact:true}).click()
    await phone.getByRole('button',{name:'端口与光模块',exact:true}).click()
    const touchTile = phone.locator('#port-tile-2').locator('..')
    await touchTile.scrollIntoViewIfNeeded()
    const touchBounds = await touchTile.boundingBox()
    await phone.touchscreen.tap(touchBounds.x+12,touchBounds.y+touchBounds.height-8)
    assert.equal(await phone.locator('#port-tile-2').getAttribute('aria-expanded'),'true','touching the lower card selects its port')
    await phone.locator('#port-tile-1 .port-tile-speed').tap()
    assert.equal(await phone.locator('#port-tile-1').getAttribute('aria-expanded'),'true','touching the displayed speed views the port')
    assert.equal(await phone.locator('.port-speed-select').count(),0)
    await phone.locator('#port-tile-1').locator('..').screenshot({path:path.join(output,'touch-card.png')})
    await phone.getByRole('button',{name:'调整 P1 速率',exact:true}).tap()
    await phone.getByRole('combobox',{name:'P1 端口速率',exact:true}).selectOption('10')
    assert(await phone.getByRole('group',{name:'P1 速率调整',exact:true}).evaluate(element => element.getBoundingClientRect().top >= element.closest('.epl-box').querySelector('.port-tile-grid').getBoundingClientRect().bottom),'mobile rate editor must stay below the port selection row')
    assert.equal(await phone.locator('.save-bar').count(),0)
    await phone.locator('#epl-box-0').screenshot({path:path.join(output,'touch-rate-editor.png')})
    await phone.getByRole('group',{name:'P1 速率调整',exact:true}).getByRole('button',{name:'取消',exact:true}).tap()
    assert.equal(await phone.locator('#port-tile-1 .port-tile-speed').innerText(),'25G')
    await phone.close()

    readOnly = true
    await page.reload()
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    assert(await trigger(1).isDisabled(),'write restrictions also apply to the rate action')
    assert(await trigger(9).isDisabled())
    await clickCard(2,'state')
    assert(await trigger(2).isDisabled(),'the selected-port rate action retains write restrictions')

    readOnly=false
    sampleOptions={...sampleOptions,quality:'valid',offset:-86400}
    await page.reload()
    await page.getByRole('button',{name:'端口与光模块',exact:true}).click()
    await page.locator('#port-tile-1').click()
    const sampleButton=detail.locator('.port-freshness'), link=detail.locator('.port-current-link')
    async function checkSample(name,options,label,linkText) {
      const serial=++sampleSerial
      sampleOptions={...sampleOptions,...options}
      await page.waitForResponse(async response=>response.url()===base+'/api/v1/telemetry' && (await response.json()).fixture_case===serial)
      await page.waitForFunction(({label,linkText})=>{
        const box=document.querySelector('#port-details-0')
        return new RegExp(label).test(box?.querySelector('.port-freshness')?.textContent||'') && box?.querySelector('.port-current-link')?.textContent===linkText
      },{label,linkText})
      freshnessChecks.push({name,label:await sampleButton.innerText(),link:await link.innerText()})
    }
    await checkSample('workstation ahead of device clock',{},'采样正常','未连接')
    assert.equal(await sampleButton.getAttribute('class'),'port-freshness normal','clock skew must not show a stale warning')
    await sampleButton.evaluate(element=>{
      element.normalLabels=new Set([element.textContent])
      element.labelObserver=new MutationObserver(()=>element.normalLabels.add(element.textContent))
      element.labelObserver.observe(element,{subtree:true,childList:true,characterData:true})
    })
    for(const age of [1,2,0]) await checkSample('stable normal label at age '+age,{age},'采样正常','未连接')
    const normalLabels=await sampleButton.evaluate(element=>{element.labelObserver.disconnect();return [...element.normalLabels]})
    assert.deepEqual(normalLabels,['采样正常'],'fresh sampling must keep a stable label across successive polls')
    await checkSample('workstation behind device clock',{offset:86400,link:'up'},'采样正常','已连接')
    assert(await page.locator('#port-tile-1 .port-link-dot').evaluate(element=>element.classList.contains('up')))
    await checkSample('old sample with an otherwise valid read',{age:8},'未更新','上次：已连接')
    assert.equal(await page.locator('#port-tile-1 .port-link-dot.up').count(),0,'old link-up information must not look live')
    await sampleButton.click()
    assert.match(await detail.locator('.port-sample-help').innerText(),/超过 3 秒.*上次结果/)
    assert.match(await detail.locator('.port-sample-help').innerText(),/设备采样时间.*每 1 秒.*VLAN、MTU/)
    await page.locator('#epl-box-0').screenshot({path:path.join(output,'sampling-delay-explained.png')})
    await sampleButton.click()
    await checkSample('API failure retains the last sample',{fail:true},'更新失败','上次：已连接')
    await checkSample('data-source failure',{fail:false,error:'读取失败',age:0,quality:'stale'},'更新失败','上次：已连接')
    await checkSample('source flags the cache stale',{error:null,quality:'stale'},'采样延迟','上次：已连接')
    await checkSample('counter failure keeps independently valid link state',{quality:'unavailable',counterQuality:'unavailable'},'统计未取得','已连接')
    await checkSample('state failure is not link down',{stateQuality:'unavailable',counterQuality:'valid'},'状态未取得','未知')
    await checkSample('no sample yet',{empty:true},'等待采样','未取得')
    await checkSample('recovery restores live status',{empty:false,quality:'valid',stateQuality:'valid'},'采样正常','已连接')
    assert.deepEqual(errors,[])
    const report = {passed:true,layouts,cardClicks,positions,resizes,freshnessChecks,normalLabels,rateGeometry,real_network:false,hardware_access:false,checks:[
      'resizable P1 inspector: native dialog, pointer/keyboard size, maximize/restore, focus, drafts, nested settings and narrow full-screen layout',
      'all EPL positions and dimensions remain stable throughout every inspector animation','compact details stay inside the selected card within the quarter-screen limit','OBT grid has no unused trailing rows',
      'resizing an open inspector retains the port and compact selectors at desktop and mobile grid breakpoints',
      '48px selectors reserve at least 160px for detail content and move rate editing beside the selected port title',
      'device clock skew, delayed samples, read failures and recovery have explicit meanings independent of link state',
      'normal sampling retains one label throughout the three-second window',
      '100G fits both collapsed and expanded editors without arrow or focus-ring overlap at five viewport widths',
      'Native and Tagged VLANs show applied names, including unnamed and unconfigured cases',
      'RX and TX comparison and balanced VLAN fields','large counters and narrow-screen layouts stay within bounds',
      'split lanes support 10G and 25G; merged base ports support 40G and 100G',
      'physical clicks select the port from full cards and compact selectors, including their bottom padding',
      'speed controls appear only after the explicit rate action','rate choices require staging; Cancel, Escape and switching cards discard temporary choices',
      'touch selection and rate cancellation','staged rate edits keep details open and preserve other ports','settings and rate editing share the same draft',
      'preview validates with the production model and changes only selected rates','discard restores all rate controls',
      'inline speeds honor keyboard access and write restrictions']}
    await fs.writeFile(path.join(output,'ui-report.json'),JSON.stringify(report,null,2)+'\n')
    console.log(JSON.stringify(report))
  } catch (error) {
    await page.screenshot({path:path.join(output,'failure.png')}).catch(() => {})
    throw error
  } finally { await browser.close() }
})().catch(error => {console.error(error);process.exitCode=1})
