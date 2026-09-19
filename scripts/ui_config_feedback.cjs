/* Deferred HTTP fixtures exercise visible feedback without a device or listening socket. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')

function deferred() {
  let open
  const promise = new Promise(resolve => { open = resolve })
  return { promise, open }
}

;(async () => {
  const root = path.resolve(__dirname, '..'), output = path.join(root, 'artifacts/config-feedback')
  const seed = spawnSync(process.env.FM10K_PYTHON || 'python3', ['-c',
    'from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
  { cwd: root, env: { ...process.env, PYTHONPATH: path.join(root, 'backend') }, encoding: 'utf8' })
  assert.equal(seed.status, 0, seed.stderr)
  let configuration = JSON.parse(seed.stdout), candidate
  let previewGate = deferred(), commitGate = deferred(), confirmGate = deferred(), configGate = deferred()
  let previewPosts = 0, commitPosts = 0, confirmPosts = 0
  let jobState = 'queued', confirmed = false, verboseReadback = false
  const base = 'http://127.0.0.1:18112', errors = [], layouts = []
  const browser = await chromium.launch({ headless: true,
    ...(process.env.FM10K_BROWSER_CHANNEL ? { channel: process.env.FM10K_BROWSER_CHANNEL } : {}) })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'zh-CN' })
    page.setDefaultTimeout(15000)
    await page.clock.install()
    page.on('pageerror', error => errors.push(error.message))
    const job = () => ({ id: 'config-job', kind: 'configuration', state: jobState, deadline: Date.now() / 1000 + 90,
      message: verboseReadback && jobState === 'running' ? '应用配置并核对硬件。'.repeat(80)+'readback_'+ 'x'.repeat(160) : ({ queued: '配置作业等待执行', running: '应用配置并核对硬件', awaiting_confirmation: '已生效，请在倒计时结束前确认', done: '配置已确认' })[jobState] })
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== base) return route.abort()
      const send = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      switch (url.pathname) {
        case '/api/v1/auth/session': return send({ initialized: true, authenticated: true, username: 'fixture', csrf: 'fixture', mode: 'mock' })
        case '/api/v1/capabilities': return send({ mode: 'mock', version: '0.1.0~rc3', profile: configuration.profile })
        case '/api/v1/updates': return send({ available: false, locked: false })
        case '/api/v1/config':
          if (confirmed) await configGate.promise
          return send({ revision: confirmed ? 8 : 7, configuration, pending: null })
        case '/api/v1/telemetry': return send({ ports: [], sensors: { temperatures: [], fan: {}, quality: 'pending' }, optics: [] })
        case '/api/v1/config/preview': {
          ++previewPosts
          candidate = request.postDataJSON().configuration
          const accepted = await previewGate.promise
          return accepted ? send({ id: 'a'.repeat(32), affected_epls: [], requires_bandwidth_ack: false,
            changes: [{ path: '/vlans/1/name', before: 'default', after: candidate.vlans[0].name }] }) :
            send({ detail: 'fixture：配置校验失败，草稿保留' }, 422)
        }
        case '/api/v1/config/commit': {
          ++commitPosts
          const accepted = await commitGate.promise
          if (!accepted) return send({ detail: 'fixture：提交未接受，请检查配置' }, 409)
          configuration = candidate
          return send(job(), 202)
        }
        case '/api/v1/jobs/config-job': return send(job())
        case '/api/v1/jobs/config-job/confirm':
          ++confirmPosts
          await confirmGate.promise
          confirmed = true; jobState = 'done'
          return send({ ok: true })
      }
      if (url.pathname.startsWith('/api/')) throw new Error('Unexpected request: ' + url.pathname)
      const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({ contentType: relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.css') ? 'text/css' : 'text/html',
        body: await fs.readFile(path.join(root, 'frontend/dist', relative)) })
    })
    await page.goto(base)
    await page.getByRole('button', { name: '二层交换', exact: true }).click()
    await page.getByLabel('VLAN 名称', { exact: true }).fill('等待反馈检查')
    const previewButton = page.locator('.save-bar .primary')
    const progress = page.locator('.request-modal')
    async function checkLayout(name) {
      const metrics = await progress.evaluate(element => {
        const bounds=element.getBoundingClientRect(), content=element.querySelector('.transaction-content'), footer=element.querySelector('.transaction-footer')
        const icon=element.querySelector('.transaction-icon').getBoundingClientRect(), title=element.querySelector('#request-title').getBoundingClientRect()
        const contentBounds=content.getBoundingClientRect(), footerBounds=footer.getBoundingClientRect()
        const stages=[...element.querySelectorAll('.transaction-stages li')].map(step => {
          const label=step.querySelector('span'), range=document.createRange()
          range.selectNodeContents(label)
          const rect=step.getBoundingClientRect()
          return {x:rect.x,y:rect.y,width:rect.width,height:rect.height,lines:range.getClientRects().length}
        })
        const buttons=[...footer.querySelectorAll('button')].map(button => {
          const rect=button.getBoundingClientRect()
          return {text:button.textContent.trim(),left:rect.left,right:rect.right,top:rect.top,bottom:rect.bottom}
        })
        return {viewport:{width:innerWidth,height:innerHeight},width:bounds.width,height:bounds.height,
          headerAligned:icon.right+6 <= title.left && Math.abs(icon.top-title.top)<2,
          stages,footerWidth:footerBounds.width,buttons,
          fits:bounds.left>=0 && bounds.right<=innerWidth+1 && bounds.top>=0 && bounds.bottom<=innerHeight+1,
          footerVisible:contentBounds.bottom<=footerBounds.top+1 && footerBounds.bottom<=innerHeight+1,
          bodyScrolls:content.scrollHeight>content.clientHeight+1,
          noHorizontalOverflow:element.scrollWidth<=element.clientWidth+1 && content.scrollWidth<=content.clientWidth+1,
          buttonsFit:buttons.every(button=>button.left>=footerBounds.left && button.right<=footerBounds.right+1 && button.top>=footerBounds.top && button.bottom<=footerBounds.bottom+1)}
      })
      assert(metrics.headerAligned,'icon and title should share a row: '+name)
      assert(metrics.fits && metrics.footerVisible && metrics.buttonsFit && metrics.noHorizontalOverflow,'dialog and actions must fit: '+name+' '+JSON.stringify(metrics))
      assert(Math.abs(metrics.footerWidth-metrics.width)<2,'footer divider spans the dialog width')
      if (metrics.stages.length) {
        assert.equal(metrics.stages.length,3)
        assert(metrics.stages.every(stage=>stage.lines===1),'stage labels must not split a single character onto another line')
        assert(Math.max(...metrics.stages.map(stage=>stage.width))-Math.min(...metrics.stages.map(stage=>stage.width))<1,'stage widths must match')
        assert(Math.max(...metrics.stages.map(stage=>stage.y))-Math.min(...metrics.stages.map(stage=>stage.y))<1,'stages must share a row')
      }
      layouts.push({name,...metrics})
      await fs.mkdir(output,{recursive:true})
      await fs.writeFile(path.join(output,'layout-report.json'),JSON.stringify(layouts,null,2)+'\n')
      await progress.screenshot({path:path.join(output,name+'.png'),animations:'disabled'})
      return metrics
    }
    await previewButton.click()
    await progress.getByRole('heading', { name: '正在校验配置' }).waitFor()
    assert.equal(await previewButton.isDisabled(), true)
    assert.match(await previewButton.innerText(), /正在校验/)
    assert.notEqual(await page.locator('main').getAttribute('inert'), null)
    assert.equal(await progress.evaluate(el => el === document.activeElement), true)
    await previewButton.dispatchEvent('click')
    assert.equal(previewPosts, 1)
    await page.clock.runFor(16000)
    await progress.getByText('等待时间较长，仍在等待设备响应。收到结果后会自动更新。').waitFor()
    await checkLayout('preview-long-wait')
    assert(Number(await progress.locator('.request-elapsed strong').innerText()) >= 15)
    await fs.mkdir(output, { recursive: true })
    await page.screenshot({ path: path.join(output, 'preview-wait.png'), fullPage: true })
    previewGate.open(false)
    await progress.waitFor({ state: 'hidden' })
    await page.getByRole('alert').filter({ hasText: 'fixture：配置校验失败' }).waitFor()
    assert.equal(await page.getByLabel('VLAN 名称', { exact: true }).inputValue(), '等待反馈检查')
    assert.equal(await previewButton.isDisabled(), false)
    assert.equal(await page.locator('main').getAttribute('inert'), null)

    previewGate = deferred()
    await previewButton.click()
    await progress.getByRole('heading', { name: '正在校验配置' }).waitFor()
    previewGate.open(true)
    await page.getByRole('heading', { name: '检查配置变更', exact: true }).waitFor()
    await progress.waitFor({ state: 'hidden' })
    const commitButton = page.locator('.preview-modal .modal-actions .primary')
    await commitButton.click()
    await progress.getByRole('heading', { name: '正在提交配置' }).waitFor()
    assert.equal(await commitButton.isDisabled(), true)
    assert.equal(await page.locator('.preview-modal [aria-label="关闭预览"]').isDisabled(), true)
    assert.equal(await page.locator('.preview-modal .modal-actions .secondary').isDisabled(), true)
    await commitButton.dispatchEvent('click')
    assert.equal(commitPosts, 1)
    await page.screenshot({ path: path.join(output, 'commit-wait.png'), fullPage: true })
    commitGate.open(false)
    await progress.getByText('fixture：提交未接受，请检查配置', { exact: true }).waitFor()
    await checkLayout('commit-rejected')
    await progress.getByRole('button', { name: '返回预览', exact: true }).click()
    await progress.waitFor({ state: 'hidden' })
    await page.locator('.preview-modal .alert').filter({ hasText: 'fixture：提交未接受' }).waitFor()
    assert.equal(await commitButton.isDisabled(), false)

    commitGate = deferred()
    await commitButton.click()
    await progress.getByRole('heading', { name: '正在提交配置' }).waitFor()
    commitGate.open(true)
    const banner = page.locator('.job-banner')
    await banner.getByText('配置作业等待执行', { exact: true }).waitFor()
    assert.equal(await page.locator('.preview-modal').count(), 0)
    assert.equal(await banner.locator('.spin').count(), 1)
    jobState = 'running'
    await page.clock.runFor(1000)
    await banner.getByText('应用配置并核对硬件', { exact: true }).waitFor()
    await checkLayout('applying-desktop')
    for (const viewport of [{width:390,height:844},{width:320,height:568},{width:760,height:360}]) {
      await page.setViewportSize(viewport)
      await checkLayout('applying-'+viewport.width)
    }
    verboseReadback = true
    await page.clock.runFor(1000)
    await progress.getByText(/readback_x/).waitFor()
    const longLayout=await checkLayout('applying-long-message')
    assert(longLayout.bodyScrolls,'long feedback scrolls in the content area while actions stay visible')
    verboseReadback = false
    jobState = 'awaiting_confirmation'
    await page.clock.runFor(1000)
    const confirmButton = progress.getByRole('button', { name: '确认保留', exact: true })
    await confirmButton.waitFor()
    for (const viewport of [{width:1440,height:900},{width:390,height:844},{width:320,height:568}]) {
      await page.setViewportSize(viewport)
      const layout=await checkLayout('confirm-'+viewport.width)
      assert.deepEqual(layout.buttons.map(button=>button.text),['收起到状态栏','恢复原配置','确认保留'],'primary confirmation action is last')
    }
    await page.setViewportSize({width:1440,height:900})
    assert.equal(await banner.locator('.spin').count(), 0)
    await confirmButton.click()
    await progress.getByRole('heading', { name: '正在确认配置' }).waitFor()
    confirmGate.open(true)
    await progress.getByText('正在读取已确认的配置与设备状态。', { exact: true }).waitFor()
    assert.equal(await banner.getByText('配置已确认', { exact: true }).count(), 0)
    configGate.open(true)
    await banner.getByText('配置已确认', { exact: true }).waitFor()
    await progress.waitFor({ state: 'hidden' })
    await banner.getByRole('button', { name: '查看结果', exact: true }).click()
    await progress.getByRole('heading', { name: '配置已确认', exact: true }).waitFor()
    await checkLayout('completed-desktop')
    await page.clock.runFor(6000)
    assert.equal(await progress.isVisible(), true, 'explicitly reopened results remain readable')
    await progress.getByRole('button', { name: '完成并关闭', exact: true }).click()
    await progress.waitFor({ state: 'hidden' })
    await page.getByRole('heading', { name: '二层交换', exact: true }).click()
    await page.clock.runFor(6000)
    await banner.waitFor({ state: 'hidden' })
    assert.equal(await page.locator('.save-bar').count(), 0)
    assert.deepEqual([previewPosts, commitPosts, confirmPosts], [2, 2, 1])
    assert.deepEqual(errors, [])
    const report = { passed: true, real_network: false, hardware_access: false, layouts,
      checks: ['immediate preview feedback and elapsed wait', 'duplicate preview blocked',
        'preview failure preserves draft and unlocks controls', 'commit feedback blocks duplicate and dismissal',
        'commit failure preserves preview', 'queued and running job feedback uses server state',
        'confirmation remains pending until authoritative refresh finishes',
        'one continuous dialog through apply and confirmation', 'successful confirmation closes the dialog',
        'completed result can be reopened; notification expires after reviewing',
        'icon and title share a row; equal-width stages keep labels on one line',
        'full-width footer and visible actions at desktop, phone and short viewport sizes',
        'long readback messages wrap and scroll without moving the action footer out of view'] }
    await fs.writeFile(path.join(output, 'ui-report.json'), JSON.stringify(report, null, 2) + '\n')
    console.log(JSON.stringify(report))
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
