/* Browser-only transaction and notification regression; every request is intercepted. */
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
async function bounded(promise) {
  let timer
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Fixture request did not arrive')), 15000)
  })]) } finally { clearTimeout(timer) }
}

;(async () => {
  const root = path.resolve(__dirname, '..'), output = path.join(root, 'artifacts/transaction-lifecycle')
  const seed = spawnSync(process.env.FM10K_PYTHON || 'python3', ['-c',
    'from fm10k_controlpanel.models import SwitchConfiguration; print(SwitchConfiguration().model_dump_json())'],
  { cwd: root, env: { ...process.env, PYTHONPATH: path.join(root, 'backend') }, encoding: 'utf8' })
  assert.equal(seed.status, 0, seed.stderr)
  const clone = value => JSON.parse(JSON.stringify(value))
  let configuration = JSON.parse(seed.stdout), original = clone(configuration), candidate
  let revision = 7, jobNumber = 1, jobState = 'running', rollbackFailed = false
  let actionGate, configGate, telemetryGate, telemetryEntered, needsConfigRead = false, holdTelemetry = false
  const posts = { confirm: 0, rollback: 0, commit: 0 }, errors = [], layouts = [], checks = []
  const base = 'http://127.0.0.1:18115'
  let deviceOffset = -86400
  const job = () => ({ id: 'config-job-' + jobNumber, kind: 'configuration', state: jobState,
    deadline: Date.now() / 1000 + deviceOffset + 300, remaining_seconds: 300,
    message: ({ queued: '配置作业等待执行', running: '应用配置并核对硬件', awaiting_confirmation: '已生效，请确认保留',
      done: '配置已确认', rolled_back: '原配置已恢复', failed: '配置执行失败' })[jobState],
    error: jobState === 'failed' ? 'fixture：设备未接受配置' : undefined, rollback_failed: rollbackFailed })
  const browser = await chromium.launch({ headless: true,
    ...(process.env.FM10K_BROWSER_CHANNEL ? { channel: process.env.FM10K_BROWSER_CHANNEL } : {}) })
  try {
    await fs.mkdir(output, { recursive: true })
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'zh-CN' })
    page.setDefaultTimeout(15000)
    await page.clock.install()
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== base) return route.abort()
      const send = (body, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) })
      switch (url.pathname) {
        case '/api/v1/auth/session': return send({ initialized: true, authenticated: true, username: 'fixture', csrf: 'fixture', mode: 'mock' })
        case '/api/v1/capabilities': return send({ mode: 'mock', version: '0.1.0~rc10', profile: configuration.profile })
        case '/api/v1/updates': return send({ available: false, locked: false })
        case '/api/v1/config':
          if (needsConfigRead) {
            await configGate.promise
            needsConfigRead = false; holdTelemetry = true
          }
          return send({ revision, configuration,
            pending: ['queued','running','awaiting_confirmation'].includes(jobState) ? { job_id: job().id } : null })
        case '/api/v1/telemetry':
          if (holdTelemetry) {
            holdTelemetry = false; telemetryEntered.open()
            await telemetryGate.promise
          }
          return send({ ports: [], sensors: { temperatures: [], fan: {}, quality: 'pending' }, optics: [] })
        case '/api/v1/config/preview':
          candidate = request.postDataJSON().configuration
          return send({ id: 'a'.repeat(32), affected_epls: [], requires_bandwidth_ack: false,
            changes: [{ path: '/vlans/1/name', before: configuration.vlans[0].name, after: candidate.vlans[0].name }] })
        case '/api/v1/config/commit':
          ++posts.commit; ++jobNumber; jobState = 'queued'; rollbackFailed = false
          original = clone(configuration); configuration = clone(candidate)
          return send(job(), 202)
      }
      if (url.pathname === '/api/v1/jobs/' + job().id) return send(job())
      const action = url.pathname.match(/^\/api\/v1\/jobs\/config-job-\d+\/(confirm|rollback)$/)?.[1]
      if (action) {
        ++posts[action]
        if (!await actionGate.promise) return send({ detail: 'fixture：确认暂未完成，请重试' }, 409)
        if (action === 'rollback') configuration = clone(original)
        ++revision; jobState = action === 'confirm' ? 'done' : 'rolled_back'; needsConfigRead = true
        return send({ ok: true })
      }
      if (url.pathname.startsWith('/api/')) throw new Error('Unexpected request: ' + url.pathname)
      const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({ contentType: relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.css') ? 'text/css' : 'text/html',
        body: await fs.readFile(path.join(root, 'frontend/dist', relative)) })
    })
    await page.goto(base)
    const progress = page.locator('.transaction-modal'), banner = page.locator('.job-banner')
    const notice = page.locator('.content > .alert.success'), errorBanner = page.locator('.content > .alert.danger')
    await banner.getByText('应用配置并核对硬件', { exact: true }).waitFor()
    await page.evaluate(() => {
      window.progressMounts = 0
      let open = false
      new MutationObserver(() => {
        const visible = !!document.querySelector('.transaction-modal')
        if (visible && !open) ++window.progressMounts
        open = visible
      }).observe(document.body, { childList: true, subtree: true })
    })
    const mounts = () => page.evaluate(() => window.progressMounts)
    async function blurBanner() {
      await page.locator('.page-heading h1').click()
      await page.mouse.move(0, 0)
    }
    async function collapsed(previousMounts) {
      assert.equal(await progress.count(), 0, 'collapsed action must not reopen its dialog')
      assert.equal(await mounts(), previousMounts, 'no transient dialog mount')
      assert.equal(await page.locator('main').getAttribute('inert'), null, 'inline progress keeps the page available')
    }
    async function layout(name) {
      const metrics = await banner.evaluate(element => {
        const rect = element.getBoundingClientRect()
        const buttons = [...element.querySelectorAll('button')].map(button => {
          const box = button.getBoundingClientRect()
          return { text: button.textContent.trim() || button.getAttribute('aria-label'), left: box.left, right: box.right, top: box.top, bottom: box.bottom }
        })
        return { width: innerWidth, noOverflow: document.documentElement.scrollWidth <= innerWidth,
          inside: buttons.every(box => box.left >= rect.left && box.right <= rect.right + 1), buttons }
      })
      assert(metrics.noOverflow && metrics.inside, JSON.stringify(metrics))
      for (let i = 0; i < metrics.buttons.length; ++i) for (let j = i + 1; j < metrics.buttons.length; ++j) {
        const a = metrics.buttons[i], b = metrics.buttons[j]
        assert(!(a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom), 'banner actions overlap')
      }
      layouts.push({ name, ...metrics })
      await banner.screenshot({ path: path.join(output, name + '.png'), animations: 'disabled' })
    }
    function resetActionGates() {
      actionGate = deferred(); configGate = deferred(); telemetryGate = deferred(); telemetryEntered = deferred()
    }
    async function finishInline(action) {
      resetActionGates()
      const previousMounts = await mounts()
      await banner.getByRole('button', { name: action === 'confirm' ? '确认保留' : '恢复原配置', exact: true }).click()
      await banner.getByText(action === 'confirm' ? '正在确认配置' : '正在恢复配置', { exact: true }).waitFor()
      await collapsed(previousMounts)
      assert.notEqual(await page.locator('.page-body').getAttribute('inert'), null, 'configuration edits remain locked during readback')
      assert.notEqual(await page.locator('#main-navigation').getAttribute('inert'), null, 'navigation cannot start a competing refresh')
      actionGate.open(true)
      await banner.getByText(action === 'confirm' ? '正在读取已确认的配置与设备状态。' : '正在读取恢复后的配置与设备状态。', { exact: true }).waitFor()
      configGate.open()
      await bounded(telemetryEntered.promise)
      assert.equal(await banner.getByRole('button', { name: /正在确认|正在恢复/ }).isDisabled(), true)
      await collapsed(previousMounts)
      telemetryGate.open()
      await banner.getByText(action === 'confirm' ? '配置已确认' : '原配置已恢复', { exact: true }).waitFor()
      await collapsed(previousMounts)
      assert.equal(await page.locator('.page-body').getAttribute('inert'), null, 'configuration edits unlock after readback')
      await blurBanner()
    }
    async function startJob() {
      await page.getByRole('button', { name: '二层交换', exact: true }).click()
      await page.getByLabel('VLAN 名称', { exact: true }).fill('事务回归-' + (jobNumber + 1))
      await page.getByRole('button', { name: '预览并校验', exact: true }).click()
      await page.getByRole('button', { name: '提交配置', exact: true }).click()
      await progress.getByRole('button', { name: '收起到状态栏', exact: true }).click()
      await blurBanner()
    }

    assert.equal(await progress.count(), 0, 'a recovered pending job starts in the status bar')
    await banner.getByRole('button', { name: '查看进度', exact: true }).focus()
    await page.keyboard.press('Enter')
    await progress.getByRole('heading', { name: '正在应用并回读配置', exact: true }).waitFor()
    assert.equal(await progress.evaluate(element => element === document.activeElement), true)
    await progress.getByRole('button', { name: '收起到状态栏', exact: true }).click()
    assert.equal(await banner.getByRole('button', { name: '查看进度', exact: true }).evaluate(element => element === document.activeElement), true)
    await blurBanner()
    await page.clock.runFor(12000)
    await banner.getByRole('button', { name: '查看进度', exact: true }).click()
    assert(Number(await progress.locator('.request-elapsed strong').innerText()) >= 12, 'reopening preserves elapsed time')
    await progress.getByRole('button', { name: '收起到状态栏', exact: true }).click()
    jobState = 'awaiting_confirmation'
    await page.clock.runFor(1000)
    await banner.getByRole('button', { name: '确认保留', exact: true }).waitFor()
    assert.match(await banner.locator('.countdown').innerText(), /^(?:29\d|300)s$/,
      'confirmation countdown must use the device remainder despite a one-day clock difference')
    deviceOffset = 86400
    await page.clock.runFor(1000)
    assert.match(await banner.locator('.countdown').innerText(), /^(?:29\d|300)s$/,
      'a device wall-clock correction must not extend the confirmation window')
    for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 844 }, { width: 320, height: 568 }]) {
      await page.setViewportSize(viewport)
      await layout('pending-' + viewport.width)
    }
    await page.setViewportSize({ width: 1440, height: 900 })
    await blurBanner()
    await page.clock.runFor(12000)
    assert.equal(await banner.isVisible(), true, 'pending confirmation never expires as a notification')
    checks.push('recovered jobs have a keyboard-accessible reopen button and preserve elapsed time', 'active and awaiting-confirmation banners do not expire', 'desktop and phone banner actions fit without overlap')

    // Two identical failures must each receive a fresh timeout without opening a modal.
    for (let attempt = 0; attempt < 2; ++attempt) {
      resetActionGates()
      const previousMounts = await mounts(), previousPosts = posts.confirm
      await banner.getByRole('button', { name: '确认保留', exact: true }).click()
      await banner.getByText('正在确认配置', { exact: true }).waitFor()
      await banner.getByRole('button', { name: '正在确认…', exact: true }).dispatchEvent('click')
      assert.equal(posts.confirm, previousPosts + 1, 'duplicate confirmation is blocked')
      await collapsed(previousMounts)
      actionGate.open(false)
      await errorBanner.getByText('fixture：确认暂未完成，请重试', { exact: true }).waitFor()
      await collapsed(previousMounts)
      await blurBanner()
      await page.clock.runFor(attempt === 0 ? 4000 : 7000)
      assert.equal(await errorBanner.isVisible(), true, 'new identical error resets its timer')
    }
    await page.clock.runFor(4000)
    await errorBanner.waitFor({ state: 'hidden' })
    assert.equal(await banner.getByRole('button', { name: '确认保留', exact: true }).isEnabled(), true)
    await finishInline('confirm')
    await layout('confirmed-desktop')
    await blurBanner()
    await page.clock.runFor(4000)
    assert.equal(await banner.isVisible(), true)
    await page.clock.runFor(2000)
    await banner.waitFor({ state: 'hidden' })
    checks.push('collapsed confirmation stays inline through request, failure and authoritative readback', 'duplicate confirmation is blocked', 'errors expire after ten seconds and identical errors restart the timer', 'successful job notifications expire after five seconds')

    await startJob()
    jobState = 'awaiting_confirmation'
    await page.clock.runFor(1000)
    await finishInline('rollback')
    await page.clock.runFor(3000)
    await startJob()
    const newJobMounts = await mounts()
    await page.clock.runFor(7000)
    await collapsed(newJobMounts)
    assert.equal(await banner.isVisible(), true, 'an old result timer cannot remove a new job')
    checks.push('collapsed rollback remains inline through slow readback', 'configuration editing stays locked until readback completes', 'a new transaction cancels the previous result timeout')

    jobState = 'awaiting_confirmation'
    await page.clock.runFor(1000)
    await banner.getByRole('button', { name: '查看进度', exact: true }).click()
    await progress.getByRole('button', { name: '确认保留', exact: true }).waitFor()
    configuration = clone(original); ++revision; jobState = 'rolled_back'
    await page.clock.runFor(1000)
    await progress.waitFor({ state: 'hidden' })
    await banner.getByText('原配置已恢复', { exact: true }).waitFor()
    await blurBanner()
    await page.clock.runFor(6000)
    await banner.waitFor({ state: 'hidden' })
    checks.push('automatic rollback closes an open progress dialog and leaves a timed result')

    await startJob()
    jobState = 'failed'
    await page.clock.runFor(1000)
    await banner.getByText('执行失败', { exact: true }).waitFor()
    await page.clock.runFor(11000)
    await banner.waitFor({ state: 'hidden' })
    await startJob()
    jobState = 'failed'; rollbackFailed = true
    await page.clock.runFor(1000)
    await banner.getByText(/局部恢复失败/).waitFor()
    await page.clock.runFor(20000)
    assert.equal(await banner.isVisible(), true, 'unresolved recovery failures remain visible')
    await banner.getByRole('button', { name: '关闭任务', exact: true }).click()
    checks.push('ordinary failure results expire; unresolved recovery failures remain until dismissed')

    const refresh = page.getByRole('button', { name: '刷新状态', exact: true })
    await refresh.click()
    await notice.getByText('已刷新缓存数据', { exact: true }).waitFor()
    await blurBanner()
    await page.clock.runFor(3000)
    await refresh.click()
    await blurBanner()
    await page.clock.runFor(3000)
    assert.equal(await notice.isVisible(), true, 'repeated identical notice restarts its timeout')
    await page.clock.runFor(3000)
    await notice.waitFor({ state: 'hidden' })
    await refresh.click()
    await notice.getByRole('button', { name: '关闭提示', exact: true }).click()
    await refresh.click()
    await blurBanner()
    await page.clock.runFor(6000)
    await notice.waitFor({ state: 'hidden' })
    checks.push('general notices expire after five seconds, renew on repeated text and survive stale timer cleanup')

    await refresh.click()
    await notice.hover()
    await page.clock.runFor(7000)
    assert.equal(await notice.isVisible(), true, 'hover pauses a notification')
    await page.mouse.move(0, 0)
    await page.clock.runFor(6000)
    await notice.waitFor({ state: 'hidden' })
    await refresh.click()
    await notice.getByRole('button', { name: '关闭提示', exact: true }).focus()
    await page.mouse.move(0, 0)
    await page.clock.runFor(7000)
    assert.equal(await notice.isVisible(), true, 'keyboard interaction pauses a notification')
    await blurBanner()
    await page.clock.runFor(6000)
    await notice.waitFor({ state: 'hidden' })
    checks.push('hover and keyboard interaction pause notification dismissal')

    assert.deepEqual(errors, [])
    const report = { passed: true, real_network: false, hardware_access: false, posts, layouts, checks }
    await fs.writeFile(path.join(output, 'ui-report.json'), JSON.stringify(report, null, 2) + '\n')
    console.log(JSON.stringify(report))
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
