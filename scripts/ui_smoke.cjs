/* Run against a fresh, private simulator state; never a live switch. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawn } = require('node:child_process')
const { mkdtemp, mkdir } = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const assert = require('node:assert/strict')
const readline = require('node:readline')

;(async () => {
  const state = await mkdtemp(path.join(os.tmpdir(), 'fm10k-ui-'))
  const root = path.resolve(__dirname, '..')
  const port = 18081
  const asgi = process.env.FM10K_UI_TRANSPORT !== 'tcp'
  const server = spawn(process.env.FM10K_PYTHON || 'python3', asgi ?
    ['-u', 'scripts/asgi_bridge.py', state] : ['-m', 'fm10k_controlpanel', '--port', String(port)], {
    cwd: root, env: { ...process.env, PANEL_BACKEND: 'mock', PANEL_STATE_DIR: state,
      PYTHONPATH: path.join(root, 'backend') }, stdio: [asgi ? 'pipe' : 'ignore', 'pipe', 'pipe'],
  })
  let output = ''
  server.stderr.on('data', c => { output += c.toString() })
  let bridgeReady = false, sequence = 0
  const pending = new Map()
  if (asgi) {
    readline.createInterface({ input: server.stdout }).on('line', line => {
      const response = JSON.parse(line)
      if (response.ready) bridgeReady = true
      else {
        const request = pending.get(response.id)
        if (request) { pending.delete(response.id); request.resolve(response) }
      }
    })
  }
  let browser
  try {
    const base = 'http://127.0.0.1:' + port
    for (let i = 0; i < 80; ++i) {
      if (server.exitCode !== null) throw new Error(output)
      if (asgi && bridgeReady) break
      if (!asgi) { try { if ((await fetch(base + '/api/v1/health')).ok) break } catch {} }
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    browser = await chromium.launch({ headless: true,
      ...(process.env.FM10K_BROWSER_CHANNEL ? { channel: process.env.FM10K_BROWSER_CHANNEL } : {}) })
    const page = await browser.newPage({ viewport: { width: 1440, height: 1080 }, locale: 'zh-CN' })
    let delayRollbackRefresh = false
    if (asgi) {
      await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url())
        if (url.origin !== base) return route.abort()
        if (request.method() === 'POST' && url.pathname.endsWith('/rollback')) delayRollbackRefresh = true
        if (delayRollbackRefresh && request.method() === 'GET' && url.pathname === '/api/v1/config') {
          delayRollbackRefresh = false
          // A terminal job must not be displayed while the form still shows
          // the rejected candidate, even when the authoritative read is slow.
          await new Promise(resolve => setTimeout(resolve, 300))
        }
        const id = ++sequence
        const response = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => { pending.delete(id); reject(new Error('ASGI bridge timeout')) }, 30000)
          pending.set(id, { resolve: result => { clearTimeout(timer); resolve(result) } })
          server.stdin.write(JSON.stringify({ id, method: request.method(), path: url.pathname + url.search,
            headers: request.headers(), body: (request.postDataBuffer() || Buffer.alloc(0)).toString('base64') }) + '\n')
        })
        await route.fulfill({ status: response.status, headers: response.headers,
          body: Buffer.from(response.body, 'base64') })
      })
    }
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.goto(base)
    await page.getByLabel('用户名', { exact: true }).fill('testadmin')
    await page.getByLabel('密码', { exact: true }).fill('Fm10k-local-test-only-2026!')
    await page.getByRole('button', { name: '创建管理员并进入' }).click()
    await page.getByRole('heading', { name: '设备概览', exact: true }).waitFor()
    await page.getByRole('button', { name: '端口与光模块', exact: true }).click()
    await page.getByRole('button', { name: '查看端口 P1，OBT 1，EPL 0', exact: true }).click()
    await page.getByRole('button', { name: '调整 P1 速率', exact: true }).click()
    await page.getByRole('combobox', { name: 'P1 端口速率', exact: true }).selectOption('40')
    await page.getByRole('group', { name: 'P1 速率调整', exact: true }).getByRole('button', { name: '暂存', exact: true }).click()
    await page.getByRole('button', { name: '设置端口 P1', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'P1 · 端口设置', exact: true })
    await dialog.getByLabel('用户名称').fill('验证端口')
    await dialog.getByLabel('PVID / Native VLAN').selectOption('1')
    await dialog.getByLabel('管理启用 / 光发射启用').check()
    await dialog.getByRole('button', { name: '完成设置' }).click()
    await page.getByRole('button', { name: '预览并校验' }).click()
    await page.getByRole('heading', { name: '检查配置变更' }).waitFor()
    await page.getByRole('button', { name: '提交配置', exact: true }).click()
    const transaction = page.locator('.transaction-modal')
    await transaction.getByRole('button', { name: '确认保留' }).waitFor()
    await transaction.getByRole('button', { name: '确认保留' }).click()
    await transaction.waitFor({ state: 'hidden' })
    await page.locator('.job-banner').getByText('已完成', { exact: true }).waitFor()
    assert.equal(await page.locator('#port-tile-1 .port-tile-speed').innerText(), '40G')
    await page.getByRole('button', { name: '温度与风扇', exact: true }).click()
    await page.getByLabel('闲置点PWM', { exact: true }).fill('55')
    await page.getByLabel('闲置点PWM', { exact: true }).press('Tab')
    await page.getByRole('button', { name: '预览并校验' }).click()
    await page.getByRole('button', { name: '提交配置', exact: true }).click()
    await transaction.getByRole('button', { name: '恢复原配置', exact: true }).waitFor()
    await transaction.getByRole('button', { name: '恢复原配置', exact: true }).click()
    await transaction.waitFor({ state: 'hidden' })
    await page.locator('.job-banner').getByText('已回滚', { exact: true }).waitFor()
    assert.equal(await page.getByLabel('闲置点PWM', { exact: true }).inputValue(), '50')
    await page.getByRole('button', { name: '二层交换', exact: true }).click()
    for (const name of ['MAC 地址表', '链路聚合', 'RSTP', 'LLDP', 'IGMP', '流量管理', '端口镜像', 'VLAN']) {
      await page.getByRole('tab', { name, exact: true }).click()
      await page.waitForTimeout(70)
    }
    for (const name of ['配置管理', '操作日志', '系统与维护']) {
      await page.getByRole('button', { name, exact: true }).click()
      await page.getByRole('heading', { name, exact: true }).waitFor()
    }
    const admin = page.locator('.administrator-settings')
    await admin.getByLabel('管理员用户名', { exact: true }).fill('renamedadmin')
    await admin.getByLabel('当前密码', { exact: true }).fill('Fm10k-local-test-only-2026!')
    await admin.getByLabel('新密码', { exact: true }).fill('Replacement-test-password-2026!')
    await admin.getByLabel('再次输入新密码', { exact: true }).fill('Replacement-test-password-2026!')
    const accountReply = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/auth/administrator')
    await admin.getByRole('button', { name: '保存管理员信息' }).click()
    const accountResponse = await accountReply
    const accountResult = await accountResponse.json()
    assert.equal(accountResponse.status(), 200, accountResult.detail || 'administrator update failed')
    await admin.getByText('管理员信息已更新，其他登录会话已失效。').waitFor()
    assert.equal(await admin.getByLabel('当前密码', { exact: true }).inputValue(), '')
    await page.getByRole('button', { name: '退出登录', exact: true }).click()
    await page.getByLabel('用户名', { exact: true }).fill('renamedadmin')
    await page.getByLabel('密码', { exact: true }).fill('Replacement-test-password-2026!')
    await page.getByRole('button', { name: '登录', exact: true }).click()
    await page.getByRole('button', { name: '设备概览', exact: true }).waitFor()
    await page.getByRole('button', { name: /三层网络/ }).click()
    await page.getByRole('heading', { name: '三层网络，入口已预留' }).waitFor()
    await page.getByRole('button', { name: '设备概览', exact: true }).click()
    await mkdir(path.join(root, 'artifacts'), { recursive: true })
    await page.screenshot({ path: path.join(root, 'artifacts/dashboard-desktop.png'), fullPage: true })
    await page.setViewportSize({ width: 390, height: 844 })
    await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 0)
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile overflow')
    await page.getByRole('button', { name: '展开导航', exact: true }).click()
    await page.getByRole('button', { name: '温度与风扇', exact: true }).click()
    await page.getByRole('heading', { name: '温度与风扇', exact: true }).waitFor()
    await page.getByRole('button', { name: '展开导航', exact: true }).click()
    await page.getByRole('button', { name: '设备概览', exact: true }).click()
    await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 0)
    await page.screenshot({ path: path.join(root, 'artifacts/dashboard-mobile.png'), fullPage: true, animations: 'disabled' })
    assert.deepEqual(errors, [], 'browser errors')
    console.log(`UI smoke passed (${asgi ? 'ASGI pipe, no listening socket' : 'localhost TCP'}): setup, port commit/confirm, fan rollback, L2 pages, desktop and mobile.`)
  } finally {
    if (browser) await browser.close()
    server.kill('SIGTERM')
  }
})().catch(error => { console.error(error); process.exitCode = 1 })
