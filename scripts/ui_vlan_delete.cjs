/* Focused VLAN deletion regression. HTTP is intercepted; no device is contacted. */
const { chromium } = require(process.env.FM10K_PLAYWRIGHT_MODULE || '../frontend/node_modules/playwright')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')
const assert = require('node:assert/strict')

;(async () => {
  const root = path.resolve(__dirname, '..')
  const output = path.join(root, 'artifacts/vlan-delete')
  const python = process.env.FM10K_PYTHON || 'python3'
  const env = { ...process.env, PYTHONPATH: path.join(root, 'backend') }
  const seed = spawnSync(python, ['-c', `
import json
from fm10k_controlpanel.models import SwitchConfiguration
c = SwitchConfiguration().model_dump(mode='json')
c['vlans'] = [{'id': v, 'name': 'VLAN ' + str(v)} for v in (1, 10, 20, 30)]
for p in ('1', '5'):
    c['ports'][p].update(enabled=True, vlan_mode='trunk', pvid=1, tagged_vlans=[10])
c['ports']['9']['pvid'] = 30
c['lags'] = [{'name': 'ae3', 'members': [1, 5], 'mode': 'static'}]
c['static_macs'] = [{'mac': '02:00:00:00:00:10', 'vlan': 10, 'port': 5}]
c['igmp']['vlans'] = [10]
c['igmp']['static_groups'] = [{'address': '239.1.1.1', 'vlan': 10, 'ports': [5]}]
print(SwitchConfiguration.model_validate(c).model_dump_json())
`], { cwd: root, env, encoding: 'utf8' })
  assert.equal(seed.status, 0, seed.stderr)
  const configuration = JSON.parse(seed.stdout)
  const base = 'http://127.0.0.1:18111'
  const requests = [], errors = []
  let lastPreview
  const browser = await chromium.launch({ headless: true,
    ...(process.env.FM10K_BROWSER_CHANNEL ? { channel: process.env.FM10K_BROWSER_CHANNEL } : {}) })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN' })
    page.setDefaultTimeout(15000)
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== base) return route.abort()
      const send = body => route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) })
      if (request.method() !== 'GET') requests.push(url.pathname)
      switch (url.pathname) {
        case '/api/v1/auth/session': return send({ initialized: true, authenticated: true, username: 'fixture', csrf: 'fixture', mode: 'mock' })
        case '/api/v1/capabilities': return send({ mode: 'mock', version: '0.1.0~rc2', profile: configuration.profile })
        case '/api/v1/updates': return send({ available: false, locked: false })
        case '/api/v1/config': return send({ revision: 7, configuration, pending: null })
        case '/api/v1/telemetry': return send({ ports: [], sensors: { temperatures: [], fan: {}, quality: 'pending' }, optics: [] })
        case '/api/v1/operational/fdb': return send({ data: [] })
        case '/api/v1/operational/igmp': return send({ data: { members: [], groups: [], routers: [] } })
        case '/api/v1/config/preview': {
          lastPreview = request.postDataJSON()
          const checked = spawnSync(python, ['-c', 'import sys; from fm10k_controlpanel.models import Proposal; Proposal.model_validate_json(sys.stdin.read())'],
            { cwd: root, env, encoding: 'utf8', input: JSON.stringify(lastPreview) })
          assert.equal(checked.status, 0, checked.stderr)
          return send({ id: 'fixture-preview', affected_epls: [], requires_bandwidth_ack: false,
            changes: [{ path: '/vlans/1', before: 1, after: null }] })
        }
      }
      if (url.pathname.startsWith('/api/')) throw new Error('Unexpected request: ' + url.pathname)
      const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1)
      assert(!relative.includes('..'))
      return route.fulfill({ contentType: relative.endsWith('.js') ? 'text/javascript' : relative.endsWith('.css') ? 'text/css' : 'text/html',
        body: await fs.readFile(path.join(root, 'frontend/dist', relative)) })
    })
    await page.goto(base)
    await page.getByRole('button', { name: '二层交换', exact: true }).click()
    const remove = id => page.getByRole('button', { name: `删除 VLAN ${id}`, exact: true })
    const dialog = page.getByRole('dialog')
    await remove(1).click()
    await dialog.getByRole('heading', { name: 'VLAN 1 仍在使用中' }).waitFor()
    assert.match(await dialog.innerText(), /PVID \/ Native VLAN/)
    assert.match(await dialog.innerText(), /ae3 成员/)
    await dialog.getByRole('button', { name: '返回 VLAN 列表' }).click()
    assert.equal(await remove(1).count(), 1)
    assert.deepEqual(requests, [], 'blocked deletion must not send configuration writes')

    await page.getByLabel('VLAN 名称', { exact: true }).nth(1).fill('保留草稿名称')
    await remove(10).click()
    assert.match(await dialog.innerText(), /Tagged VLAN/)
    assert.match(await dialog.innerText(), /静态 MAC 02:00:00:00:00:10/)
    assert.match(await dialog.innerText(), /IGMP Snooping/)
    assert.match(await dialog.innerText(), /静态组播 239\.1\.1\.1/)
    await fs.mkdir(output, { recursive: true })
    await page.screenshot({ path: path.join(output, 'vlan-references.png'), fullPage: true })
    await dialog.getByRole('button', { name: '调整 静态 MAC 02:00:00:00:00:10', exact: true }).click()
    assert.equal(await page.getByRole('tab', { name: 'MAC 地址表', exact: true }).getAttribute('aria-selected'), 'true')
    await page.getByRole('tab', { name: 'VLAN', exact: true }).click()
    assert.equal(await page.getByLabel('VLAN 名称', { exact: true }).nth(1).inputValue(), '保留草稿名称')
    await remove(10).click()
    await dialog.getByRole('button', { name: '调整 IGMP Snooping', exact: true }).click()
    assert.equal(await page.getByRole('tab', { name: 'IGMP', exact: true }).getAttribute('aria-selected'), 'true')
    await page.getByRole('tab', { name: 'VLAN', exact: true }).click()

    await remove(30).click()
    assert.match(await dialog.innerText(), /P9/)
    assert.match(await dialog.innerText(), /端口已关闭，仍保留配置/)
    await dialog.getByRole('button', { name: '返回 VLAN 列表' }).click()
    await remove(20).click()
    assert.equal(await dialog.count(), 0)
    assert.equal(await remove(20).count(), 0)
    assert.equal(await remove(10).count(), 1)
    await page.getByLabel('VLAN ID', { exact: true }).fill('20')
    await page.getByRole('button', { name: '添加 VLAN', exact: true }).click()

    for (const port of [1, 5]) {
      await remove(1).click()
      if (port === 5) assert.equal(await dialog.getByRole('button', { name: '调整 P1', exact: true }).count(), 0)
      await dialog.getByRole('button', { name: `调整 P${port}`, exact: true }).click()
      await page.getByRole('dialog').getByLabel('PVID / Native VLAN').selectOption('20')
      await page.getByRole('dialog').getByRole('button', { name: '完成设置', exact: true }).click()
      await page.getByRole('button', { name: '二层交换', exact: true }).click()
    }
    await remove(1).click()
    assert.equal(await dialog.count(), 0)
    assert.equal(await remove(1).count(), 0)
    await page.getByRole('button', { name: '预览并校验', exact: true }).click()
    await dialog.getByRole('heading', { name: '检查配置变更', exact: true }).waitFor()
    assert.equal(lastPreview.configuration.ports['1'].pvid, 20)
    assert.equal(lastPreview.configuration.ports['5'].pvid, 20)
    assert.deepEqual(lastPreview.configuration.ports['1'].tagged_vlans, [10])
    assert.equal(lastPreview.configuration.vlans.find(v => v.id === 10).name, '保留草稿名称')
    assert.deepEqual(lastPreview.configuration.static_macs, configuration.static_macs)
    assert.deepEqual(lastPreview.configuration.igmp, configuration.igmp)
    assert.deepEqual(requests, ['/api/v1/config/preview'])
    assert.deepEqual(errors, [])
    const report = { passed: true, real_network: false, hardware_access: false,
      checks: ['PVID deletion blocked before draft mutation', 'all explicit VLAN references shown',
        'MAC and IGMP navigation preserves draft', 'disabled port references retained',
        'unused VLAN deletion leaves other configuration unchanged',
        'port migration refreshes dependency list', 'resolved deletion passes production model validation'] }
    await fs.writeFile(path.join(output, 'ui-report.json'), JSON.stringify(report, null, 2) + '\n')
    console.log(JSON.stringify(report))
  } finally { await browser.close() }
})().catch(error => { console.error(error); process.exitCode = 1 })
