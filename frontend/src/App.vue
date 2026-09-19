<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { Activity, ArrowDownToLine, ArrowRight, Cable, Check, ChevronRight, CircleHelp, Cpu, Download, Fan, FileDiff, GitBranch, LayoutDashboard, Layers, LoaderCircle, LogOut, RefreshCw, Router, Save, Settings2, ShieldCheck, Thermometer, Upload, X } from 'lucide-vue-next'
import { api, ApiError, setCsrf } from './api'
import type { Configuration, Job, PortGroup, PortTelemetry } from './types'
import PortGroups from './components/PortGroups.vue'
import PortGroupChanges from './components/PortGroupChanges.vue'
import FanCurveEditor from './components/FanCurveEditor.vue'
import AdministratorSettings from './components/AdministratorSettings.vue'
import OtaUpdates from './components/OtaUpdates.vue'
import RoceSettings from './components/RoceSettings.vue'
import TimeSettings from './components/TimeSettings.vue'
import { useAutoDismiss } from './composables/useAutoDismiss'
import { advanceSampleClock } from './portTelemetry'
import { sensorQuality } from './sensorTelemetry'

const nav = [
  { id: 'overview', label: '设备概览', icon: LayoutDashboard },
  { id: 'ports', label: '端口与光模块', icon: Cable },
  { id: 'l2', label: '二层交换', icon: Layers },
  { id: 'thermal', label: '温度与风扇', icon: Fan },
  { id: 'config', label: '配置管理', icon: FileDiff },
  { id: 'logs', label: '操作日志', icon: Activity },
  { id: 'system', label: '系统与维护', icon: Settings2 },
  { id: 'l3', label: '三层网络', icon: Router },
]
const l2tabs = ['VLAN', 'MAC 地址表', '链路聚合', 'RSTP', 'LLDP', 'IGMP', '流量管理', 'RDMA / RoCE', '端口镜像']
const page = ref('overview'), l2tab = ref('VLAN'), mobileNav = ref(false)
const initialized = ref(false), authenticated = ref(false), booting = ref(true)
const username = ref(''), password = ref(''), mode = ref('mock')
const cfg = ref<Configuration>(), saved = ref(''), revision = ref(1)
const appliedConfiguration = computed<Configuration|undefined>(() => saved.value ? JSON.parse(saved.value) : undefined)
const telemetry = ref<any>({ ports: [], sensors: { temperatures: [], fan: {} }, optics: [] })
const caps = ref<any>({}), system = ref<any>({}), logs = ref<any[]>([]), operational = ref<any>(null)
const updateStatus = ref<any>({enabled:false,state:'reserved'})
const nativeIntegration = computed(() => telemetry.value.native_integration || caps.value.native_integration || {})
const basic100g = computed(() => nativeIntegration.value['startup-mode'] === 'basic100g')
const controlMode = computed(() => mode.value === 'netlab' && nativeIntegration.value['startup-mode'] === 'control')
const writesReady = computed(() => mode.value === 'mock' ||
  (telemetry.value.control_available !== false && nativeIntegration.value['board-hal'] === 'bound' && nativeIntegration.value.synchronized === 'true'))
const recoverySupported = computed(() => nativeIntegration.value.recovery === 'active-replay-v1')
const recovering = computed(() => job.value?.kind === 'control_recovery' && ['queued','running'].includes(job.value.state))
const error = ref(''), notice = ref(''), pendingActions = ref(0), preview = ref<any>(null)
const errorBannerVisible = ref(false), errorSequence = ref(0), noticeSequence = ref(0)
const busy = computed(() => pendingActions.value > 0)
type ConfigAction = 'preview'|'commit'|'confirm'|'rollback'
const configAction = ref<ConfigAction|null>(null), requestStarted = ref(0), requestDetail = ref('')
const requestDialog = ref<HTMLElement|null>(null), previewDialog = ref<HTMLElement|null>(null)
const jobBanner = ref<HTMLElement|null>(null), mainError = ref<HTMLElement|null>(null)
const transactionTrigger = ref<HTMLButtonElement|null>(null)
const transactionVisible = ref(false), previewRequestVisible = ref(false), transactionStarted = ref(0)
const requestVisible = computed(() => transactionVisible.value || previewRequestVisible.value)
const requestInert = computed(() => configAction.value === 'preview' || transactionVisible.value)
let previewFeedbackTimer: ReturnType<typeof setTimeout>|undefined
const requestLabels: Record<ConfigAction, { title: string; detail: string }> = {
  preview: { title: '正在校验配置', detail: '正在检查配置引用并生成差异，完成后将显示预览结果。' },
  commit: { title: '正在提交配置', detail: '正在等待设备返回作业，收到后将自动显示执行状态。' },
  confirm: { title: '正在确认配置', detail: '正在保存确认结果，请稍候。' },
  rollback: { title: '正在恢复配置', detail: '正在请求恢复原配置，请稍候。' },
}
const job = ref<Job|null>(null), bandwidthAck = ref(false), confirmTimeout = ref(60)
const jobAction = computed(() => configAction.value === 'confirm' || configAction.value === 'rollback' ? configAction.value : null)
const bannersBlocked = computed(() => busy.value || requestVisible.value || !!preview.value || !authenticated.value)
const noticeDismissEvents = useAutoDismiss(() => notice.value ? noticeSequence.value : null,
  () => bannersBlocked.value ? 0 : 5000, () => { notice.value = '' })
const errorDismissEvents = useAutoDismiss(() => error.value && errorBannerVisible.value ? errorSequence.value : null,
  () => bannersBlocked.value ? 0 : 10000, () => { errorBannerVisible.value = false })
const jobDismissEvents = useAutoDismiss(() => job.value, () => {
  if (bannersBlocked.value || !job.value || job.value.rollback_failed || !['done','failed','rolled_back'].includes(job.value.state)) return 0
  return job.value.state === 'failed' ? 10000 : 5000
}, () => { job.value = null })
const requestTitle = computed(() => configAction.value ? requestLabels[configAction.value].title :
  error.value ? '操作结果需要核对' : job.value?.state === 'awaiting_confirmation' ? '配置已应用，请确认保留' :
  job.value?.state === 'done' ? '配置已确认' : job.value?.state === 'rolled_back' ? '原配置已恢复' :
  job.value?.state === 'failed' ? '配置执行失败' : job.value?.state === 'running' ? '正在应用并回读配置' : '配置已提交，等待执行')
const requestMessage = computed(() => configAction.value ? requestDetail.value : error.value || job.value?.error || job.value?.message || '正在核对设备作业状态。')
const requestExecuting = computed(() => !!configAction.value || ['queued','running'].includes(job.value?.state || ''))
const now = ref(Date.now() / 1000), selectedPort = ref<number|null>(null)
const monotonicNow = ref(performance.now())
const jobReceived = ref(performance.now())
watch(job, () => { jobReceived.value = performance.now() }, {flush:'sync'})
const telemetryReceipt = ref<{serverTime:number|null; monotonic:number}>({serverTime:null,monotonic:performance.now()})
watch(telemetry, metrics => {
  const times = (metrics.ports || []).map((port:PortTelemetry) => port.sampled_at).filter(Number.isFinite)
  const epoch = metrics.server_time ?? metrics.sampled_at ?? Math.max(0,...times)
  telemetryReceipt.value = {serverTime:Number.isFinite(epoch) && epoch > 0 ? epoch : null,monotonic:performance.now()}
}, {immediate:true,flush:'sync'})
const telemetryNow = computed(() => {
  now.value // Refresh elapsed age even when polling fails or configuration work pauses it.
  return advanceSampleClock(telemetryReceipt.value.serverTime,telemetryReceipt.value.monotonic,performance.now())
})
const portSettingsPort = ref<number|null>(null)
const requestSeconds = computed(() => Math.max(0, Math.floor(now.value - (transactionVisible.value ? transactionStarted.value : requestStarted.value))))
const pwm = ref(50), manualSeconds = ref(60), newVlan = ref(10), newVlanName = ref('')
const vlanDeleteTarget = ref<number|null>(null)
type VlanReference = { kind: 'port'|'mac'|'igmp'; title: string; detail: string; port?: number }
const vlanDeleteReferences = computed(() => vlanDeleteTarget.value === null ? [] : vlanReferences(vlanDeleteTarget.value))
const fdbFilter = ref(''), clearPort = ref<number|null>(null), clearVlan = ref<number|null>(null)
const operationalState = ref<'idle'|'loading'|'loaded'|'error'>('idle')
const fault = ref(''), staleSimulation = ref(false)
let poller: ReturnType<typeof setInterval>|undefined, polling = false
let refreshGeneration = 0
let operationalGeneration = 0
let operationalDue = 0
const operationalFeature = () => ({ 'MAC 地址表': 'fdb', 'LLDP': 'lldp', '链路聚合': 'lags', 'RSTP': 'rstp', 'IGMP': 'igmp', 'RDMA / RoCE': 'roce' } as Record<string, string>)[l2tab.value]
watch(revision, () => { ++operationalGeneration; operational.value = null; operationalState.value = 'idle'; operationalDue = 0 })
const dirty = computed(() => cfg.value && JSON.stringify(cfg.value) !== saved.value)
const stormControllers = computed(() => Object.values(cfg.value?.ports || {}).reduce((n, p) => n + Number(p.ingress_kbps > 0) + Object.values(p.storm).filter(rate => rate > 0).length, 0))
const title = computed(() => nav.find(item => item.id === page.value)?.label || '')
const ports = computed<PortTelemetry[]>(() => telemetry.value.ports || [])
const activePorts = computed(() => ports.value.filter(p => p.active))
const upPorts = computed(() => activePorts.value.filter(p => p.link === 'up').length)
const nominal = computed(() => (cfg.value?.groups || []).reduce((sum, g) => sum + (g.mode === 'split' ? g.lane_speeds.reduce((a, b) => a + Number(b), 0) : Number.parseInt(g.mode)), 0))
const core = computed(() => telemetry.value.sensors?.temperatures?.find((s: any) => s.id === 'fm10840_core'))
const atom = computed(() => telemetry.value.sensors?.temperatures?.find((s: any) => s.id === 'atom_cpu'))
const fan = computed(() => telemetry.value.sensors?.fan || {})
const fanModes: Record<string, string> = { manual: '限时手动测试', hardware_lut: '硬件曲线控制', failsafe: '保护满速', unconfigured: '尚未初始化' }
const fanModeLabel = computed(() => fanModes[String(fan.value.mode)] || '状态不可用')
const fmtPwm = (value: unknown) => typeof value === 'number' && Number.isFinite(value) ? value.toFixed(1) : '—'
const sensorTimestamp = (sensor: any) => sensor?.sampled_at === undefined ? telemetry.value.sensors?.sampled_at : sensor.sampled_at
const measurementQuality = (sensor: any) => {
  const timestamp = sensorTimestamp(sensor)
  return sensorQuality(sensor?.quality ?? telemetry.value.sensors?.quality, timestamp, telemetryNow.value)
}
const countdown = computed(() => {
  const remaining = job.value?.remaining_seconds
  const seconds = typeof remaining === 'number' && Number.isFinite(remaining) ?
    remaining - Math.max(0, monotonicNow.value - jobReceived.value) / 1000 :
    (job.value?.deadline || 0) - (telemetryNow.value ?? now.value)
  return Math.max(0, Math.ceil(seconds))
})
const sensorStale = computed(() => !['valid', 'simulated'].includes(measurementQuality(telemetry.value.sensors)))
const fdbPortLabel = (entry: any) => entry.lag || (entry.port >= 1 && entry.port <= 24 ? `P${entry.port}` : `内部端口 ${entry.port}`)
const fdbAgeLabel = (entry: any) => entry.type === 'static' ? '不老化' :
  (({ young: '近期学习', aging: '等待老化', unknown: '状态不可用' } as Record<string, string>)[String(entry.age_state)] || '状态不可用')
const filteredFdb = computed(() => Array.isArray(operational.value) ? operational.value.filter((entry: any) =>
  `${entry.mac} VLAN ${entry.vlan} ${fdbPortLabel(entry)} ${entry.type}`.toLowerCase().includes(fdbFilter.value.trim().toLowerCase())) : [])
const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value))
const fmtTime = (time?: number) => time ? new Date(time * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '等待采样'
const fmtBytes = (n: number|null) => n == null ? '不可用' : n >= 1e9 ? (n / 1e9).toFixed(2) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(2) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' KB' : (n || 0) + ' B'
const fmtValue = (value: unknown) => value === null ? '未配置' : typeof value === 'object' ? JSON.stringify(value) : String(value)
const quality = (value: string) => ({ simulated: '模拟数据', valid: '有效', stale: '已过期', unavailable: '不可用', pending: '等待采样', unqualified: '待真机验证', invalid_tach: '测速异常' }[value] || value)
const tachDiagnostic = (value: string) => ({ ok: '测速正常', read_failed: '测速读取失败', tach_disabled: '测速输入未启用', controller_standby: '风扇控制器处于待机', unsupported_clock: '测速时钟模式待校准', no_signal: '未检测到测速脉冲，请核对转接线测速针脚', cpld_unavailable: '使用控制器直读测速', cpld_mismatch: '缓存读数不一致，使用控制器直读测速' }[value] || value)
const stateLabel = (state: string) => ({ queued: '等待执行', running: '执行中', awaiting_confirmation: '等待确认', done: '已完成', failed: '执行失败', rolled_back: '已回滚' }[state] || state)
const numbers = (event: Event) => {
  const text = (event.target as HTMLInputElement).value.trim()
  if (!text) return []
  return text.split(/[,，\s]+/).map(Number)
}
function portGroupBase(group: PortGroup) { return [0,1,2,5,6,7].indexOf(group.epl) * 4 + 1 }
function navigate(id: string) {
  page.value = id; mobileNav.value = false
  if (id === 'logs') guard(async () => { logs.value = (await api('/logs')).entries })
  if (id === 'system') guard(async () => { system.value = await api('/system') })
  if (id === 'l2') loadOperational()
}
function showNotice(message = '') {
  notice.value = message; ++noticeSequence.value
}
function showError(message = '') {
  error.value = message; errorBannerVisible.value = !!message; ++errorSequence.value
}
async function guard(action: () => Promise<void>) {
  ++refreshGeneration
  showError(); ++pendingActions.value
  try { await action() } catch (e) { showError(e instanceof Error ? e.message : String(e)) }
  finally { --pendingActions.value }
}
async function runConfigAction(kind: ConfigAction, action: () => Promise<void>) {
  if (configAction.value || busy.value) return
  const trigger = document.activeElement instanceof HTMLElement ? document.activeElement : null
  configAction.value = kind
  now.value = requestStarted.value = Date.now() / 1000
  requestDetail.value = requestLabels[kind].detail
  if (kind === 'preview') {
    previewFeedbackTimer = setTimeout(async () => {
      previewRequestVisible.value = true
      await nextTick()
      requestDialog.value?.focus({ preventScroll:true })
    }, 350)
  } else if (kind === 'commit') {
    transactionStarted.value = requestStarted.value
    transactionVisible.value = true
  }
  try {
    await guard(async () => {
      await nextTick()
      requestDialog.value?.focus({ preventScroll: true })
      await action()
    })
  } finally {
    if (previewFeedbackTimer) clearTimeout(previewFeedbackTimer)
    previewRequestVisible.value = false
    configAction.value = null
    await nextTick()
    if (transactionVisible.value) requestDialog.value?.focus({ preventScroll: true })
    else if (preview.value) previewDialog.value?.focus({ preventScroll: true })
    else if (error.value) {
      mainError.value?.focus({ preventScroll: true })
      mainError.value?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    } else if (kind !== 'preview' && job.value) jobBanner.value?.focus({ preventScroll: true })
    else if (trigger?.isConnected && !trigger.hasAttribute('disabled')) trigger.focus({ preventScroll: true })
  }
}
async function openTransaction() {
  if (job.value?.kind !== 'configuration') return
  transactionVisible.value = true
  await nextTick()
  requestDialog.value?.focus({ preventScroll: true })
}
async function closeTransaction() {
  if (busy.value) return
  transactionVisible.value = false
  await nextTick()
  if (preview.value) previewDialog.value?.focus({preventScroll:true})
  else (transactionTrigger.value || jobBanner.value)?.focus({preventScroll:true})
}
function expireSession() {
  ++refreshGeneration; ++operationalGeneration
  setCsrf(''); authenticated.value = false; cfg.value = undefined
  job.value = null; transactionVisible.value = false; preview.value = null
  transactionStarted.value = 0; showNotice(); showError()
  password.value = ''
}
async function loadConfig(isCurrent: () => boolean = () => true) {
  const result = await api('/config')
  const pendingJob = result.pending?.job_id ? await api('/jobs/' + result.pending.job_id) : null
  if (!isCurrent()) return
  cfg.value = clone(result.configuration); revision.value = result.revision
  saved.value = JSON.stringify(cfg.value)
  if (pendingJob) {
    if (job.value?.id !== pendingJob.id) transactionStarted.value = Date.now() / 1000
    job.value = pendingJob
  }
}
async function load() {
  const [capabilities, metrics, updates] = await Promise.all([api('/capabilities'), api('/telemetry'), api('/updates')])
  caps.value = capabilities; telemetry.value = metrics; mode.value = capabilities.mode; updateStatus.value = updates
  await loadConfig()
}
async function login() {
  await guard(async () => {
    const result = await api(initialized.value ? '/auth/login' : '/auth/setup', { username: username.value, password: password.value })
    setCsrf(result.csrf); password.value = ''; authenticated.value = true; initialized.value = true
    await load()
  })
}
async function logout() {
  await guard(async () => { try { await api('/auth/logout', {}) } finally { expireSession() } })
}
async function makePreview() {
  if (!writesReady.value) { showError(controlMode.value ? '硬件控制暂不可用，请先恢复控制。' : '当前运行模式尚未开放配置编辑。'); return }
  await runConfigAction('preview', async () => {
    preview.value = await api('/config/preview', { expected_revision: revision.value, configuration: cfg.value })
    bandwidthAck.value = false
  })
}
async function recoverControl() {
  if (busy.value || recovering.value) return
  await guard(async () => {
    job.value = await api('/control/recover', {})
    preview.value = null
  })
}
async function commit() {
  if (!preview.value || busy.value || configAction.value) return
  job.value = null
  await runConfigAction('commit', async () => {
    job.value = await api('/config/commit', { draft_id: preview.value.id, confirm_timeout: confirmTimeout.value, accept_bandwidth_warning: bandwidthAck.value })
    preview.value = null
  })
}
async function finish(action: 'confirm'|'rollback') {
  if (!job.value || job.value.state !== 'awaiting_confirmation') return
  await runConfigAction(action, async () => {
    const id = job.value!.id
    await api('/jobs/' + id + '/' + action, {})
    requestDetail.value = action === 'confirm' ? '正在读取已确认的配置与设备状态。' : '正在读取恢复后的配置与设备状态。'
    const result = await api('/jobs/' + id)
    await loadConfig()
    telemetry.value = await api('/telemetry')
    job.value = result
    if (['done','rolled_back'].includes(result.state)) transactionVisible.value = false
  })
}
async function poll() {
  now.value = Date.now() / 1000
  monotonicNow.value = performance.now()
  if (!authenticated.value || polling || busy.value) return
  polling = true
  const generation = refreshGeneration
  const isCurrent = () => generation === refreshGeneration && !busy.value && authenticated.value
  try {
    const metrics = await api('/telemetry')
    if (!isCurrent()) return
    telemetry.value = metrics
    if (job.value && ['queued', 'running', 'awaiting_confirmation'].includes(job.value.state)) {
      const id = job.value.id, previous = job.value.state
      const result = await api('/jobs/' + id)
      const jobIsCurrent = () => isCurrent() && job.value?.id === id
      if (!jobIsCurrent()) return
      const finished = previous !== result.state && ['done', 'rolled_back'].includes(result.state)
      if (finished && ['configuration','control_recovery'].includes(result.kind)) await loadConfig(jobIsCurrent)
      if (jobIsCurrent()) {
        job.value = result
        if (finished && result.kind === 'configuration') transactionVisible.value = false
        if (finished && result.kind === 'control_recovery') {
          telemetry.value = await api('/telemetry')
          showNotice('硬件已同步，控制已恢复。')
        }
        if (finished && result.kind === 'clear_dynamic_fdb' && page.value === 'l2' && l2tab.value === 'MAC 地址表')
          await loadOperational()
      }
    }
    if (isCurrent() && page.value === 'l2' && l2tab.value === 'RDMA / RoCE' &&
        document.visibilityState === 'visible' && operationalState.value !== 'loading' &&
        !['queued','running','awaiting_confirmation'].includes(job.value?.state || '') &&
        performance.now() >= operationalDue) await readOperational(true)
  } catch (e) {
    if (e instanceof ApiError && e.code === 'superseded_session') return
    if (isCurrent()) telemetry.value.error = e instanceof Error ? e.message : String(e)
  }
  finally { polling = false }
}
async function loadOperational() { await readOperational(false) }
async function readOperational(background: boolean) {
  const request = ++operationalGeneration
  const feature = operationalFeature(), requestedRevision = revision.value
  if (!background) operational.value = null
  operationalState.value = feature ? 'loading' : 'idle'
  const current = () => request === operationalGeneration && authenticated.value &&
    page.value === 'l2' && operationalFeature() === feature && revision.value === requestedRevision
  const read = async () => {
    try {
      const result = await api('/operational/' + feature)
      if (current()) {
        operational.value = feature === 'roce' ? {...result.data, server_time:result.server_time} : result.data
        operationalState.value = 'loaded'
      }
    } catch (e) {
      if (current()) { operational.value = null; operationalState.value = 'error'; if (!background) throw e }
    } finally {
      if (current()) operationalDue = performance.now() + 10000
    }
  }
  if (feature) { if (background) await read(); else await guard(read) }
}
function addVlan() {
  if (!cfg.value) return
  if (!Number.isInteger(newVlan.value) || newVlan.value < 1 || newVlan.value > 4094 || cfg.value.vlans.some(v => v.id === newVlan.value)) { showError('请输入未使用的 VLAN ID（1–4094）'); return }
  cfg.value.vlans.push({ id: newVlan.value, name: newVlanName.value }); newVlan.value++; newVlanName.value = ''
}
function vlanReferences(vlan: number): VlanReference[] {
  if (!cfg.value) return []
  const references: VlanReference[] = []
  for (const [id, port] of Object.entries(cfg.value.ports)) {
    const uses = []
    if (port.pvid === vlan) uses.push('PVID / Native VLAN')
    if (port.tagged_vlans.includes(vlan)) uses.push('Tagged VLAN')
    if (!uses.length) continue
    const lag = cfg.value.lags.find(group => group.members.includes(Number(id)))
    references.push({ kind: 'port', port: Number(id), title: `P${id}${port.name ? ' · ' + port.name : ''}`,
      detail: uses.join('、') + (port.enabled ? '' : '（端口已关闭，仍保留配置）') +
        (lag ? `；${lag.name} 成员，修改时请保持聚合成员的 VLAN 配置一致` : '') })
  }
  for (const entry of cfg.value.static_macs.filter(entry => entry.vlan === vlan))
    references.push({ kind: 'mac', title: `静态 MAC ${entry.mac}`, detail: `VLAN ${vlan} → P${entry.port}` })
  if (cfg.value.igmp.vlans.includes(vlan))
    references.push({ kind: 'igmp', title: 'IGMP Snooping', detail: `侦听 VLAN ${vlan}` })
  for (const group of cfg.value.igmp.static_groups.filter(group => group.vlan === vlan))
    references.push({ kind: 'igmp', title: `静态组播 ${group.address}`, detail: group.ports.map(port => `P${port}`).join('、') })
  return references
}
function deleteVlan(vlan: number) {
  if (!cfg.value) return
  showError(); showNotice()
  if (vlanReferences(vlan).length) { vlanDeleteTarget.value = vlan; return }
  cfg.value.vlans = cfg.value.vlans.filter(entry => entry.id !== vlan)
  preview.value = null
  showNotice(`已从草稿中删除 VLAN ${vlan}，预览并提交后生效。`)
}
function editVlanReference(reference: VlanReference) {
  vlanDeleteTarget.value = null
  if (reference.kind === 'port') {
    navigate('ports'); selectedPort.value = reference.port!; portSettingsPort.value = reference.port!
  } else {
    l2tab.value = reference.kind === 'mac' ? 'MAC 地址表' : 'IGMP'
    navigate('l2')
  }
}
function addLag() {
  const names = new Set(cfg.value!.lags.map(l => l.name))
  const id = Array.from({ length: 64 }, (_, i) => i).find(i => !names.has('ae' + i))
  if (id !== undefined) cfg.value!.lags.push({ name: 'ae' + id, members: [], mode: 'active', minimum_links: 1, periodic: 'fast' })
}
async function downloadBackup() {
  await guard(async () => {
    const backup = await api('/backups/export')
    const href = URL.createObjectURL(new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = href; link.download = 'fm10k-config-r' + revision.value + '.json'; link.click(); URL.revokeObjectURL(href)
    showNotice('配置备份已导出，不包含管理员密码或会话。')
  })
}
async function restore(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]
  if (!file) return
  await runConfigAction('preview', async () => {
    if (file.size > 2_000_000) throw new Error('备份超过 2 MB 限制')
    preview.value = await api('/backups/preview', JSON.parse(await file.text()))
    cfg.value = clone(preview.value.configuration); bandwidthAck.value = false
  })
  input.value = ''
}
async function manualFan() {
  await guard(async () => { job.value = await api('/fans/manual', { pwm_percent: pwm.value, duration_seconds: manualSeconds.value }) })
}
async function injectFault() {
  await guard(async () => { await api('/simulation/fault', { phase: fault.value || null, sensor_error: staleSimulation.value }); showNotice('模拟故障设置已应用；不会访问真实硬件。') })
}
onMounted(async () => {
  window.addEventListener('fm10k-session-expired',expireSession)
  await guard(async () => {
    const session = await api('/auth/session')
    initialized.value = session.initialized; authenticated.value = session.authenticated; mode.value = session.mode
    if (session.authenticated) { setCsrf(session.csrf); username.value = session.username; await load() }
  })
  booting.value = false; poller = setInterval(poll, 1000)
})
onUnmounted(() => {
  if (poller) clearInterval(poller)
  if (previewFeedbackTimer) clearTimeout(previewFeedbackTimer)
  window.removeEventListener('fm10k-session-expired',expireSession)
})
</script>

<template>
  <div v-if="booting" class="loading-screen"><Cpu :size="32" /><span>正在连接控制面…</span></div>
  <div v-else-if="!authenticated" class="login-screen">
    <div class="login-intro"><div class="brand-mark"><GitBranch :size="26" /></div><p class="eyebrow">FM10K / CONTROL PANEL</p><h1>交换网络，<br>尽在掌握。</h1><p>FM10840 二层交换管理<br>双 300G OBT · Debian 13</p><div class="login-lines"><i v-for="n in 12" :key="n"></i></div><small>PE31625G24DiRA · 双 OBT</small></div>
    <form class="login-card" @submit.prevent="login"><span class="tag">{{ mode === 'mock' ? '模拟环境' : '设备管理' }}</span><h2>{{ initialized ? '登录控制面板' : '创建首个管理员' }}</h2><p>{{ initialized ? '使用你的管理员账户继续。' : '设置管理账户后即可开始配置，密码至少 12 位。' }}</p><label>用户名<input v-model="username" autocomplete="username" minlength="3" maxlength="64" required placeholder="admin" /></label><label>密码<input v-model="password" type="password" :autocomplete="initialized ? 'current-password' : 'new-password'" minlength="12" maxlength="256" required placeholder="至少 12 位字符" /></label><div v-if="error" class="alert danger" role="alert">{{ error }}</div><button class="primary wide" :disabled="busy">{{ busy ? '正在连接…' : initialized ? '登录' : '创建管理员并进入' }}<ArrowRight :size="17" /></button><small>管理账户仅用于本机面板。首次访问请使用可信管理网络。</small></form>
  </div>
  <div v-else class="shell">
    <button v-if="mobileNav" class="nav-backdrop" aria-label="收起导航" @click="mobileNav = false"></button>
    <aside :inert="requestInert || !!jobAction" id="main-navigation" :class="['sidebar', { open: mobileNav }]">
      <a class="brand" href="#" @click.prevent="navigate('overview')"><span class="brand-mark"><GitBranch :size="22" /></span><span>fm10k<span class="brand-caption">CONTROL PANEL</span></span></a>
      <div class="device-label"><span class="status-dot"></span> PE31625G24DiRA <span class="muted">01</span></div>
      <p class="nav-caption">设备管理</p>
      <nav><button v-for="item in nav" :key="item.id" :class="['nav-item', { active: page === item.id }]" @click="navigate(item.id)"><component :is="item.icon" :size="18" /><span>{{ item.label }}</span><span v-if="item.id === 'l3'" class="soon">预留</span><ChevronRight v-else-if="page === item.id" :size="14" /></button></nav>
      <div class="sidebar-bottom"><div><span class="status-dot" :class="{ amber: mode === 'mock' }"></span>{{ mode === 'mock' ? '模拟设备已连接' : '原生控制面' }}</div><small>Debian 13 · IES 4.3.2 目标</small><div class="profile"><span class="avatar">{{ username.slice(0, 1).toUpperCase() }}</span><span>{{ username }}<small>管理员</small></span><button class="icon-button" title="退出登录" aria-label="退出登录" @click="logout"><LogOut :size="16" /></button></div></div>
    </aside>
    <main :inert="requestInert">
      <header class="topbar"><button class="icon-button menu-button" aria-label="展开导航" :aria-expanded="mobileNav" aria-controls="main-navigation" @click="mobileNav = !mobileNav"><Layers :size="20" /></button><span>控制面板</span><ChevronRight :size="14" /><strong>{{ title }}</strong><div class="topbar-right"><span class="mono">CONFIG r{{ revision }}</span><span class="tag" :class="{ amber: mode === 'mock' }">{{ mode === 'mock' ? '模拟模式' : '真机待验收' }}</span></div></header>
      <div class="content">
        <div class="page-heading"><div><p class="eyebrow">FM10840 / {{ page.toUpperCase() }}</p><h1>{{ title }}</h1><p class="subtitle">{{ page === 'overview' ? '查看交换状态、端口资源与板卡运行情况。' : '所有配置变更均经过预览、校验与确认后保存。' }}</p></div><button class="secondary" :disabled="busy" @click="guard(async () => { telemetry = await api('/telemetry'); showNotice('已刷新缓存数据') })"><RefreshCw :size="15" />刷新状态</button></div>
        <div v-if="mode === 'mock'" class="environment-note"><CircleHelp :size="16" /><span>当前为模拟设备。链路、计数器与传感器数据用于功能演示，真机验收尚未完成。</span><span class="mono">SIMULATED</span></div>
        <div v-else-if="basic100g" class="environment-note"><Cable :size="18" /><span><strong>100G 连通测试</strong> · P1 / P5 / P9 / P13 / P17 / P21 已配置为 100G，VLAN 1 无标签。页面显示实际链路与计数器；固定配置暂不可编辑。此阶段未启用环路协议，请使用独立测试链路。</span></div>
        <div v-else-if="!writesReady && controlMode" class="environment-note control-recovery" role="status"><CircleHelp :size="16" /><span><strong>硬件控制暂不可用</strong>：配置同步尚未完成或服务通信异常。恢复会核对已保存配置，并处理已超时的未确认变更；成功后重新加载配置。<small v-if="!recoverySupported">需要配套原生更新才能使用恢复按钮。</small></span><button class="secondary" :disabled="busy || recovering || !recoverySupported || ['queued','running'].includes(job?.state || '')" @click="recoverControl"><RefreshCw :class="{spin:recovering}" :size="15" />{{ recovering ? '正在恢复…' : '恢复控制' }}</button></div>
        <div v-else-if="!writesReady" class="environment-note"><CircleHelp :size="16" /><span>当前为硬件观测模式，配置编辑尚未开放。</span></div>
        <div v-if="telemetry.error" class="alert warning" role="status">采样异常：{{ telemetry.error }}。旧数据已标记，请检查控制面连接。</div>
        <div v-if="error && errorBannerVisible" ref="mainError" v-on="errorDismissEvents" tabindex="-1" class="alert danger" role="alert"><span>{{ error }}</span><button class="icon-button" aria-label="关闭错误" @click="showError()"><X :size="16" /></button></div>
        <div v-if="notice" v-on="noticeDismissEvents" class="alert success" role="status"><span>{{ notice }}</span><button class="icon-button" aria-label="关闭提示" @click="showNotice()"><X :size="16" /></button></div>
        <div v-if="job" ref="jobBanner" v-on="jobDismissEvents" tabindex="-1" class="job-banner" role="region" aria-label="作业状态" :class="{ failed: job.state === 'failed', pending: job.state === 'awaiting_confirmation', executing: !!jobAction || ['queued', 'running'].includes(job.state) }">
          <LoaderCircle v-if="jobAction || ['queued', 'running'].includes(job.state)" class="spin" :size="20" aria-hidden="true" /><Activity v-else :size="19" />
          <div class="job-banner-message" role="status" aria-live="polite"><strong>{{ jobAction ? requestLabels[jobAction].title : stateLabel(job.state) }}</strong><p>{{ jobAction ? requestDetail : job.message }}<span v-if="job.error && !jobAction"> · {{ job.error }}</span><span v-if="job.rollback_failed"> · 局部恢复失败，受影响端口组保持关闭</span></p></div>
          <div class="job-banner-actions">
            <span v-if="job.state === 'awaiting_confirmation'" class="countdown">{{ countdown }}s</span>
            <button v-if="job.kind === 'configuration'" ref="transactionTrigger" class="secondary job-details" aria-haspopup="dialog" aria-controls="configuration-progress" :aria-expanded="transactionVisible" @click="openTransaction">{{ ['done','failed','rolled_back'].includes(job.state) ? '查看结果' : '查看进度' }}</button>
            <template v-if="job.state === 'awaiting_confirmation'"><button class="secondary" :disabled="busy" @click="finish('rollback')">{{ jobAction === 'rollback' ? '正在恢复…' : '恢复原配置' }}</button><button class="primary" :disabled="busy" @click="finish('confirm')"><Check :size="16" />{{ jobAction === 'confirm' ? '正在确认…' : '确认保留' }}</button></template>
            <button v-else-if="['done', 'failed', 'rolled_back'].includes(job.state)" class="icon-button job-close" aria-label="关闭任务" @click="job = null"><X :size="16" /></button>
          </div>
        </div>
        <div v-if="cfg" class="page-body" :inert="!!jobAction">
          <section v-if="page === 'overview'" class="overview">
            <div class="metrics-grid"><article class="metric"><div><span>在线端口</span><Cable :size="18" /></div><strong>{{ upPorts }}<small>/ {{ activePorts.length }}</small></strong><p><span class="status-dot"></span>{{ activePorts.length }} 个活动槽位 · 24 个固定槽位</p></article><article class="metric"><div><span>外部标称带宽</span><ArrowDownToLine :size="18" /></div><strong>{{ nominal }}<small>Gbps</small></strong><p>实际整卡吞吐等待流量测试</p></article><article class="metric"><div><span>交换芯片温度</span><Thermometer :size="18" /></div><strong>{{ core?.celsius?.toFixed(1) ?? '—' }}<small>°C</small></strong><p :class="{ 'text-warning': sensorStale }">{{ sensorStale ? '数据不可用或已过期' : 'LM96163 · ' + fmtTime(telemetry.sensors.sampled_at) }}</p></article><article class="metric"><div><span>Atom CPU 温度</span><Cpu :size="18" /></div><strong>{{ atom?.celsius?.toFixed(1) ?? '—' }}<small>°C</small></strong><p :class="{ 'text-warning': measurementQuality(atom) !== 'valid' && measurementQuality(atom) !== 'simulated' }">{{ quality(measurementQuality(atom)) }} · {{ fmtTime(sensorTimestamp(atom)) }}</p></article><article class="metric"><div><span>风扇转速</span><Fan :size="18" /></div><strong>{{ fan.rpm ?? '—' }}<small>{{ fan.rpm_estimated ? 'RPM · 估算' : 'RPM' }}</small></strong><p>PWM {{ fmtPwm(fan.pwm_percent) }}% · {{ fanModeLabel }}</p></article></div>
            <section class="card topology"><div class="card-heading"><div><h2>端口拓扑</h2><p>2 × 300G OBT / 6 个 EPL / 24 条通道</p></div><div class="legend"><span><i class="dot green"></i>在线</span><span><i class="dot gray"></i>关闭</span><span><i class="dot hollow"></i>合口占用</span></div></div>
              <div class="modules"><article v-for="mpo in [1, 2]" :key="mpo" class="module"><div class="module-heading"><strong>OBT {{ mpo }} <span>/ MPO {{ mpo }}</span></strong><span class="tag">300G</span></div><div class="epl-row"><div v-for="g in cfg.groups.slice((mpo - 1) * 3, mpo * 3)" :key="g.epl" class="epl"><div class="epl-label">EPL {{ g.epl }}<small>{{ g.mode === 'split' ? '4 × Lane' : '1 × ' + g.mode.toUpperCase() }}</small></div><div class="lane-grid"><button v-for="lane in [0, 1, 2, 3]" :key="lane" :class="['lane', { up: ports.find(p => p.id === portGroupBase(g) + lane)?.link === 'up', inactive: g.mode !== 'split' && lane > 0 }]" :aria-label="'编辑端口 ' + (portGroupBase(g) + lane)" @click="selectedPort = portGroupBase(g) + lane; navigate('ports')"><i></i><span>{{ String(portGroupBase(g) + lane).padStart(2, '0') }}</span></button></div><span class="lane-caption">{{ g.mode === 'split' ? g.lane_speeds.join(' / ') + ' G' : 'Lane 0–3 合口' }}</span></div></div><footer><span class="status-dot"></span>12 条双工光通道 <span class="mono">MUX 0x0{{ mpo }}</span></footer></article></div>
              <div class="card-footer"><span>合口与拆分按 EPL 独立操作；LACP 在「二层交换」中配置。</span><button class="text-button" @click="navigate('ports')">管理端口<ArrowRight :size="15" /></button></div>
            </section>
            <div class="two-column"><section class="card"><div class="card-heading"><div><h2>温度监测</h2><p>每 5 秒采样，浏览器读取缓存</p></div><Thermometer :size="19" /></div><div v-for="sensor in telemetry.sensors.temperatures" :key="sensor.id" class="sensor-row"><span>{{ sensor.label }}<small>{{ sensor.source }} · {{ quality(measurementQuality(sensor)) }} · {{ fmtTime(sensorTimestamp(sensor)) }}</small></span><div class="temperature-track"><i :style="{ width: Math.min(sensor.celsius, 100) + '%' }"></i></div><strong>{{ sensor.celsius?.toFixed(1) ?? '—' }}<small> °C</small></strong></div><p class="footnote">{{ quality(telemetry.sensors.quality) }} · {{ fmtTime(telemetry.sensors.sampled_at) }}</p></section><section class="card"><div class="card-heading"><div><h2>配置与能力</h2><p>当前生效配置 r{{ revision }}</p></div><ShieldCheck :size="19" /></div><div class="definition-row"><span>二层交换</span><span>VLAN · LACP · RSTP · LLDP · IGMP</span></div><div class="definition-row"><span>端口模型</span><span>固定 24 槽位 / 10–100G</span></div><div class="definition-row"><span>转发吞吐验收</span><span class="tag amber">待真机验证</span></div><div class="definition-row"><span>三层能力</span><span class="muted">尚未启用</span></div><button class="text-button" @click="navigate('config')">查看配置与版本<ArrowRight :size="15" /></button></section></div>
          </section>

          <PortGroups v-if="page === 'ports'" :configuration="cfg" :applied-configuration="appliedConfiguration || cfg" :ports="ports" :optics="telemetry.optics || []" :temperatures="telemetry.sensors.temperatures || []"
            :modal-blocked="requestInert || !!preview"
            v-model:selected-port="selectedPort" v-model:settings-port="portSettingsPort" :sample-now="telemetryNow" :sampling-error="telemetry.error"
            :sample-interval="telemetry.port_sample_interval_seconds || 1" :stale-after="telemetry.port_stale_after_seconds || 3"
            :disabled="!writesReady || busy || ['queued','running','awaiting_confirmation'].includes(job?.state || '')" />

          <section v-if="page === 'l2'" class="stack">
            <div class="tabs" role="tablist"><button v-for="tab in l2tabs" :key="tab" role="tab" :aria-selected="l2tab === tab" :class="{ active: l2tab === tab }" @click="l2tab = tab; loadOperational()">{{ tab }}</button></div>
            <section v-if="l2tab === 'VLAN'" class="card"><div class="card-heading"><div><h2>802.1Q VLAN</h2><p>Access / Trunk、PVID、Native VLAN 与 Tagged 成员在端口配置中设置。</p></div><span class="tag">{{ cfg.vlans.length }} 个 VLAN</span></div><div class="inline-form"><label>VLAN ID<input v-model.number="newVlan" type="number" min="1" max="4094" /></label><label>名称<input v-model="newVlanName" maxlength="64" placeholder="例如：业务网络" /></label><button class="secondary" @click="addVlan">添加 VLAN</button></div><div class="table-wrap"><table><thead><tr><th>VLAN ID</th><th>名称</th><th>Untagged / Native</th><th>Tagged</th><th></th></tr></thead><tbody><tr v-for="v in cfg.vlans" :key="v.id"><td class="mono">{{ v.id }}</td><td><input v-model="v.name" maxlength="64" aria-label="VLAN 名称" /></td><td>{{ Object.entries(cfg.ports).filter(([,p]) => p.pvid === v.id).map(([id]) => 'P' + id).join(', ') || '—' }}</td><td>{{ Object.entries(cfg.ports).filter(([,p]) => p.tagged_vlans.includes(v.id)).map(([id]) => 'P' + id).join(', ') || '—' }}</td><td><button class="text-button destructive" :disabled="busy" :aria-label="'删除 VLAN ' + v.id" @click="deleteVlan(v.id)">删除</button></td></tr></tbody></table></div></section>
            <section v-if="l2tab === 'MAC 地址表'" class="card"><div class="card-heading"><div><h2>MAC 地址表</h2><p>静态条目经配置事务写入；清理操作仅删除动态学习条目。</p></div><button class="secondary" @click="loadOperational"><RefreshCw :size="15" />刷新</button></div><div class="inline-form"><label>老化时间（秒）<input v-model.number="cfg.mac_aging_seconds" type="number" min="10" max="1000000" /></label><label>查询<input v-model="fdbFilter" placeholder="MAC / VLAN / 端口" /></label></div><div class="table-wrap"><table><thead><tr><th>MAC</th><th>VLAN</th><th>接口</th><th>类型</th><th>老化状态</th></tr></thead><tbody><tr v-for="(m,i) in filteredFdb" :key="i"><td class="mono">{{ m.mac }}</td><td>{{ m.vlan }}</td><td>{{ fdbPortLabel(m) }}</td><td>{{ m.type }}</td><td>{{ fdbAgeLabel(m) }}</td></tr><tr v-if="!filteredFdb.length"><td colspan="5" class="empty">{{ operationalState === 'loading' ? '正在读取 MAC 地址表…' : operationalState === 'error' ? 'MAC 地址表读取失败，请刷新重试' : '暂无匹配的已学习条目' }}</td></tr></tbody></table></div><div class="subsection"><h3>静态 MAC 配置</h3><div v-for="(m,i) in cfg.static_macs" :key="i" class="inline-form"><label>MAC<input v-model="m.mac" placeholder="02:00:00:00:00:01" /></label><label>VLAN<input v-model.number="m.vlan" type="number" min="1" max="4094" /></label><label>端口<input v-model.number="m.port" type="number" min="1" max="24" /></label><button class="text-button destructive" @click="cfg.static_macs.splice(i,1)">删除</button></div><button class="secondary" @click="cfg.static_macs.push({ mac: '', vlan: 1, port: 1 })">添加静态条目</button></div><div class="subsection"><h3>清理动态条目</h3><div class="inline-form"><label>端口<select v-model="clearPort"><option :value="null">全部端口</option><option v-for="p in activePorts" :key="p.id" :value="p.id">P{{ p.id }}</option></select></label><label>VLAN<select v-model="clearVlan"><option :value="null">全部 VLAN</option><option v-for="v in cfg.vlans" :key="v.id" :value="v.id">{{ v.id }}</option></select></label><button class="secondary" :disabled="busy" @click="guard(async () => { job = await api('/fdb/clear', { port: clearPort, vlan: clearVlan }) })">清理动态 MAC</button></div></div></section>
            <section v-if="l2tab === '链路聚合'" class="card"><div class="card-heading"><div><h2>链路聚合 / LACP</h2><p>成员速率、MTU 和 VLAN 配置必须一致。此处组合独立以太网端口。</p></div><button class="secondary" @click="addLag">添加 LAG</button></div><div v-if="!cfg.lags.length" class="empty"><GitBranch :size="28" /><h3>尚未配置聚合组</h3><p>通过 LACP 或静态 LAG 提供链路冗余与负载分担。</p></div><div v-for="(lag,i) in cfg.lags" :key="lag.name" class="subsection"><div class="inline-form"><label>聚合接口<input v-model="lag.name" pattern="ae[0-9]+" /></label><label>模式<select v-model="lag.mode"><option value="active">LACP 主动</option><option value="passive">LACP 被动</option><option value="static">静态 LAG</option></select></label><label>成员端口<input :value="lag.members.join(',')" placeholder="1,5" @change="lag.members = numbers($event)" /></label><label>最少链路<input v-model.number="lag.minimum_links" type="number" min="1" max="16" /></label><label>周期<select v-model="lag.periodic"><option value="fast">快速（1 秒）</option><option value="slow">慢速（30 秒）</option></select></label><button class="text-button destructive" @click="cfg.lags.splice(i,1)">删除</button></div></div><div v-if="Array.isArray(operational) && operational.length" class="subsection"><h3>运行状态</h3><div v-for="lag in operational" :key="lag.name" class="definition-row"><span>{{ lag.name }}</span><span>{{ lag.state }} · {{ lag.mode === 'static' ? '静态聚合' : lag.synchronized == null ? '同步状态不可用' : lag.synchronized ? '已同步' : '未同步' }}</span></div></div></section>
            <section v-if="l2tab === 'RSTP'" class="card"><div class="card-heading"><div><h2>快速生成树</h2><p>环路保护与拓扑收敛。边缘端口和 BPDU 保护在端口配置中调整。</p></div></div><div class="form-grid"><label class="check"><input v-model="cfg.rstp.enabled" type="checkbox" />启用 RSTP</label><label>桥优先级<select v-model.number="cfg.rstp.bridge_priority"><option v-for="n in 16" :key="n" :value="(n-1)*4096">{{ (n-1)*4096 }}</option></select></label></div><div class="table-wrap"><table><thead><tr><th>端口</th><th>边缘端口</th><th>BPDU 保护</th><th>路径开销（0=自动）</th><th>端口优先级</th></tr></thead><tbody><tr v-for="p in activePorts" :key="p.id"><td>P{{ p.id }}</td><td><input v-model="cfg.ports[p.id]!.edge" type="checkbox" :aria-label="'P'+p.id+' 边缘端口'" /></td><td><input v-model="cfg.ports[p.id]!.bpdu_guard" type="checkbox" :aria-label="'P'+p.id+' BPDU 保护'" /></td><td><input v-model.number="cfg.ports[p.id]!.path_cost" type="number" min="0" max="200000000" aria-label="路径开销" /></td><td><input v-model.number="cfg.ports[p.id]!.port_priority" type="number" min="0" max="240" step="16" aria-label="端口优先级" /></td></tr></tbody></table></div><p class="footnote">协议状态以原生服务回读为准；模拟模式不产生真实 BPDU。</p></section>
            <section v-if="l2tab === 'LLDP'" class="card"><div class="card-heading"><div><h2>邻居发现</h2><p>逐端口开关可在端口配置中设置。邻居记录保留真实入口端口。</p></div><button class="secondary" @click="loadOperational">刷新邻居</button></div><div class="form-grid"><label class="check"><input v-model="cfg.lldp.enabled" type="checkbox" />启用 LLDP 收发</label><label>发送间隔（秒）<input v-model.number="cfg.lldp.transmit_interval" type="number" min="5" max="3600" /></label><label>保持倍数<input v-model.number="cfg.lldp.hold_multiplier" type="number" min="2" max="10" /></label></div><div class="table-wrap"><table><thead><tr><th>本地端口</th><th>远端设备</th><th>远端端口</th><th>剩余时间</th></tr></thead><tbody><tr v-for="(n,i) in (Array.isArray(operational) ? operational : [])" :key="i"><td>{{ n.port || n.local_port }}</td><td>{{ n.system_name || n.chassis_id }}</td><td>{{ n.port_id }}</td><td>{{ n.ttl }}s</td></tr><tr v-if="!operational?.length"><td class="empty" colspan="4">暂无 LLDP 邻居</td></tr></tbody></table></div></section>
            <section v-if="l2tab === 'IGMP'" class="card"><div class="card-heading"><div><h2>IGMP Snooping v1 / v2</h2><p>网络中需要已有查询器。fast-leave 默认关闭，仅用于明确的直连接收端口。</p></div></div><div class="form-grid"><label class="check"><input v-model="cfg.igmp.enabled" type="checkbox" />启用 IGMP Snooping</label><label>侦听 VLAN<input :value="cfg.igmp.vlans.join(',')" placeholder="10,20" @change="cfg.igmp.vlans = numbers($event)" /></label><label>路由器端口<input :value="cfg.igmp.router_ports.join(',')" placeholder="1,5" @change="cfg.igmp.router_ports = numbers($event)" /></label><label>成员老化时间（秒）<input v-model.number="cfg.igmp.membership_timeout" type="number" min="10" max="3600" /></label><label>fast-leave 端口<input :value="cfg.igmp.fast_leave_ports.join(',')" placeholder="默认不启用" @change="cfg.igmp.fast_leave_ports = numbers($event)" /></label></div><div class="subsection"><h3>静态组播</h3><div v-for="(g,i) in cfg.igmp.static_groups" :key="i" class="inline-form"><label>组地址<input v-model="g.address" placeholder="239.1.1.1" /></label><label>VLAN<input v-model.number="g.vlan" type="number" min="1" max="4094" /></label><label>成员端口<input :value="g.ports.join(',')" @change="g.ports = numbers($event)" /></label><button class="text-button destructive" @click="cfg.igmp.static_groups.splice(i,1)">删除</button></div><button class="secondary" @click="cfg.igmp.static_groups.push({ address: '', vlan: 1, ports: [] })">添加静态组播</button></div><div class="subsection"><h3>已知组成员</h3><div v-for="(g,i) in (Array.isArray(operational) ? operational : [])" :key="i" class="definition-row"><span>{{ g.address }} / VLAN {{ g.vlan }}</span><span>成员：{{ (g.listener_ports ?? g.ports)?.join(', ') || '无' }}<template v-if="g.pending_listener_ports?.length"> · 待确认成员：{{ g.pending_listener_ports.join(', ') }}</template><template v-if="g.retiring_listener_ports?.length"> · 待清理成员：{{ g.retiring_listener_ports.join(', ') }}</template><template v-if="g.router_ports?.length"> · 路由器：{{ g.router_ports.join(', ') }}</template><template v-if="g.pending_router_ports?.length"> · 待处理：{{ g.pending_router_ports.join(', ') }}</template></span></div><p v-if="!operational?.length" class="muted">暂无组成员</p></div></section>
            <RoceSettings v-if="l2tab === 'RDMA / RoCE'" :configuration="cfg" :applied="appliedConfiguration" :revision="revision" :capabilities="caps.roce" :ports="ports" :disabled="!writesReady || busy || ['queued','running','awaiting_confirmation'].includes(job?.state || '')" :job="job" :operational="operational" @preview="makePreview" :loading="operationalState === 'loading'" :failed="operationalState === 'error'" @refresh="loadOperational" />
            <section v-if="l2tab === '流量管理'" class="card"><div class="card-heading"><div><h2>优先级与队列调度</h2><p>端口限速与三类风暴抑制在端口配置中设置。入口限速和每类风暴抑制各占一个控制器；当前配置 {{ stormControllers }} / {{ caps.storm_control?.controller_capacity || 16 }}。0 为关闭，启用时至少 22000 kbps，实际阈值由硬件量化。</p></div></div><div class="form-grid"><p v-if="cfg.qos.roce.enabled" class="body-copy">RoCE 已保留数据优先级 3 → TC3{{ cfg.qos.roce.classification === 'dscp' ? '、CNP 优先级 6 → TC7' : '' }}；分类冲突由统一校验拦截。<button class="text-button" @click="l2tab='RDMA / RoCE'">打开 RDMA / RoCE</button></p><label>信任模式<select v-model="cfg.qos.trust"><option value="none">不信任（默认优先级）</option><option value="ieee-802.1p">802.1p</option></select></label><label>默认优先级<input v-model.number="cfg.qos.default_priority" type="number" min="0" max="7" /></label><label>调度算法<select v-model="cfg.qos.scheduler"><option value="drr">DRR 加权轮询</option><option value="strict">SP 严格优先级</option></select></label></div><div class="table-wrap"><table><thead><tr><th>802.1p 优先级</th><th>队列 / TC 映射</th><th>DRR 权重</th></tr></thead><tbody><tr v-for="i in 8" :key="i"><td>{{ i-1 }}</td><td><input v-model.number="cfg.qos.priority_map[i-1]" type="number" min="0" max="7" :disabled="cfg.qos.roce.enabled && (i === 4 || cfg.qos.roce.classification === 'dscp' && i === 7)" aria-label="队列映射" /></td><td><input v-model.number="cfg.qos.weights[i-1]" type="number" min="1" max="255" :disabled="cfg.qos.scheduler !== 'drr'" aria-label="DRR 权重" /></td></tr></tbody></table></div></section>
            <section v-if="l2tab === '端口镜像'" class="card"><div class="card-heading"><div><h2>本地 SPAN</h2><p>首版提供一个本地会话，镜像目的必须是独立物理端口。</p></div></div><div class="form-grid"><label class="check"><input v-model="cfg.mirror.enabled" type="checkbox" />启用端口镜像</label><label>源端口<select v-model="cfg.mirror.source"><option :value="null">选择端口</option><option v-for="p in activePorts" :key="p.id" :value="p.id">P{{ p.id }}</option></select></label><label>目的端口<select v-model="cfg.mirror.destination"><option :value="null">选择端口</option><option v-for="p in activePorts" :key="p.id" :value="p.id">P{{ p.id }}</option></select></label><label>方向<select v-model="cfg.mirror.direction"><option value="both">双向（RX + TX）</option><option value="rx">仅接收（RX）</option><option value="tx">仅发送（TX）</option></select></label></div></section>
          </section>

          <section v-if="page === 'thermal'" class="stack">
            <div class="metrics-grid"><article v-for="s in telemetry.sensors.temperatures" :key="s.id" class="metric"><div><span>{{ s.label }}</span><Thermometer :size="18" /></div><strong>{{ s.celsius?.toFixed(1) ?? '—' }}<small>°C</small></strong><p>{{ quality(measurementQuality(s)) }} · {{ fmtTime(sensorTimestamp(s)) }} · {{ s.source }}</p></article><article class="metric"><div><span>风扇反馈</span><Fan :size="18" /></div><strong>{{ fan.rpm ?? '—' }}<small>{{ fan.rpm_estimated ? 'RPM · 估算' : 'RPM' }}</small></strong><p>TACH {{ fan.tach_count ?? '—' }} · PWM {{ fmtPwm(fan.pwm_percent) }}%</p><p v-if="fan.tach_diagnostic">{{ tachDiagnostic(fan.tach_diagnostic) }}</p></article></div>
            <FanCurveEditor v-model="cfg.fan" :temperature="core?.celsius" :actual-pwm="fan.pwm_percent" :disabled="!writesReady || busy || ['queued','running','awaiting_confirmation'].includes(job?.state || '')" />
            <section class="card"><div class="card-heading"><div><h2>限时 PWM 测试</h2><p>最多 60 秒，到期自动恢复硬件曲线。临界温度保护始终有效。</p></div><span class="tag" :class="{ amber: fan.mode === 'manual' }">{{ fan.mode === 'manual' ? '手动测试中' : '曲线运行中' }}</span></div><div class="inline-form"><label class="slider-label">PWM {{ pwm }}%<input v-model.number="pwm" type="range" min="25" max="100" /></label><label>持续时间（秒）<input v-model.number="manualSeconds" type="number" min="1" max="60" /></label><button class="secondary" :disabled="!writesReady || busy || sensorStale || job?.state === 'awaiting_confirmation'" @click="manualFan">开始限时测试</button></div><p class="footnote">TACH 换算参数需要匹配实板风扇校准；0 和 65535 均视为测速异常。</p></section>
          </section>

          <section v-if="page === 'config'" class="stack"><div class="two-column"><section class="card"><div class="card-heading"><div><h2>配置事务</h2><p>活动配置由 configd 统一管理</p></div><FileDiff :size="20" /></div><ol class="steps"><li><span>1</span><div><strong>编辑与预览</strong><p>检查配置差异、EPL 影响范围和预算。</p></div></li><li><span>2</span><div><strong>应用与回读</strong><p>只修改目标对象，失败时执行局部回滚。</p></div></li><li><span>3</span><div><strong>限时确认</strong><p>确认保留新配置；超时自动恢复原配置。</p></div></li></ol><div class="inline-actions"><button class="primary" :disabled="!writesReady || !dirty || busy" @click="makePreview">预览当前修改</button><button class="secondary" :disabled="!dirty || busy" @click="guard(loadConfig)">丢弃本地修改</button></div></section><section class="card"><div class="card-heading"><div><h2>备份与恢复</h2><p>可读 JSON 格式，包含完整交换及风扇配置</p></div><Save :size="20" /></div><p class="body-copy">导出已生效的配置。恢复时先校验版本和校验和，再进入同一套差异与确认流程。</p><div class="inline-actions"><button class="secondary" @click="downloadBackup"><Download :size="16" />导出备份</button><label class="button secondary"><Upload :size="16" />导入备份<input type="file" accept=".json,application/json" class="sr-only" :disabled="busy" @change="restore" /></label></div><p class="footnote">备份不包含密码、会话、SDK 二进制或 Debian 管理网络配置。</p></section></div><section v-if="mode === 'mock'" class="card"><div class="card-heading"><div><h2>模拟故障演练</h2><p>验证配置失败、局部恢复与过期数据的呈现。</p></div><span class="tag amber">仅模拟模式</span></div><div class="inline-form"><label>下次提交故障点<select v-model="fault"><option value="">无故障</option><option value="quiesce_protocols">目标协议暂停</option><option value="disable_group">目标组关闭</option><option value="set_ethernet_mode">Ethernet Mode 切换</option><option value="verify_group">端口组回读</option><option value="fan_write">风扇曲线写入</option><option value="apply_l2">二层配置应用</option><option value="readback">最终回读</option></select></label><label class="check"><input v-model="staleSimulation" type="checkbox" />温度采样失败</label><button class="secondary" @click="injectFault">设置模拟故障</button></div></section></section>
          <section v-if="page === 'logs'" class="card"><div class="card-heading"><div><h2>操作审计</h2><p>最近 200 条记录，包含配置提交、确认与恢复。</p></div><button class="secondary" @click="navigate('logs')">刷新</button></div><div class="table-wrap"><table><thead><tr><th>时间</th><th>事件</th><th>操作者</th><th>详情</th></tr></thead><tbody><tr v-for="(entry,i) in logs" :key="i"><td class="mono">{{ new Date(entry.time*1000).toLocaleString('zh-CN') }}</td><td>{{ entry.event }}</td><td>{{ entry.actor || '控制面' }}</td><td class="break-word">{{ entry.error || (entry.revision ? '配置 r' + entry.revision : entry.job_id || '—') }}</td></tr><tr v-if="!logs.length"><td colspan="4" class="empty">暂无操作记录</td></tr></tbody></table></div></section>
          <section v-if="page === 'system'" class="stack">
            <section class="card"><div class="card-heading"><h2>系统信息</h2><Cpu :size="20" /></div><div v-for="(value,key) in { '主机':system.hostname, '操作系统':system.system, '面板版本':system.version, '后端':system.backend, 'SDK 操作者':system.sdk_owner, '驱动基线':system.driver_baseline, 'SDK 目标':system.sdk_target, '板卡 Profile':system.profile }" :key="key" class="definition-row"><span>{{ key }}</span><span class="break-word">{{ value || '—' }}</span></div></section>
            <OtaUpdates :status="updateStatus" :current-version="system.version || caps.version" @backups="navigate('config')" />
            <TimeSettings :disabled="busy || ['queued','running','awaiting_confirmation'].includes(job?.state || '')" />
            <AdministratorSettings :username="username" :disabled="busy" @updated="username = $event" @expired="expireSession" />
          </section>
          <section v-if="page === 'l3'" class="card l3-card"><div class="feature-icon"><Router :size="34" /></div><span class="tag">后续版本</span><h2>三层网络，入口已预留</h2><p>首版专注二层交换。三层接口、ARP 与路由将在后续接入，当前未启动 rpd / FRR。</p><div class="l3-options"><div><Cable :size="20" /><strong>三层接口</strong><span>尚未启用</span></div><div><Layers :size="20" /><strong>ARP 邻居</strong><span>尚未启用</span></div><div><Router :size="20" /><strong>路由表</strong><span>尚未启用</span></div></div></section>
        </div>
        <footer class="page-footer"><span>FM10K Control Panel <span class="mono">v{{ caps.version || system.version || '0.1.0' }}</span></span><span>端口 1s · 温控 5s <span class="status-dot"></span> {{ fmtTime(telemetry.sampled_at) }}</span></footer>
      </div>
      <div v-if="writesReady && dirty && !preview" class="save-bar"><span><i class="dot blue"></i>有尚未提交的配置修改 <small>基于 r{{ revision }}</small></span><div><button class="secondary" :disabled="busy" @click="guard(loadConfig)">丢弃修改</button><button class="primary" :disabled="busy || ['running','queued','awaiting_confirmation'].includes(job?.state || '')" @click="makePreview" :aria-busy="configAction === 'preview'"><LoaderCircle v-if="configAction === 'preview'" class="spin" :size="16" aria-hidden="true" /><FileDiff v-else :size="16" />{{ configAction === 'preview' ? '正在校验…' : '预览并校验' }}</button></div></div>
    </main>
    <div v-if="vlanDeleteTarget !== null && cfg" :inert="requestInert" class="modal-backdrop" @click.self="vlanDeleteTarget = null" @keydown.esc="vlanDeleteTarget = null">
      <section class="modal" role="dialog" aria-modal="true" aria-labelledby="vlan-delete-title" aria-describedby="vlan-delete-help">
        <div class="card-heading"><h2 id="vlan-delete-title">VLAN {{ vlanDeleteTarget }} 仍在使用中</h2><button class="icon-button" aria-label="关闭 VLAN 引用提示" @click="vlanDeleteTarget = null"><X :size="20" /></button></div>
        <div class="modal-scroll">
          <p id="vlan-delete-help" class="body-copy">VLAN 已保留在草稿中。请先调整以下引用，再返回删除；所有修改统一预览并提交。</p>
          <div class="table-wrap"><table><thead><tr><th>配置</th><th>引用方式</th><th>操作</th></tr></thead><tbody>
            <tr v-for="(reference, index) in vlanDeleteReferences" :key="index"><td class="break-word">{{ reference.title }}</td><td class="break-word">{{ reference.detail }}</td><td><button class="secondary" :aria-label="'调整 ' + reference.title" @click="editVlanReference(reference)">{{ reference.kind === 'port' ? '修改端口' : reference.kind === 'mac' ? '修改 MAC' : '修改 IGMP' }}</button></td></tr>
          </tbody></table></div>
          <p class="footnote">需要保留端口业务时，先添加新的 VLAN 并调整端口成员关系。关闭端口或停用 IGMP 不会自动清除其 VLAN 配置。</p>
        </div>
        <div class="modal-actions"><button class="secondary" @click="vlanDeleteTarget = null">返回 VLAN 列表</button></div>
      </section>
    </div>
    <div v-if="preview" :inert="requestInert" class="modal-backdrop"><section ref="previewDialog" tabindex="-1" class="modal preview-modal" role="dialog" aria-modal="true" aria-labelledby="preview-title"><div class="card-heading"><div><p class="eyebrow">CONFIGURATION REVIEW</p><h2 id="preview-title">检查配置变更</h2></div><button class="icon-button" aria-label="关闭预览" :disabled="busy" @click="preview = null"><X :size="20" /></button></div><div class="modal-scroll"><div class="preview-summary"><span><strong>{{ preview.changes.length }}</strong> 处差异</span><span>影响 EPL <strong>{{ preview.affected_epls.join(', ') || '无模式变更' }}</strong></span><span class="tag">无需全卡重启</span></div><div v-if="preview.global_qos_change" class="alert warning">速率、MTU、优先级或 PFC 变更会重算全芯片缓冲水位，事务协调范围为全部 EPL。</div><div v-if="preview.requires_bandwidth_ack" class="alert warning">外部标称 {{ preview.bandwidth.external_gbps }}G，加上内部端口后超过 600G SKU 预算。实际整卡吞吐需要单独验收。</div><PortGroupChanges :changes="preview.group_changes || []" /><div class="table-wrap"><table><thead><tr><th>配置项</th><th>修改前</th><th>修改后</th></tr></thead><tbody><tr v-for="(change,i) in preview.changes" :key="i"><td class="mono break-word">{{ change.label || change.path }}</td><td class="diff-before">{{ fmtValue(change.before) }}</td><td class="diff-after">{{ fmtValue(change.after) }}</td></tr><tr v-if="!preview.changes.length"><td class="empty" colspan="3">配置没有变化</td></tr></tbody></table></div><div class="inline-form"><label>确认期限<select v-model.number="confirmTimeout" :disabled="busy"><option :value="30">30 秒</option><option :value="60">60 秒</option><option :value="120">120 秒</option><option :value="300">300 秒</option></select></label><p class="body-copy">配置应用并回读后，请在期限内确认；未确认将自动恢复原配置。</p></div><label v-if="preview.requires_bandwidth_ack" class="check"><input v-model="bandwidthAck" type="checkbox" :disabled="busy" />已了解标称带宽与整卡吞吐的区别，继续提交</label><div v-if="error" class="alert danger">{{ error }}</div></div><div class="modal-actions"><button class="secondary" :disabled="busy" @click="preview = null">返回编辑</button><button class="primary" :disabled="busy || !preview.changes.length || (preview.requires_bandwidth_ack && !bandwidthAck)" @click="commit" :aria-busy="configAction === 'commit'"><LoaderCircle v-if="configAction === 'commit'" class="spin" :size="16" aria-hidden="true" /><Check v-else :size="16" />{{ configAction === 'commit' ? '正在提交…' : '提交配置' }}</button></div></section></div>
    <div v-if="requestVisible" class="modal-backdrop request-backdrop">
      <section id="configuration-progress" ref="requestDialog" tabindex="-1" class="modal request-modal transaction-modal" role="dialog" aria-modal="true" aria-labelledby="request-title" aria-describedby="request-description">
        <div class="transaction-content">
          <header class="transaction-header">
            <div class="transaction-icon" aria-hidden="true"><LoaderCircle v-if="requestExecuting" class="spin request-icon" :size="24" /><Check v-else-if="job?.state === 'done'" class="request-icon" :size="24" /><Activity v-else class="request-icon" :size="24" /></div>
            <div class="transaction-heading" role="status" aria-live="polite"><h2 id="request-title">{{ requestTitle }}</h2><p id="request-description">{{ requestMessage }}</p></div>
          </header>
          <ol v-if="transactionVisible" class="transaction-stages" aria-label="配置流程">
            <li :class="{ complete:!!job }"><span>提交请求</span></li>
            <li :class="{ active:job?.state === 'running', complete:['awaiting_confirmation','done'].includes(job?.state || '') }"><span>应用与回读</span></li>
            <li :class="{ active:job?.state === 'awaiting_confirmation', complete:job?.state === 'done' }"><span>确认保留</span></li>
          </ol>
          <p v-if="requestSeconds >= 15 && requestExecuting" class="request-note">等待时间较长，仍在等待设备响应。收到结果后会自动更新。</p>
          <div v-if="job?.rollback_failed" class="alert danger">局部恢复失败，受影响端口组保持关闭，请检查设备日志。</div>
          <p v-if="transactionVisible && job?.state === 'awaiting_confirmation'" class="transaction-confirm-help">请在 <strong>{{ countdown }} 秒</strong> 内确认，逾期会自动恢复原配置。</p>
        </div>
        <footer class="transaction-footer">
          <div class="transaction-meta" aria-live="off"><p class="request-elapsed">已用时 <strong>{{ requestSeconds }}</strong> 秒</p><p v-if="job" class="request-job">作业 <code>{{ job.id.slice(0,8) }}</code></p></div>
          <div v-if="transactionVisible" class="transaction-actions">
            <button class="secondary transaction-dismiss" :disabled="busy" @click="closeTransaction">{{ preview ? '返回预览' : ['done','failed','rolled_back'].includes(job?.state || '') ? '完成并关闭' : '收起到状态栏' }}</button>
            <template v-if="job?.state === 'awaiting_confirmation'">
              <button class="secondary" :disabled="busy" @click="finish('rollback')">恢复原配置</button>
              <button class="primary" :disabled="busy" @click="finish('confirm')"><Check :size="16" />确认保留</button>
            </template>
          </div>
        </footer>
      </section>
    </div>
  </div>
</template>
