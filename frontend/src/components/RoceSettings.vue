<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import { advanceSampleClock } from '../portTelemetry'
import type { Configuration, Job, PortTelemetry, RoceCapabilities, RoceOperational, RocePreflight } from '../types'
const props = defineProps<{
  configuration: Configuration; applied?: Configuration; revision: number;
  operational: RoceOperational|null; capabilities?: RoceCapabilities; ports: PortTelemetry[];
  loading: boolean; failed: boolean; disabled: boolean; job: Job|null
}>()
const emit = defineEmits<{ refresh: []; preview: [] }>()
const tab = ref('概览'), step = ref(0), wizard = ref<Configuration|null>(null)
const working = computed(() => wizard.value || props.configuration)
const roce = computed(() => working.value.qos.roce)
const check = ref<RocePreflight|null>(null), checking = ref(false), checkError = ref('')
const checkKey = ref(''), monotonicNow = ref(performance.now())
const receipt = ref<{serverTime:number|null; monotonic:number}>({serverTime:null,monotonic:performance.now()})
watch(() => props.operational, sample => {
  const serverTime = sample?.server_time
  receipt.value = {serverTime:typeof serverTime === 'number' && Number.isFinite(serverTime) ? serverTime : null,monotonic:performance.now()}
  monotonicNow.value = receipt.value.monotonic
}, {immediate:true,flush:'sync'})
const sampleNow = computed(() => advanceSampleClock(receipt.value.serverTime,receipt.value.monotonic,monotonicNow.value))
let generation = 0, debounce: ReturnType<typeof setTimeout>|undefined
const ticker = setInterval(() => { monotonicNow.value = performance.now() }, 1000)
onUnmounted(() => { ++generation; clearInterval(ticker); if (debounce) clearTimeout(debounce) })
const clone = <T,>(value:T):T => JSON.parse(JSON.stringify(value))
const inputKey = computed(() => JSON.stringify([working.value, props.revision]))
const checked = computed(() => checkKey.value === inputKey.value && !checking.value && !checkError.value)
async function preflight() {
  const current = ++generation, key = inputKey.value
  checking.value = true; checkError.value = ''
  try {
    const result = await api<RocePreflight>('/roce/preflight', {configuration: working.value, expected_revision: props.revision})
    if (current === generation && key === inputKey.value) { check.value = result; checkKey.value = key }
  } catch (error) { if (current === generation) checkError.value = error instanceof Error ? error.message : String(error) }
  finally { if (current === generation) checking.value = false }
}
watch(inputKey, () => {
  ++generation; checkKey.value = ''; checking.value = true
  if (debounce) clearTimeout(debounce)
  debounce = setTimeout(preflight, 250)
}, {immediate:true})
const stale = computed(() => !props.operational?.sampled_at || sampleNow.value === null ||
  !Number.isFinite(props.operational.sampled_at) || sampleNow.value - props.operational.sampled_at > 30 || sampleNow.value < props.operational.sampled_at)
const validSample = computed(() => !props.failed && !stale.value && props.operational?.quality === 'valid' && props.operational.revision === props.revision)
const dirty = computed(() => !!props.applied && JSON.stringify(props.configuration) !== JSON.stringify(props.applied))
const configState = computed(() => {
  const state = props.job?.state
  if (state === 'queued' || state === 'running') return '应用中'
  if (state === 'awaiting_confirmation') return '待确认'
  if (state === 'failed') return '应用失败'
  if (dirty.value) return '待应用'
  if (!validSample.value) return '等待有效回读'
  if (!props.operational?.configuration_applied) return '配置不一致'
  return props.applied?.qos.roce.enabled ? '已生效' : '已关闭'
})
const runtime = computed(() => {
  if (props.failed) return '读取失败'
  if (props.loading && !validSample.value) return '读取中'
  if (props.operational?.quality === 'simulated') return '模拟 · 无硬件证明'
  if (!validSample.value) return '未知 / 样本过期'
  const selected = props.operational?.ports.filter(p => p.selected) || []
  if (selected.some(p => p.configuration_matches === false)) return '端口配置异常'
  if (selected.some(p => p.link === 'unknown' || p.state_quality === 'unavailable')) return '参与端口状态未知'
  if (selected.some(p => p.link !== 'up')) return '参与端口链路未全部就绪'
  if (selected.some(p => p.quality !== 'valid')) return '端口计数不可用'
  return selected.length ? '链路已就绪' : '未启用'
})
const rows = computed(() => check.value?.ports || [])
const groups = computed(() => [...new Set(rows.value.map(p => `OBT${p.obt} · EPL${p.epl}`))])
const vlan = ref<number|null>(null)
const chosenSuggestions = ref<string[]>([])
watch(() => check.value, () => { chosenSuggestions.value = [] })
function start() { if (wizard.value) { tab.value = '配置'; return }; wizard.value = clone(props.configuration); wizard.value.qos.roce.enabled = true; step.value = 1; tab.value = '配置' }
function cancel() { wizard.value = null; step.value = 0 }
watch(() => props.revision, () => { cancel() })
function finish() {
  if (!checked.value || !check.value?.valid || props.disabled || !wizard.value) return
  Object.assign(props.configuration, clone(wizard.value)); cancel(); emit('preview')
}
function togglePort(port:number, selected:boolean) {
  roce.value.ports = selected ? [...new Set([...roce.value.ports, port])].sort((a,b)=>a-b) : roce.value.ports.filter(p=>p!==port)
}
function applySuggestions() {
  for (const s of check.value?.suggestions || []) {
    if (!chosenSuggestions.value.includes(s.path)) continue
    const parts = s.path.split('.')
    // Only server-generated paths in our own config draft; never touches hardware.
    if (parts[0] === 'ports' && ['enabled','ingress_kbps','egress_kbps','lldp'].includes(parts[2] || '')) {
      const p = working.value.ports[parts[1]!]
      if (p && parts[2] === 'enabled') p.enabled = s.after === true
      if (p && parts[2] === 'ingress_kbps') p.ingress_kbps = Number(s.after)
      if (p && parts[2] === 'egress_kbps') p.egress_kbps = Number(s.after)
      if (p && parts[2] === 'lldp') p.lldp = s.after === true
    } else if (s.path === 'qos.priority_map') working.value.qos.priority_map = clone(s.after as number[])
    else if (s.path === 'qos.default_priority') working.value.qos.default_priority = Number(s.after)
    else if (s.path === 'qos.trust') working.value.qos.trust = String(s.after)
    else if (s.path === 'lldp.enabled') working.value.lldp.enabled = s.after === true
  }
}
function addVlan() {
  if (vlan.value == null || !working.value.vlans.some(v => v.id === vlan.value)) return
  for (const n of roce.value.ports) {
    const p = working.value.ports[n]!
    p.vlan_mode = 'trunk'; p.tagged_vlans = [...new Set([...p.tagged_vlans, vlan.value])].sort((a,b)=>a-b)
  }
}
function discard() { if (props.applied) Object.assign(props.configuration, clone(props.applied)); cancel() }
function exportDiagnostic() {
  const value = {exported_at:new Date().toISOString(), revision:props.revision,
    snapshot_status: validSample.value ? 'current' : 'unconfirmed-or-stale',
    applied_configuration:props.applied, draft_configuration:working.value,
    preflight:checked.value ? check.value : null, operational:props.failed ? null : props.operational,
    qualification_records:[],
    note:'此导出包含当前配置与设备采样；配置成功不代表当前路径已通过流量或拥塞验收。'}
  const url = URL.createObjectURL(new Blob([JSON.stringify(value,null,2)], {type:'application/json'}))
  const a = document.createElement('a'); a.href = url; a.download = `fm10840-roce-r${props.revision}.json`; a.click()
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}
const show = (value:unknown) => value == null ? '不可用' : String(value)
const bytes = (value:number|null|undefined) => value == null ? '不可用' : `${(value/1024).toFixed(1)} KiB`
const link = (port:number) => props.ports.find(p=>p.id===port)?.link || '未知'
const selectedRows = computed(() => rows.value.filter(p=>roce.value.ports.includes(p.port)))
const watchdogLabel = (phase:string) => ({disabled:'已关闭',observing:'监测中',suspect:'疑似停滞',recovering:'正在解除暂停',cooldown:'冷却中',suspended:'监测暂停','restore-failed':'掩码恢复失败',unavailable:'不可用'}[phase] || '未知')
const dcbxLabel = (state:string) => ({matched:'通告一致',disabled:'已关闭',expired:'对端通告已过期','local-error':'本机通告无效','link-down':'链路 Down · 等待对端','no-peer':'等待对端通告','no-peer-dcbx':'对端未通告 DCBX','multiple-peers':'存在多个邻居','pfc-mismatch':'PFC 不一致','ets-mismatch':'ETS 不一致','app-mismatch':'应用优先级不一致','malformed-peer':'对端通告无效','missing-pfc':'缺少 PFC 通告','missing-ets':'缺少 ETS 通告','missing-app':'缺少应用通告','local-missing':'本机通告未加载','local-mismatch':'本机策略不一致'}[state] || '未知')
</script>

<template>
  <section class="stack roce-page">
    <section class="card">
      <div class="card-heading"><div><p class="eyebrow">LOSSLESS ETHERNET</p><h2>RDMA / RoCE</h2><p>单板二层 RoCEv2 · 按业务优先级配置流控与缓冲。</p></div><button class="secondary" :disabled="loading" @click="emit('refresh')">{{ loading ? '读取中…' : '刷新硬件状态' }}</button></div>
      <div class="roce-status" aria-live="polite">
        <div><span>配置状态</span><strong>{{ configState }}</strong><small>当前配置 r{{ revision }}</small></div>
        <div><span>运行状态</span><strong>{{ runtime }}</strong><small>设备采样：{{ operational?.sampled_at ? new Date(operational.sampled_at*1000).toLocaleString() : '尚无采样' }} · 每 10 秒自动刷新</small></div>
        <div><span>流量验证</span><strong>需独立验收</strong><small>按实际端点与拓扑验证传输和拥塞恢复</small></div>
      </div>
      <p v-if="failed" class="alert danger" role="alert">硬件状态读取失败，请重试。当前没有可用于确认配置的读数。</p>
      <nav class="tabs" aria-label="RoCE 页面"><button v-for="name in ['概览','配置','诊断']" :key="name" :class="{active:tab===name}" :aria-current="tab===name ? 'page' : undefined" @click="tab=name">{{ name }}</button></nav>
    </section>

    <template v-if="tab==='概览'">
      <section class="card"><div class="card-heading"><div><h2>静态 PFC</h2><p>{{ applied?.qos.roce.classification==='dscp' ? `DSCP ${applied.qos.roce.dscp} → TC3 无损队列；CNP DSCP ${applied.qos.roce.cnp_dscp} → TC7 优先队列。` : 'PCP3 → TC3 → 独立无损缓冲。主机需配置相同的 VLAN、PCP 与 PFC。' }}</p></div><span class="tag">{{ applied?.qos.roce.enabled ? '已配置' : '未启用' }}</span></div>
        <div class="definition-row"><span>已配置参与端口</span><span>{{ applied?.qos.roce.ports.map(p=>'P'+p).join('、') || '尚未选择' }}</span></div>
        <div class="definition-row"><span>缓冲准备</span><span>{{ !validSample ? '待有效回读' : operational?.buffer_ready ? '已就绪' : '未就绪 · 需要初始化或检查水位' }}</span></div>
        <div class="inline-actions"><button class="primary" :disabled="disabled" @click="applied?.qos.roce.enabled ? tab='配置' : start()">{{ applied?.qos.roce.enabled ? '编辑配置' : '配置 RoCE' }}</button><button class="secondary" @click="tab='诊断'">查看诊断</button></div>
      </section>
      <section class="card"><h2>能力与开放条件</h2><div v-if="!capabilities" class="body-copy">能力信息不可用，请刷新页面后重试。</div><div v-for="f in [...(capabilities?.modes || []),...(capabilities?.features || [])]" :key="f.id" class="definition-row"><span>{{ f.label }}</span><span>{{ f.status==='configurable' ? '可配置' : f.status==='unsupported' ? '本型号不支持' : f.status==='pending-validation' ? '待验收' : '尚未实现' }}<small>{{ f.reason }}</small></span></div></section>
    </template>

    <section v-if="tab==='配置'" class="card">
      <div class="card-heading"><div><h2>{{ wizard ? '引导启用 RoCE' : 'RoCE 配置' }}</h2><p>修改仅进入草稿，预览、提交并确认后才会生效。</p></div><button v-if="!wizard" class="secondary" :disabled="disabled" @click="start">重新运行引导</button></div>
      <ol v-if="wizard" class="roce-steps" aria-label="启用步骤"><li v-for="(name,i) in ['模式','端口','网络检查','确认']" :key="name" :aria-current="step===i+1 ? 'step' : undefined">{{ i+1 }}. {{ name }}</li></ol>
      <fieldset :disabled="disabled" class="roce-fields">
        <div v-if="!wizard || step===1">
          <label class="check"><input v-model="roce.enabled" type="checkbox" />启用静态 PFC RoCE</label>
          <p class="body-copy">PFC 保护数据优先级 3。可选择 PCP 标签或 DSCP 分类，并通过 DCBX 交换本机策略。</p>
          <div class="form-grid"><label>流量分类<select v-model="roce.classification" aria-label="流量分类"><option value="pcp">PCP · Tagged VLAN</option><option value="dscp">DSCP · 数据与 CNP 独立队列</option></select></label><label>DCBX 策略交换<select v-model="roce.dcbx" aria-label="DCBX 策略交换"><option value="off">关闭 · 手动对齐主机</option><option value="ieee">IEEE · 本机策略优先</option></select></label></div>
          <div v-if="roce.classification==='dscp'" class="form-grid subsection"><label>RoCE 数据 DSCP<input v-model.number="roce.dscp" type="number" min="0" max="63" /></label><label>CNP DSCP<input v-model.number="roce.cnp_dscp" type="number" min="0" max="63" /></label></div>
          <p v-if="roce.dcbx==='ieee'" class="footnote">通过 LLDP 通告 PFC、ETS 和应用优先级，并检测对端差异。邻居不会覆盖本机配置；交换通告不代表网卡已应用策略。</p>
          <p class="footnote">本型号二层转发路径不提供拥塞触发的 ECN / CE 标记。CNP 优先转发与端点拥塞控制需按实际网络条件验收。</p>
          <p v-if="!roce.enabled" class="footnote">停用会关闭参与端口 PFC 并恢复 TC 映射；保留混合缓冲布局及 VLAN、MTU 等通用配置。</p>
        </div>
        <div v-if="!wizard || step===2" class="subsection"><h3>参与端口 · 已选 {{ roce.ports.length }}</h3><p class="body-copy">至少两个端口；链路 Down 可以预配置。灰色端口显示具体限制，已有选择可取消。</p>
          <div v-for="group in groups" :key="group" class="roce-port-group"><h4>{{ group }}</h4><div class="roce-port-grid"><label v-for="p in rows.filter(p=>`OBT${p.obt} · EPL${p.epl}`===group)" :key="p.port" :class="['roce-port', {selected:roce.ports.includes(p.port), unavailable:!p.eligible}]">
            <span><input type="checkbox" :aria-label="'选择 P'+p.port" :checked="roce.ports.includes(p.port)" :disabled="!p.eligible && !roce.ports.includes(p.port)" @change="togglePort(p.port,($event.target as HTMLInputElement).checked)" /><strong>P{{ p.port }}</strong><span>{{ p.speed_gbps || '—' }}G · {{ link(p.port) }}</span></span>
            <small>{{ p.reason || (p.enabled ? '端口已启用' : '端口未启用，需修改') }}</small><small>MTU {{ p.mtu }} · Tagged {{ p.tagged_vlans.join(', ') || '无' }}</small>
          </label></div></div>
        </div>
        <div v-if="!wizard || step===3" class="subsection"><h3>网络与优先级</h3>
          <div class="definition-row"><span>无损分类</span><span>{{ roce.classification==='dscp' ? `DSCP ${roce.dscp}` : 'PCP3' }} → TC3 → SMP1 · PFC 收发优先级 3</span></div>
          <div v-if="roce.classification==='dscp'" class="definition-row"><span>CNP 转发</span><span>DSCP {{ roce.cnp_dscp }} → TC7 → SMP0 · 严格优先级 · PFC 关闭</span></div>
          <div class="definition-row"><span>参与端口队列调度</span><span>DRR · TC3 权重 {{ working.qos.weights[3] }}<small>权重沿用流量管理；RoCE 参与端口使用 DRR</small></span></div>
          <div v-if="roce.dcbx==='ieee'" class="definition-row"><span>ETS 带宽分配</span><span>{{ checked ? check?.dcbx_policy?.bandwidth.map((v,i)=>`TC${i} ${v}%`).join(' / ') : '待检查' }}<small>按通用 QoS 权重分配为整数百分比；通告与实际调度保持一致，TC7 为 CNP 严格优先级时不分配 ETS 保证带宽。</small></span></div>
          <div class="definition-row"><span>{{ roce.classification==='dscp' ? '共同业务 VLAN（可使用 Access）' : '共同 Tagged VLAN' }}</span><span>{{ checked ? check?.common_vlans?.join('、') || '无' : '待检查' }}</span></div>
          <div class="inline-form"><label>加入现有业务 VLAN<select v-model="vlan"><option :value="null">选择已有 VLAN</option><option v-for="v in working.vlans" :key="v.id" :value="v.id">{{ v.id }} · {{ v.name }}</option></select></label><button class="secondary" :disabled="vlan===null || !roce.ports.length" @click="addVlan">为所选端口加入 Tagged VLAN</button></div>
          <p class="footnote">此操作将所选端口改为 Trunk、增加指定标签 VLAN，并保留原有 PVID 和标签成员；不修改 MTU。没有合适 VLAN 时先在 VLAN 页面创建。</p>
          <details class="subsection"><summary>高级参数与缓冲预算</summary><div class="form-grid"><label>最长线缆（米）<input v-model.number="roce.cable_length_m" type="number" :min="capabilities?.cable_length_m.min ?? 0" :max="capabilities?.cable_length_m.max ?? 100" /></label><label>对端暂停响应上限（纳秒）<input v-model.number="roce.response_time_ns" type="number" :min="capabilities?.response_time_ns.min ?? 500" :max="capabilities?.response_time_ns.max ?? 10000" /></label></div><p class="footnote">预算输入需通过实际拥塞测试验证；系统按速率、MTU 与传播时间计算，最终由原生层核验。</p>
            <div v-if="checked" class="table-wrap"><table><thead><tr><th>端口</th><th>所需 headroom</th><th>已配置容量</th></tr></thead><tbody><tr v-for="p in selectedRows" :key="p.port"><td>P{{ p.port }}</td><td>{{ bytes(p.headroom_bytes) }}</td><td>{{ bytes(p.capacity_bytes) }}</td></tr></tbody></table></div>
            <p v-if="checked && check?.budget" class="body-copy">全芯片无损分区 {{ bytes(check.budget.lossless_partition_bytes) }} · 保守预算剩余 {{ bytes(check.budget.remaining_bytes) }}</p>
          </details>
          <div class="subsection"><h3>PFC watchdog</h3>
            <label class="check"><input v-model="roce.watchdog.enabled" type="checkbox" />启用 PFC watchdog</label>
            <p class="footnote">默认关闭。连续观察到 TC3 被 PFC 暂停、队列非空且端口没有数据发送时，短暂解除优先级 3 的暂停响应，再恢复原设置。其他队列仍在发包时可能漏检；恢复期间可能丢包。</p>
            <div v-if="roce.watchdog.enabled" class="form-grid">
              <label>停滞检测时间（毫秒）<input v-model.number="roce.watchdog.detect_ms" type="number" min="1000" max="60000" step="100" /></label>
              <label>解除暂停时间（毫秒）<input v-model.number="roce.watchdog.recovery_ms" type="number" min="100" max="1000" step="100" /></label>
              <label>恢复后冷却时间（毫秒）<input v-model.number="roce.watchdog.cooldown_ms" type="number" min="10000" max="600000" step="1000" /></label>
            </div>
          </div>
        </div>
        <div v-if="!wizard || step>=3" class="subsection" aria-live="polite"><h3>配置预检</h3><p v-if="checking">正在检查草稿…</p><p v-else-if="checkError" role="alert">{{ checkError }}</p><template v-else-if="checked"><p :class="check?.valid ? 'body-copy' : 'alert danger'">{{ check?.valid ? '软件预检通过；提交前仍需原生校验与差异确认。' : '以下问题需要处理后才能预览：' }}</p><ul class="roce-issues"><li v-for="i in check?.issues" :key="i.path+i.message">{{ i.message }}</li></ul><p v-for="w in check?.warnings" :key="w" class="footnote">{{ w }}</p>
          <div v-if="check?.suggestions.length"><h4>建议修改 · 主动选择后加入草稿</h4><label v-for="s in check.suggestions" :key="s.path" class="check roce-suggestion"><input v-model="chosenSuggestions" type="checkbox" :value="s.path" />{{ s.label }}（{{ s.before }} → {{ s.after }}）</label><button class="secondary" :disabled="!chosenSuggestions.length" @click="applySuggestions">加入所选建议修改</button></div>
        </template><button v-if="checkError" class="secondary" @click="preflight">重新预检</button></div>
        <div v-if="wizard && step===4" class="subsection"><h3>确认配置范围</h3><p class="body-copy">{{ roce.enabled ? '启用静态 PFC' : '停用 RoCE' }} · {{ roce.ports.map(p=>'P'+p).join('、') }}。下一步显示完整差异，包括 VLAN、QoS 和端口联动。缓冲与映射变更可能影响全部 EPL。</p><p class="footnote">离开引导前点击“预览变更”才会把引导草稿合入当前编辑；取消引导保留进入前的编辑。</p></div>
        <div class="inline-actions"><template v-if="wizard"><button class="secondary" @click="cancel">取消引导</button><button v-if="step>1" class="secondary" @click="step--">上一步</button><button v-if="step<4" class="primary" :disabled="(step===2 && roce.ports.length<2) || (step===3 && (!checked || !check?.valid))" @click="step++">下一步</button><button v-else class="primary" :disabled="!checked || !check?.valid" @click="finish">预览变更</button></template><template v-else><button class="primary" :disabled="!dirty || !checked || !check?.valid" @click="emit('preview')">预览 RoCE 变更</button><button class="secondary" :disabled="!dirty" @click="discard">丢弃全部本地修改</button></template></div>
      </fieldset>
    </section>

    <template v-if="tab==='诊断'">
      <section class="card"><div class="card-heading"><div><h2>端口流控与拥塞</h2><p>累计值为端口级计数，非逐优先级统计。零值不代表无损验收通过。</p></div><button class="secondary" @click="exportDiagnostic">导出诊断 JSON</button></div>
        <p v-if="!validSample" class="alert">当前样本未确认或已过期，下方旧读数仅供参考，请刷新硬件状态。</p>
        <div class="table-wrap"><table><thead><tr><th>端口</th><th>链路 / 数据质量</th><th>PFC 接收</th><th>PFC 发送</th><th>入口拥塞丢弃</th><th>出口拥塞丢弃</th><th>TC3 占用</th><th>优先级 3 剩余暂停量</th><th>CNP TC7 占用</th></tr></thead><tbody><tr v-for="p in (!failed ? operational?.ports : [])" :key="p.port"><td>P{{ p.port }}{{ p.selected ? ' · RoCE' : '' }}</td><td>{{ p.link }}<small>{{ p.quality==='valid' ? '有效' : '未确认' }}</small></td><td>{{ show(p.counters?.rx_pfc_packets) }}</td><td>{{ show(p.counters?.tx_pfc_packets) }}</td><td>{{ show(p.counters?.rx_congestion_drops) }}</td><td>{{ show(p.counters?.tx_congestion_drops) }}</td><td>{{ bytes(p.tc3_usage_bytes) }}</td><td>{{ p.pause?.quality==='valid' ? show(p.pause.rx_quanta?.[3]) + ' quanta' : '不可用' }}</td><td>{{ bytes(p.cnp_usage_bytes) }}</td></tr><tr v-if="failed || !operational?.ports.length"><td colspan="9">暂无有效端口读数</td></tr></tbody></table></div>
        <details class="subsection"><summary>队列映射与硬件水位</summary><template v-if="!failed && operational"><p class="body-copy">TC → SMP：{{ operational.tc_smp_map?.join(' / ') || '不可用' }}</p><p class="body-copy">共享分区占用：{{ operational.smp_usage_bytes?.map(bytes).join(' / ') || '不可用' }}（不包含 RX 私有区域）</p><pre class="roce-json">{{ JSON.stringify({shared:operational.shared_watermarks, ports:operational.watermarks},null,2) }}</pre></template></details>
      </section>
      <section v-if="!failed && operational?.diagnostics" class="card"><h2>暂停观测与近期事件</h2><p class="body-copy">后台每 {{ operational.diagnostics.interval_seconds }} 秒采样，记录当前配置的队列峰值。历史保留在本次服务进程中，最多 180 个采样和 64 条事件。</p>
        <p class="footnote">{{ operational.diagnostics.observation }}</p>
        <div v-for="p in operational.diagnostics.ports" :key="p.port" class="definition-row"><span>P{{ p.port }}</span><span>TC3 采样峰值 {{ bytes(p.tc3_peak_bytes) }}<small>{{ !validSample || p.quality!=='valid' ? '暂停状态未确认' : p.suspected_stall ? `可疑暂停停滞，已连续观测 ${p.observed_stall_seconds.toFixed(0)} 秒，请检查对端` : p.pause_observed ? '本次采样检测到暂停' : '本次采样未检测到暂停' }}</small></span></div>
        <p v-if="!operational.diagnostics.events.length" class="footnote">尚无低频诊断事件。watchdog 状态见下方。</p>
        <ul v-else class="roce-checklist"><li v-for="(event,i) in [...operational.diagnostics.events].reverse()" :key="i">{{ new Date(event.time*1000).toLocaleString() }} · r{{ event.revision }} · P{{ event.port }} · {{ event.message }}</li></ul>
      </section>
      <section class="card"><h2>PFC watchdog 状态</h2><p class="body-copy">每 100 毫秒检查已配置端口。普通 Pause、新增数据发送或超过 300 毫秒的采样间断都会重新开始停滞检测；维护期间暂停检测。计数保留在本次设备服务运行期间。</p>
        <div class="table-wrap"><table><thead><tr><th>端口</th><th>状态</th><th>检测次数</th><th>掩码恢复次数</th><th>失败次数</th><th>采样间断</th></tr></thead><tbody>
          <tr v-for="p in (!failed ? operational?.ports.filter(p=>p.selected) : [])" :key="p.port"><td>P{{ p.port }}</td><td>{{ validSample && p.watchdog?.supported ? watchdogLabel(p.watchdog.phase) : '状态未确认' }}<small v-if="p.watchdog?.enabled && p.watchdog.quality!=='valid'">当前采样不可用</small></td><td>{{ show(p.watchdog?.detections) }}</td><td>{{ show(p.watchdog?.restorations) }}</td><td>{{ show(p.watchdog?.failures) }}</td><td>{{ show(p.watchdog?.gaps) }}</td></tr>
        </tbody></table></div>
        <p class="footnote">掩码恢复只表示暂停设置已回读一致；流量恢复及无损性需要单独验收。</p>
      </section>
      <section class="card"><h2>DCBX 本机与对端策略</h2><p class="body-copy">{{ applied?.qos.roce.enabled && applied.qos.roce.dcbx==='ieee' ? 'IEEE DCBX · 本机策略优先。配置状态与对端通告分别检查。' : 'DCBX 已关闭，主机需手动对齐。' }}</p>
        <div v-if="!failed && operational?.dcbx?.ports?.length" class="table-wrap"><table><thead><tr><th>端口</th><th>策略状态</th><th>本机通告发送数</th><th>对端</th></tr></thead><tbody><tr v-for="p in operational.dcbx.ports" :key="p.port"><td>P{{ p.port }}</td><td>{{ validSample ? dcbxLabel(p.state) : '样本未确认 / 已过期' }}</td><td>{{ show(p.tx_frames) }}</td><td>{{ p.peers.map(p=>p.system_name || '未命名邻居').join('、') || '暂无' }}</td></tr></tbody></table></div>
        <details v-if="!failed && operational?.dcbx" class="subsection"><summary>查看 PFC / ETS / 应用策略</summary><pre class="roce-json">{{ JSON.stringify(operational.dcbx,null,2) }}</pre></details>
      </section>
      <section class="card"><h2>对端与验收检查</h2><ol class="roce-checklist"><li>网卡和驱动需提供 RDMA 设备，确认 RoCEv2 GID 与业务 VLAN 对应。</li><li>{{ applied?.qos.roce.classification==='dscp' ? `主机数据使用 DSCP ${applied.qos.roce.dscp}、CNP 使用 DSCP ${applied.qos.roce.cnp_dscp}；PFC 使用优先级 3，CNP 优先级 6 不启用 PFC。` : '主机发送 PCP3 标签流量，并启用优先级 3 PFC。' }}开启 DCBX 时还需确认双方通告及主机实际应用状态。</li><li>核对主机与路径 MTU；交换机 L2 MTU 与主机 IP/RDMA MTU 的口径不同，不直接照抄数值。</li><li>执行 Read / Write / Send、双向、多 QP 与持续流量测试，记录拓扑、速率、MTU 和配置版本。</li><li>施加受控拥塞，验证 PFC 报文、丢弃与恢复及普通流量隔离；仅靠互通或零计数不能完成验收。</li></ol></section>
    </template>
  </section>
</template>

<style scoped>
.roce-status{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:20px 0}.roce-status>div{background:#f5f8fa;border:1px solid #e6edef;border-radius:8px;padding:17px;display:flex;flex-direction:column;gap:10px}.roce-status span,.roce-status small{color:#71858e;font-size:11px;line-height:1.6}.roce-status strong{font-size:16px;font-weight:550;color:#294e55}.roce-fields{border:0;padding:0;margin:0;min-width:0}.roce-steps{display:flex;list-style:none;padding:0;gap:8px;margin:18px 0 24px}.roce-steps li{flex:1;padding:12px;background:#f1f5f6;color:#778c96;font-size:12px;border-radius:5px}.roce-steps [aria-current=step]{background:#e2f3ec;color:#23755b;font-weight:600}.roce-port-group{margin-top:20px}.roce-port-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:10px}.roce-port{padding:13px;border:1px solid #dfe8ec;border-radius:7px;background:#fafcfd;cursor:pointer;min-width:0}.roce-port.selected{border-color:#5ba98b;background:#eff9f3}.roce-port.unavailable{background:#f5f6f7;color:#8b969c}.roce-port>span{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.roce-port input{width:15px;height:15px;margin:0}.roce-port span span,.roce-port small{font-size:10px;line-height:1.6}.roce-port small{display:block;margin-top:7px;overflow-wrap:anywhere}.roce-results{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:22px 0}.roce-results>div{display:flex;flex-direction:column;gap:10px}.roce-results strong{font-size:24px;color:#365c64;font-weight:550}.roce-results small,.roce-results span{font-size:11px;color:#83949e}.roce-issues,.roce-checklist{padding-left:22px;font-size:12px;line-height:1.9;color:#647b87}.roce-suggestion{margin:12px 0;line-height:1.7}.roce-json{max-height:320px;overflow:auto;background:#f7f9fa;padding:14px;font-size:11px}summary{cursor:pointer;font-size:13px;color:#506e7a;margin-bottom:18px}h4{font-size:12px;color:#617b85}.roce-page .definition-row>span:last-child{overflow-wrap:anywhere}.roce-page .inline-form{margin-top:18px}
@media(max-width:1100px){.roce-port-grid,.roce-results{grid-template-columns:repeat(2,minmax(0,1fr))}.roce-status{grid-template-columns:1fr}.roce-status>div{gap:6px}.roce-status strong{font-size:15px}}
@media(max-width:480px){.roce-port-grid,.roce-page .form-grid{grid-template-columns:1fr}.roce-steps{gap:4px}.roce-steps li{font-size:10px;padding:10px 7px}.roce-page .definition-row{align-items:flex-start;gap:10px}.roce-page .definition-row>span:first-child{flex-shrink:1}}
</style>
