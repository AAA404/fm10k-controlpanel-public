<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { Cable, ChevronUp, CircleHelp, Settings2 } from 'lucide-vue-next'
import type { Configuration, PortGroup, PortTelemetry } from '../types'
import PortSettings from './PortSettings.vue'
import PortRateEditor from './PortRateEditor.vue'
import PortOptics from './PortOptics.vue'
import PortInspector from './PortInspector.vue'
import { changeGroupMode } from '../portModes'
import { portFreshness, portLinkLabel } from '../portTelemetry'

const props = defineProps<{
  configuration: Configuration
  appliedConfiguration: Configuration
  ports: PortTelemetry[]
  optics: any[]
  temperatures: any[]
  selectedPort: number|null
  settingsPort: number|null
  disabled?: boolean
  modalBlocked?: boolean
  sampleNow: number|null
  sampleInterval: number
  staleAfter: number
  samplingError?: string|null
}>()
const emit = defineEmits<{ 'update:selectedPort':[port:number|null]; 'update:settingsPort':[port:number|null] }>()
const epls = [0,1,2,5,6,7], search = ref('')
// Keep the outgoing inspector inside its own fixed card until it fades out.
const detailPort = ref<number|null>(null), detailVisible = ref(false)
const detailTabs = ['端口详情', '收发统计', 'VLAN 状态', '光模块']
const activeTab = ref(0)
const sampleHelpOpen = ref(false)
const rateEdit = ref<{port: number; mode: PortGroup['mode']; original: number; speed: number}|null>(null)
const base = (group: PortGroup) => epls.indexOf(group.epl)*4+1
const mpo = (group: PortGroup) => epls.indexOf(group.epl) < 3 ? 1 : 2
const groupPorts = (group: PortGroup) => [0,1,2,3].map(lane => base(group)+lane)
const expanded = (group: PortGroup) => detailPort.value !== null && groupPorts(group).includes(detailPort.value)
const groupsFor = (module: number) => props.appliedConfiguration.groups.filter(group => mpo(group) === module)
const data = (id: number) => props.ports.find(port => port.id === id)
const groupFor = (id: number) => props.appliedConfiguration.groups.find(group => groupPorts(group).includes(id))!
const draftGroup = (group: PortGroup) => props.configuration.groups.find(candidate => candidate.epl === group.epl)!
const configuredSpeed = (group: PortGroup, id: number) => group.mode === 'split' ? group.lane_speeds[id-base(group)]! : id === base(group) ? group.mode === '100g' ? 100 : 40 : null
const draftSpeed = (group: PortGroup, id: number) => configuredSpeed(draftGroup(group),id)
const speedChanged = (group: PortGroup, id: number) => draftSpeed(group,id) !== configuredSpeed(group,id)
const currentSpeed = (id: number) => data(id)?.active === false ? '合口占用' : data(id)?.speed_gbps == null ? '不可用' : data(id)!.speed_gbps+'G'
const selected = computed(() => detailPort.value === null ? null : props.appliedConfiguration.ports[detailPort.value])
const runtime = computed(() => detailPort.value === null ? undefined : data(detailPort.value))
const freshness = (port?:PortTelemetry) => portFreshness(port,props.sampleNow,props.staleAfter,props.samplingError)
const sampling = computed(() => freshness(runtime.value))
const online = (port?:PortTelemetry) => !!port && port.link === 'up' && port.active && !port.degraded && !freshness(port).delayed && !['unavailable','pending'].includes(port.state_quality || port.quality)
const hasDraft = computed(() => detailPort.value !== null && (
  JSON.stringify(props.configuration.ports[detailPort.value]) !== JSON.stringify(selected.value) ||
  speedChanged(groupFor(detailPort.value),detailPort.value) ||
  draftGroup(groupFor(detailPort.value)).mode !== groupFor(detailPort.value).mode
))
const moduleInfo = (module: number) => props.optics.find(optic => optic.mpo === module)
const moduleTemperature = (module: number) => props.temperatures.find(sensor => sensor.id === 'obt'+module)
const vlanLabel = (id: number) => {
  const vlan = props.appliedConfiguration.vlans.find(vlan => vlan.id === id)
  return id+' · '+(vlan ? vlan.name.trim() || '未命名' : '名称未提供')
}
const associations = computed(() => {
  const id = detailPort.value
  if (id === null) return []
  const configuration = props.appliedConfiguration
  const result = []
  const lag = configuration.lags.find(lag => lag.members.includes(id))
  if (lag) result.push(lag.name + ' · ' + lag.mode + ' 聚合成员')
  const mirror = configuration.mirror
  if (mirror.enabled && mirror.source === id) result.push('镜像源 · ' + mirror.direction)
  if (mirror.enabled && mirror.destination === id) result.push('镜像目的口')
  for (const mac of configuration.static_macs.filter(mac => mac.port === id))
    result.push('静态 MAC ' + mac.mac + ' / VLAN ' + mac.vlan)
  if (configuration.igmp.router_ports.includes(id)) result.push('IGMP 静态路由器端口')
  if (configuration.igmp.fast_leave_ports.includes(id)) result.push('IGMP Fast Leave')
  for (const group of configuration.igmp.static_groups.filter(group => group.ports.includes(id)))
    result.push('组播 ' + group.address + ' / VLAN ' + group.vlan)
  return result
})
const counters = computed(() => [
  ['字节', runtime.value?.rx_bytes, runtime.value?.tx_bytes],
  ['报文', runtime.value?.rx_packets, runtime.value?.tx_packets],
  ['错误', runtime.value?.rx_errors, runtime.value?.tx_errors],
  ['丢弃', runtime.value?.rx_drops, runtime.value?.tx_drops],
])
async function openRate(group: PortGroup, id: number) {
  const speed = draftSpeed(group,id)
  if (props.disabled || speed === null) return
  rateEdit.value = {port:id,mode:draftGroup(group).mode,original:speed,speed}
  await nextTick()
  if (rateEdit.value?.port === id) document.getElementById('port-rate-'+id)?.focus({preventScroll:true})
}
async function cancelRate(restoreFocus = true) {
  const id = rateEdit.value?.port
  rateEdit.value = null
  if (!restoreFocus || id === undefined) return
  await nextTick()
  document.getElementById((props.disabled ? 'port-tile-' : 'port-rate-trigger-')+id)?.focus({preventScroll:true})
}
function saveRate(group: PortGroup, id: number) {
  const edit = rateEdit.value, draft = draftGroup(group)
  if (!edit || edit.port !== id) return
  if (props.disabled || draft.mode !== edit.mode || configuredSpeed(draft,id) !== edit.original) {
    cancelRate()
    return
  }
  const speed = edit.speed
  if (draft.mode === 'split') {
    if ([10,25].includes(speed)) draft.lane_speeds[id-base(group)] = speed
  } else if (id === base(group) && [40,100].includes(speed)) changeGroupMode(props.configuration,draft,speed === 100 ? '100g' : '40g')
  cancelRate()
}
function selectPort(id: number) {
  rateEdit.value = null
  emit('update:selectedPort',props.selectedPort === id ? null : id)
}
function matches(id: number) {
  const term = search.value.trim().toLowerCase().replace(/\s+/g,'')
  const g = groupFor(id)
  return !term || ('P'+id+' '+props.appliedConfiguration.ports[id]?.name+' EPL'+g.epl+' OBT'+mpo(g)+' MPO'+mpo(g)).toLowerCase().replace(/\s+/g,'').includes(term)
}
function visibleGroup(group: PortGroup) { return groupPorts(group).some(matches) || expanded(group) }
function status(port?: PortTelemetry) {
  return portLinkLabel(port,freshness(port).delayed)
}
function portDescription(group: PortGroup, id: number) {
  const speed = draftSpeed(group,id)
  const rate = speed === null ? '合口占用' : speed+'G'
  return [props.appliedConfiguration.ports[id]?.name,
    speedChanged(group,id) ? '待提交 '+rate+'，当前 '+currentSpeed(id) : '配置 '+rate+'，当前 '+currentSpeed(id),
    data(id)?.active === false ? '归属 P'+base(group) : status(data(id)), freshness(data(id)).label].filter(Boolean).join('，')
}
const number = (value: unknown) => typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('zh-CN') : '不可用'
const timestamp = (value?: number|null) => value ? new Date(value*1000).toLocaleTimeString('zh-CN',{hour12:false}) : '未取得采样'
async function close() {
  const previous = detailPort.value
  emit('update:selectedPort',null)
  await nextTick()
  if (previous !== null) document.getElementById('port-tile-'+previous)?.focus({preventScroll:true})
}
function afterLeave() {
  detailPort.value = props.selectedPort
  detailVisible.value = props.selectedPort !== null
}
async function selectTab(index: number) {
  activeTab.value = (index+detailTabs.length)%detailTabs.length
  await nextTick()
  if (detailPort.value !== null) document.getElementById('port-tab-'+groupFor(detailPort.value).epl+'-'+activeTab.value)?.focus({preventScroll:true})
}
async function closeSettings() {
  const previous = props.settingsPort
  emit('update:settingsPort',null)
  await nextTick()
  const floatingSettings = document.querySelector<HTMLElement>('.port-inspector-dialog[open] .port-inspector-settings')
  if (floatingSettings) floatingSettings.focus({preventScroll:true})
  else if (previous !== null) document.getElementById('port-settings-trigger-'+groupFor(previous).epl)?.focus({preventScroll:true})
}
watch(() => props.selectedPort, value => {
  if (value !== null && (detailPort.value === null || groupFor(value).epl === groupFor(detailPort.value).epl)) {
    detailPort.value = value
    detailVisible.value = true
  } else {
    detailVisible.value = false
  }
}, {immediate:true})
watch([() => props.selectedPort, () => props.settingsPort, () => props.configuration, () => props.disabled, search], () => {
  rateEdit.value = null
})
watch(() => props.modalBlocked, blocked => {if(blocked)emit('update:settingsPort',null)})
</script>

<template>
  <section class="port-groups-view stack">
    <div class="card-heading port-view-heading"><div><h2>逻辑端口与物理归属</h2><p>点击端口查看详情，标题栏可放大窗口或调速；其他参数在“设置”中调整。</p></div><input v-model="search" class="search" aria-label="查找端口" placeholder="端口 / 名称 / EPL / OBT" /></div>
    <section v-for="module in [1,2]" :key="module" class="obt-port-section" :aria-label="'OBT '+module+' 端口组'">
      <div class="obt-section-heading"><div><Cable :size="20" /><h2>OBT {{ module }} <span>/ MPO {{ module }}</span></h2></div><span>300G · 12 条双工通道</span></div>
      <div class="epl-box-grid">
        <article v-for="group in groupsFor(module)" v-show="visibleGroup(group)" :id="'epl-box-'+group.epl" :key="group.epl" class="card epl-box" :class="{expanded:expanded(group)}" :aria-label="'OBT '+module+' EPL '+group.epl">
          <header class="epl-box-heading">
            <div><span class="epl-label-chip">EPL {{ group.epl }}</span><small>P{{ base(group) }}–P{{ base(group)+3 }}</small></div>
            <span class="tag">{{ group.mode === 'split' ? '4 × Lane' : group.mode.toUpperCase() }}</span>
            <button :id="'port-settings-trigger-'+group.epl" class="port-settings-trigger" :aria-label="'设置端口 P'+(expanded(group) ? detailPort : base(group))" aria-haspopup="dialog"
              @click="emit('update:settingsPort',expanded(group) ? detailPort : base(group))"><Settings2 :size="14" />设置</button>
            <button v-if="expanded(group)" class="icon-button" aria-label="收起端口详情" @click="close"><ChevronUp :size="18" /></button>
          </header>
          <div class="port-tile-grid">
            <div v-for="id in groupPorts(group)" :key="id" class="port-tile" :class="{selected:selectedPort === id,online:online(data(id)),inactive:draftSpeed(group,id) === null,dim:!matches(id),editing:rateEdit?.port === id && !expanded(group)}">
              <button :id="'port-tile-'+id" type="button" class="port-tile-toggle" :aria-label="'查看端口 P'+id+'，OBT '+module+'，EPL '+group.epl" :aria-description="portDescription(group,id)" :title="portDescription(group,id)" :aria-expanded="selectedPort === id" :aria-controls="'port-details-'+group.epl" @click="selectPort(id)">
                <span class="port-tile-heading"><strong>P{{ String(id).padStart(2,'0') }}</strong><span class="port-link-dot" :class="{up:online(data(id)),stale:freshness(data(id)).delayed}"></span></span>
                <template v-if="rateEdit?.port !== id || expanded(group)">
                  <span class="port-tile-rate" :class="{pending:speedChanged(group,id)}">
                    <span class="port-tile-speed">{{ draftSpeed(group,id) !== null ? draftSpeed(group,id)+'G' : speedChanged(group,id) ? '待合口' : expanded(group) ? '合口' : '合口占用' }}</span>
                    <span v-if="speedChanged(group,id) && draftSpeed(group,id) !== null" class="port-rate-pending-marker" aria-hidden="true">待</span>
                  </span>
                  <span v-if="speedChanged(group,id)" class="port-rate-note pending">待提交 · 当前 {{ currentSpeed(id) }}</span>
                  <span v-else-if="draftSpeed(group,id) !== null && data(id)?.speed_gbps !== draftSpeed(group,id)" class="port-rate-note">当前 {{ currentSpeed(id) }}</span>
                  <span class="port-tile-state">{{ data(id)?.active === false ? '归属 P'+base(group) : status(data(id)) }}</span>
                  <span v-if="appliedConfiguration.ports[id]?.name" class="port-tile-name" :title="appliedConfiguration.ports[id]?.name">{{ appliedConfiguration.ports[id]?.name }}</span>
                </template>
              </button>
              <PortRateEditor v-if="rateEdit && rateEdit.port === id && !expanded(group)" v-model:speed="rateEdit.speed" :port-id="id" :original="rateEdit.original"
                :options="draftGroup(group).mode === 'split' ? [10,25] : [40,100]" :disabled="disabled" @cancel="cancelRate()" @save="saveRate(group,id)" />
              <button v-else-if="!expanded(group) && draftSpeed(group,id) !== null" :id="'port-rate-trigger-'+id" type="button" class="port-rate-trigger" :aria-label="'调整 P'+id+' 速率'" :disabled="disabled" @click="openRate(group,id)">调速</button>
            </div>
          </div>
          <Transition name="port-expand" appear @after-leave="afterLeave">
            <PortInspector v-if="detailVisible && expanded(group) && selected && detailPort !== null" :port-id="detailPort" :epl="group.epl" :module="module"
              :active-tab="activeTab" :editing-rate="rateEdit?.port === detailPort" :blocked="modalBlocked" @close="close" @settings="emit('update:settingsPort',detailPort)">
              <template #actions>
                <PortRateEditor v-if="rateEdit && rateEdit.port === detailPort" class="port-rate-inline" v-model:speed="rateEdit.speed" :port-id="detailPort" :original="rateEdit.original"
                  :options="draftGroup(group).mode === 'split' ? [10,25] : [40,100]" :disabled="disabled" @cancel="cancelRate()" @save="saveRate(group,detailPort)" />
                <template v-else>
                  <span v-if="hasDraft" class="tag amber" title="此端口有未提交设置">待提交</span>
                  <button v-if="draftSpeed(group,detailPort) !== null" :id="'port-rate-trigger-'+detailPort" type="button" class="port-detail-rate-trigger" :aria-label="'调整 P'+detailPort+' 速率'" :disabled="disabled" @click="openRate(group,detailPort)">调速</button>
                  <button class="port-freshness" :class="sampling.tone" :aria-label="'查看 P'+detailPort+' 采样说明'" :aria-expanded="sampleHelpOpen" :aria-controls="'port-sample-help-'+group.epl"
                    :title="sampling.description+' 目标每 '+sampleInterval+' 秒采样，超过 '+staleAfter+' 秒标记延迟。'" @click="sampleHelpOpen = !sampleHelpOpen">{{ sampling.label }}<CircleHelp :size="12" /></button>
                </template>
              </template>
              <template #navigation>
                <label>当前端口<select aria-label="切换详情端口" :value="detailPort" @change="selectPort(Number(($event.target as HTMLSelectElement).value))">
                  <option v-for="id in groupPorts(group)" :key="id" :value="id">P{{ id }} / Lane {{ id-base(group) }}{{ id!==base(group) && group.mode!=='split' ? ' · 合口占用' : '' }}</option>
                </select></label>
              </template>
              <div class="port-detail-tabs" role="tablist" aria-label="端口信息">
                <button v-for="(tab,index) in detailTabs" :id="'port-tab-'+group.epl+'-'+index" :key="tab" role="tab" :aria-selected="activeTab === index"
                  :aria-controls="'port-panel-'+group.epl" :tabindex="activeTab === index ? 0 : -1" @click="activeTab = index"
                  @keydown.right.prevent="selectTab(index+1)" @keydown.left.prevent="selectTab(index-1)" @keydown.home.prevent="selectTab(0)" @keydown.end.prevent="selectTab(detailTabs.length-1)">{{ tab }}</button>
              </div>
              <div :id="'port-panel-'+group.epl" class="port-detail-body" role="tabpanel" :aria-labelledby="'port-tab-'+group.epl+'-'+activeTab" tabindex="0">
                <p v-if="sampleHelpOpen" :id="'port-sample-help-'+group.epl" class="port-sample-help" role="note">{{ sampling.description }}<small>设备采样时间：{{ timestamp(runtime?.sampled_at) }}。目标每 {{ sampleInterval }} 秒采样，超过 {{ staleAfter }} 秒未更新时提示延迟；VLAN、MTU 等配置项显示当前已生效配置。</small></p>
                <template v-if="activeTab === 0">
                  <div class="port-runtime-grid port-summary-grid">
                    <div><span>链路</span><strong class="port-current-link" :class="{online:online(runtime),historical:sampling.delayed}">{{ status(runtime) }}</strong></div>
                    <div><span>线速率</span><strong>{{ runtime?.speed_gbps == null ? '不可用' : runtime.speed_gbps+' Gbps' }}</strong></div>
                    <div><span>管理</span><strong>{{ runtime ? runtime.enabled ? '启用' : '关闭' : '不可用' }}</strong></div>
                    <div><span>调度</span><strong>{{ runtime?.scheduler_speed_gbps == null ? '不可用' : runtime.scheduler_speed_gbps+' Gbps' }}</strong></div>
                    <div class="port-field-wide"><span>接口模式</span><strong>{{ runtime?.ethernet_mode || '未提供' }}</strong></div>
                    <div class="port-field-wide"><span>物理归属</span><strong>OBT {{ module }} / EPL {{ group.epl }} / Lane {{ detailPort-base(group) }}<small v-if="runtime?.active === false">合口归属 P{{ base(group) }}</small></strong></div>
                    <div class="port-field-wide"><span>用户名称</span><strong>{{ selected.name || '未命名' }}</strong></div>
                    <div class="port-field-wide"><span>接口 MTU</span><strong>{{ selected.mtu }}</strong></div>
                    <div class="port-field-wide"><span>二层协议</span><strong>LLDP {{ selected.lldp ? '开' : '关' }} · BPDU 保护{{ selected.bpdu_guard ? '开' : '关' }}<small>RSTP {{ selected.edge ? '边缘端口' : '非边缘端口' }}</small></strong></div>
                  </div>
                </template>
                <template v-else-if="activeTab === 1">
                  <table class="port-stat-table" aria-label="端口收发统计"><thead><tr><th scope="col">统计项</th><th scope="col">接收 RX</th><th scope="col">发送 TX</th></tr></thead><tbody><tr v-for="[label,rx,tx] in counters" :key="String(label)"><th scope="row">{{ label }}</th><td class="mono">{{ number(rx) }}</td><td class="mono">{{ number(tx) }}</td></tr></tbody></table>
                  <div class="port-crc-summary"><span>CRC / FCS 错误</span><strong class="mono">{{ number(runtime?.crc_errors) }}</strong></div>
                  <p class="footnote">来自端口快照；未取得的计数显示为不可用。</p>
                </template>
                <template v-else-if="activeTab === 2">
                  <div class="port-runtime-grid port-vlan-grid">
                    <div><span>VLAN 模式</span><strong>{{ selected.vlan_mode === 'trunk' ? 'Trunk' : 'Access' }}</strong></div>
                    <div><span>入口 VLAN 过滤</span><strong>{{ selected.ingress_filtering ? '启用' : '关闭' }}</strong></div>
                    <div><span>PVID / Native VLAN</span><strong>{{ selected.pvid == null ? '未配置' : vlanLabel(selected.pvid) }}</strong></div>
                    <div><span>Tagged VLAN</span><ul v-if="selected.tagged_vlans.length" class="port-vlan-memberships"><li v-for="id in selected.tagged_vlans" :key="id">{{ vlanLabel(id) }}</li></ul><strong v-else>无</strong></div>
                  </div>
                  <section v-if="associations.length" class="port-detail-section"><h3>关联配置</h3><ul class="port-associations"><li v-for="item in associations" :key="item">{{ item }}</li></ul></section>
                  <p v-else class="port-empty-associations">关联配置：无</p>
                  <p class="footnote">显示当前生效配置，未提交修改可在“设置”中查看。</p>
                </template>
                <template v-else>
                  <PortOptics :port-id="detailPort" :group="group" :profile="appliedConfiguration.profile" :module-info="moduleInfo(module)"
                    :temperature="moduleTemperature(module)" :ports="ports" :sample-now="sampleNow" :disabled="disabled" />
                </template>
              </div>
            </PortInspector>
          </Transition>
        </article>
      </div>
    </section>
    <p v-if="search && !appliedConfiguration.groups.some(visibleGroup)" class="empty">没有匹配的端口、EPL 或 OBT。</p>
  </section>
  <PortSettings v-if="settingsPort !== null" :configuration="configuration" :applied-configuration="appliedConfiguration" :port-id="settingsPort" :disabled="disabled"
    @update:port-id="emit('update:settingsPort',$event)" @close="closeSettings" />
</template>
