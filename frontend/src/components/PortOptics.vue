<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import EyeDiagram from './EyeDiagram.vue'
import { advanceSampleClock, portFreshness } from '../portTelemetry'
import type { OpticalSnapshot, PortGroup, PortTelemetry } from '../types'

const props = defineProps<{portId:number; group:PortGroup; profile:string; moduleInfo?:any; temperature?:any; ports:PortTelemetry[]; sampleNow:number|null; disabled?:boolean}>()
const snapshot = ref<OpticalSnapshot|null>(null), requestError = ref(''), lane = ref(0)
const receipt = ref({serverTime:0,monotonic:0})
let generation = 0, timer:ReturnType<typeof setTimeout>|undefined, disposed = false
const base = computed(() => Math.floor((props.portId-1)/4)*4+1)
const counterPort = computed(() => props.group.mode === 'split' ? props.portId : base.value)
const runtime = computed(() => props.ports.find(port => port.id === counterPort.value))
const clock = computed(() => {
  props.sampleNow
  return snapshot.value ? advanceSampleClock(receipt.value.serverTime,receipt.value.monotonic,performance.now()) : null
})
const scoped = computed(() => snapshot.value?.port === props.portId && snapshot.value?.epl === props.group.epl ? snapshot.value : null)
const matches = computed(() => scoped.value?.mode === props.group.mode && scoped.value?.profile === props.profile)
const phy = computed(() => matches.value ? snapshot.value?.phy : undefined)
// A configuration read can fail before mode/profile are known. Keep its error
// visible, while only exposing measurements that match the applied mode.
const status = computed(() => matches.value || scoped.value?.mode == null ? scoped.value?.phy : undefined)
const errorText = computed(() => requestError.value || status.value?.error || '')
const current = computed(() => phy.value?.lanes.find(item => item.lane === lane.value))
const historical = computed(() => !!requestError.value || phy.value?.quality === 'stale' ||
  (clock.value !== null && phy.value?.sampled_at != null && clock.value-phy.value.sampled_at > (snapshot.value?.stale_after_seconds || 15)))
const stateLabel = computed(() => requestError.value ? (phy.value?.sampled_at ? '上次诊断' : '读取失败') : historical.value ? '上次诊断' :
  status.value?.reason === 'mode_changed' || (scoped.value?.mode != null && !matches.value) ? '等待模式更新' :
  ({valid:'PHY 已更新',partial:'部分数据缺失',simulated:'模拟诊断',unsupported:'PHY 暂不可用',unavailable:'读取失败'}[status.value?.quality || ''] || '等待诊断'))
const sampleTime = computed(() => phy.value?.sampled_at ? new Date(phy.value.sampled_at*1000).toLocaleTimeString('zh-CN',{hour12:false}) : '未取得')
const moduleFresh = computed(() => ['valid','simulated'].includes(props.moduleInfo?.quality) && props.moduleInfo?.sampled_at != null &&
  props.sampleNow !== null && props.sampleNow-props.moduleInfo.sampled_at <= 15)
const txEnabled = computed(() => {
  const mask=props.moduleInfo?.tx_enable_mask, bit=(Math.floor((base.value-1)/4)%3)*4+lane.value
  return moduleFresh.value && Number.isInteger(mask) && mask>=0 && mask<=0xfff ? !!(mask & (1<<bit)) : null
})
const powerChannel = computed(() => (Math.floor((base.value-1)/4)%3)*4+lane.value)
const rxPower = computed(() => props.moduleInfo?.rx_power?.find((p:any)=>p.channel===powerChannel.value))
const powerQuality = computed<string>(() => {
  const quality=props.moduleInfo?.rx_power_quality || 'unavailable', at=props.moduleInfo?.rx_power_sampled_at
  return quality==='valid' && (at==null || props.sampleNow===null || props.sampleNow-at>15) ? 'stale' : quality
})
const powerState = computed(() => ({valid:'RX 平均功率',stale:'上次 RX 读数',not_ready:'模块尚未就绪',unqualified:'未校验',unsupported_format:'模块不支持',unavailable:'未读取'}[powerQuality.value] || '未读取'))
const powerText = computed(() => {
  if(!['valid','stale'].includes(powerQuality.value) || !rxPower.value) return powerState.value
  return rxPower.value.raw===0 ? '0 µW' : typeof rxPower.value.dbm==='number' ? rxPower.value.dbm.toFixed(2)+' dBm' : '未读取'
})
const bool = (value:boolean|null|undefined, yes='是', no='否') => value == null ? '未读取' : value ? yes : no
const number = (value:unknown) => typeof value === 'number' && Number.isFinite(value) ? value.toLocaleString('zh-CN') : '未读取'
const count = (values?:(boolean|null)[]) => values?.length === 4 && values.every(value => value !== null) ? values.filter(Boolean).length+'/4' : '未读取'
const dfe = (value:number|null|undefined) => value == null ? '未读取' : ['未开始','进行中','已完成','异常'][value] || '未知（'+value+'）'
const dfeMode = (value:number|null|undefined) => value == null ? '未读取' : ['静态','单次调节','连续调节','KR 训练','仅初始校准'][value] || '未知（'+value+'）'
const counterState = computed(() => portFreshness(runtime.value,props.sampleNow).delayed ? '上次端口计数' : '端口累计计数')
const maskText = computed(() => Number.isInteger(props.moduleInfo?.tx_enable_mask) ? '0x'+props.moduleInfo.tx_enable_mask.toString(16).padStart(3,'0') : '未读取')

async function poll(token:number) {
  let delay=5000
  try {
    const value=await api<OpticalSnapshot>('/optics/ports/'+props.portId)
    if(disposed || token!==generation) return
    if(value.port!==props.portId || value.epl!==props.group.epl) throw new Error('诊断响应与当前端口不一致')
    snapshot.value=value
    receipt.value={serverTime:value.server_time,monotonic:performance.now()}
    requestError.value=''
    delay=value.refreshing || value.phy.quality==='pending' ? 1000 : 5000
  } catch(error) {
    if(disposed || token!==generation) return
    requestError.value=error instanceof Error ? error.message : String(error)
  } finally {
    if(!disposed && token===generation) timer=setTimeout(()=>poll(token),delay)
  }
}
watch(() => [props.portId,props.group.mode,props.profile], () => {
  if(timer) clearTimeout(timer)
  snapshot.value=null; requestError.value=''; lane.value=props.portId-base.value
  void poll(++generation)
}, {immediate:true})
onUnmounted(() => {disposed=true;++generation;if(timer) clearTimeout(timer)})
</script>

<template>
  <div class="port-optics">
    <div class="optics-channel-heading">
      <strong :title="(group.mode === 'split' ? '拆分口 P'+portId : '合口 P'+base)+' 的 Lane '+lane">P{{ group.mode === 'split' ? portId : base }} · L{{ lane }}</strong>
      <div v-if="group.mode !== 'split'" class="optics-lane-selector" role="group" aria-label="诊断通道">
        <button v-for="id in [0,1,2,3]" :key="id" type="button" :aria-pressed="lane === id" :aria-label="'查看 Lane '+id+' 光学诊断'" @click="lane=id">L{{ id }}</button>
      </div>
    </div>
    <div class="optics-layout">
    <div class="optics-signal-column">
    <div class="optics-power-grid" aria-label="当前通道光功率">
      <div><span title="TX 发射光功率">TX 功率</span><strong>{{ moduleInfo?.tx_power_quality === 'unsupported' ? '模块不支持' : '未提供' }}</strong></div>
      <div><span :title="powerState">{{ powerState }}</span><strong :class="{'text-warning':powerQuality==='stale'}">{{ powerText }}</strong></div>
    </div>
    <div class="optics-section-heading"><h3>信号状态</h3><span class="tag" :class="{amber:historical || ['unavailable','partial'].includes(status?.quality || '')}">{{ stateLabel }}</span></div>
    <p v-if="phy?.reason === 'split_mode'" class="optics-state-note">当前接口仅提供 40G/100G 合口的 PHY 诊断；此拆分口可查看发射开关及端口计数。</p>
    <p v-else-if="stateLabel === '等待模式更新'" class="optics-state-note">正在等待与当前速率匹配的新快照。</p>
    <p v-else-if="errorText" class="optics-state-note">{{ errorText }}</p>
    <p v-else-if="historical" class="optics-state-note">超过 15 秒未取得新快照，以下保留上次 PHY 诊断。</p>
    <dl class="optics-values">
      <div><dt>发射开关</dt><dd>{{ bool(txEnabled,'开启','关闭') }}</dd></div>
      <div><dt>TX / RX 就绪</dt><dd>{{ bool(current?.tx_ready) }} / {{ bool(current?.rx_ready) }}</dd></div>
      <div><dt>RX 电活动 / 空闲</dt><dd>{{ bool(current?.rx_activity,'有','无') }} / {{ bool(current?.rx_idle) }}</dd></div>
      <div><dt>DFE 粗调 / 精调</dt><dd>{{ dfe(current?.coarse_dfe) }} / {{ dfe(current?.fine_dfe) }}</dd></div>
    </dl>
    <p v-if="rxPower && ['valid','stale'].includes(powerQuality)" class="optics-note">{{ rxPower.microwatts.toFixed(1) }} µW · 模块通道 {{ powerChannel }} · 分辨率 0.1 µW<span v-if="rxPower.raw===0">；零读数不能换算为有限 dBm</span>。</p>
    <section v-if="group.mode !== 'split'" class="optics-pcs">
      <h3>合口 PCS-ML 状态</h3>
      <dl class="optics-values">
        <div><dt>码块锁定 / AM 锁定</dt><dd>{{ count(phy?.pcs?.block_lock) }} / {{ count(phy?.pcs?.am_lock) }}</dd></div>
        <div><dt>四路对齐</dt><dd>{{ bool(phy?.pcs?.aligned,'已对齐','未对齐') }}</dd></div>
        <div><dt>高误码指示</dt><dd>{{ bool(phy?.pcs?.high_ber,'已触发','未触发') }}</dd></div>
      </dl>
      <p class="optics-note">显示 PCS-ML 的四组状态位；当前接口未导出 100G 的 20 条虚拟 PCS Lane。未触发高误码指示不代表信号质量合格。</p>
    </section>
    </div>
    <EyeDiagram class="optics-eye-column" :port="counterPort" :lane="lane" :mode="group.mode" :profile="profile" :speed="group.mode==='split' ? group.lane_speeds[lane] : group.mode==='100g' ? 25 : 10" :disabled="disabled" />
    <details class="optics-more">
      <summary>均衡参数与采样信息</summary>
      <dl class="optics-values">
        <div><dt>TX 前游标 / 主游标 / 后游标</dt><dd>{{ number(current?.tx_pre) }} / {{ number(current?.tx_cursor) }} / {{ number(current?.tx_post) }}</dd></div>
        <div><dt>DFE 模式</dt><dd>{{ dfeMode(current?.dfe_mode) }}</dd></div>
        <div><dt>RX / TX 极性</dt><dd>{{ number(current?.rx_polarity) }} / {{ number(current?.tx_polarity) }}</dd></div>
        <div><dt>RX 终端设置</dt><dd>{{ number(current?.rx_termination) }}</dd></div>
        <div><dt>信号转换阈值（原始值）</dt><dd>{{ number(current?.signal_transition_threshold) }}</dd></div>
        <div><dt>SerDes / PCS 原始值</dt><dd>{{ current?.serdes_raw || '未读取' }} / {{ phy?.pcs?.raw || '未读取' }}</dd></div>
        <div><dt>PHY 采样时间</dt><dd>{{ sampleTime }}</dd></div>
      </dl>
      <p class="optics-note">仅在查看时按需读取；每个 EPL 最多每 5 秒刷新一次。电气活动及均衡参数不能换算成光功率。</p>
    </details>
    <details class="optics-more">
      <summary>P{{ counterPort }} {{ counterState }}</summary>
      <dl class="optics-values">
        <div><dt>CRC / FCS 错误</dt><dd>{{ number(runtime?.crc_errors) }}</dd></div>
        <div><dt>RX / TX 错误</dt><dd>{{ number(runtime?.rx_errors) }} / {{ number(runtime?.tx_errors) }}</dd></div>
      </dl>
      <p class="optics-note">{{ group.mode === 'split' ? '计数属于当前拆分端口。' : '合口计数属于整个端口，无法分摊到各 Lane。' }}错误计数不能直接换算成 BER。</p>
    </details>
    <details class="optics-more">
      <summary>模块信息与读取限制</summary>
      <dl class="optics-values">
        <div><dt>厂商 / 料号</dt><dd>{{ moduleInfo?.vendor || '未提供' }} / {{ moduleInfo?.part_number || '未提供' }}</dd></div>
        <div><dt>序列号</dt><dd>{{ moduleInfo?.serial_number || moduleInfo?.serial || '未提供' }}</dd></div>
        <div><dt>模块温度</dt><dd>{{ temperature?.celsius?.toFixed(1) ?? '—' }} °C</dd></div>
        <div><dt>模块 12 位 TX 掩码</dt><dd>{{ maskText }}{{ moduleFresh ? '' : '（非实时）' }}</dd></div>
        <div><dt>模块采样时间</dt><dd>{{ moduleInfo?.sampled_at ? new Date(moduleInfo.sampled_at*1000).toLocaleTimeString('zh-CN',{hour12:false}) : '未取得' }}</dd></div>
      </dl>
      <p class="optics-note">本模块 RX 平均功率按 CXP 接收监测表读取，每单位 0.1 µW；规范容差 ±3 dB。TX 功率监测不支持；发射开关不等于光功率。</p>
      <p class="optics-note">眼图由片上偏移采样器逐点采集，可导出原始计数。电气眼图不等同于光域眼图，DAC 刻度不换算为未校准的 mV。</p>
      <p class="optics-note">Lane 为 EPL 逻辑编号，光纤芯序需按实物标定。</p>
    </details>
    </div>
  </div>
</template>
