<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { Clock3, LoaderCircle, RefreshCw } from 'lucide-vue-next'
import { api } from '../api'
import { advanceSampleClock } from '../portTelemetry'

const props = defineProps<{ disabled?: boolean }>()
interface TimeStatus {
  available: boolean; provider: string; state: string; enabled: boolean; synchronized: boolean;
  server_time: number; timezone: string; servers: string[]; fallback_servers?: string[];
  network_servers?: string[]; runtime_servers?: string[];
  selected_server: string|null; server_address: string|null; last_synchronized_at: number|null; message: string;
}
const status = ref<TimeStatus|null>(null), error = ref(''), notice = ref('')
const readError = ref('')
const visibleError = computed(() => error.value || readError.value)
const servers = ref(''), dirty = ref(false), reading = ref(false), syncing = ref(false)
const commonServers = [
  {label:'阿里云',host:'ntp.aliyun.com'},
  {label:'腾讯云',host:'ntp.tencent.com'},
  {label:'国家授时中心',host:'ntp.ntsc.ac.cn'},
  {label:'中国 NTP Pool（服务器池）',host:'cn.pool.ntp.org'},
]
const selectedServer = ref('')
const enteredServers = computed(() => servers.value.split(/[\n,，]+/).map(s=>s.trim().toLowerCase()).filter(Boolean))
const cannotAddServer = computed(() => !selectedServer.value || enteredServers.value.length >= 4 || enteredServers.value.includes(selectedServer.value))
function addServer() {
  if (cannotAddServer.value || syncing.value || props.disabled || !status.value?.available) return
  servers.value = [...enteredServers.value,selectedServer.value].join('\n')
  dirty.value = true; selectedServer.value = ''; error.value = ''; notice.value = ''
}
const tick = ref(performance.now()), received = ref(performance.now())
let disposed = false, timer: ReturnType<typeof setInterval>|undefined, polls = 0
let readInFlight = false, requestGeneration = 0
const deviceNow = computed(() => advanceSampleClock(status.value?.server_time ?? null, received.value, tick.value))
const usable = computed(() => !readError.value && tick.value - received.value < 15000)
const label = computed(() => !usable.value ? '状态未更新' : ({synchronized:'已同步',waiting:'等待服务器响应',disabled:'未开启',unavailable:'服务不可用','service-error':'服务异常',simulated:'模拟模式'}[status.value?.state || ''] || '正在读取'))
function displayTime(epoch: number|null|undefined) {
  if (!epoch) return '—'
  try { return new Date(epoch*1000).toLocaleString('zh-CN',{timeZone:status.value?.timezone || 'UTC',hour12:false}) }
  catch { return new Date(epoch*1000).toISOString() }
}
function update(value: TimeStatus, replaceForm = false) {
  status.value = value; received.value = tick.value = performance.now()
  if (value.synchronized) notice.value = ''
  if (!dirty.value || replaceForm) {
    servers.value = (value.servers.length ? value.servers : value.fallback_servers?.length ? value.fallback_servers : ['ntp.aliyun.com','ntp.tencent.com']).join('\n')
    dirty.value = false
  }
}
async function refresh(manual = true) {
  if (readInFlight || syncing.value || disposed) return
  readInFlight = true
  // Polling must not blink or disable the controls every five seconds.
  reading.value = manual
  const generation = ++requestGeneration
  try {
    const value = await api<TimeStatus>('/system/time')
    if (!disposed && generation === requestGeneration) { update(value); readError.value = '' }
  } catch (e) { if (!disposed && generation === requestGeneration) readError.value = e instanceof Error ? e.message : String(e) }
  finally { readInFlight = false; reading.value = false }
}
async function synchronize(save: boolean) {
  if (props.disabled || syncing.value || reading.value || !status.value?.available) return
  error.value = ''; notice.value = ''
  const values = servers.value.split(/[\n,，]+/).map(s=>s.trim()).filter(Boolean)
  if (save && (!values.length || values.length>4)) { error.value = '请填写 1～4 个时间服务器，每行一个。'; return }
  // A GET already in flight may describe the state before this mutation.
  ++requestGeneration
  syncing.value = true
  try {
    const value = await api<TimeStatus>('/system/time/sync',save ? {servers:values} : {})
    if (!disposed) { update(value,save); readError.value = ''; notice.value = value.message }
  } catch (e) { if (!disposed) error.value = e instanceof Error ? e.message : String(e) }
  finally { syncing.value = false }
}
onMounted(() => {
  void refresh()
  timer = setInterval(() => {
    tick.value = performance.now()
    if (++polls % 5 === 0 && document.visibilityState === 'visible') void refresh(false)
  },1000)
})
onUnmounted(() => { disposed = true; if (timer) clearInterval(timer) })
</script>

<template>
  <section class="card time-settings">
    <div class="card-heading"><div><h2>日期与时间</h2><p>通过 NTP 时间服务器在线校时，自动保持设备时间准确。</p></div><Clock3 :size="20" /></div>
    <div class="time-summary"><div><span>设备时间 · {{ status?.timezone || '—' }}</span><strong>{{ displayTime(deviceNow) }}</strong></div><span class="tag" :class="{amber:!usable || !status?.synchronized}" role="status">{{ label }}</span></div>
    <div class="definition-row"><span>自动同步</span><span>{{ status ? status.enabled ? '已开启' : '未开启' : '—' }}</span></div>
    <div class="definition-row"><span>当前时间服务器</span><span>{{ status?.selected_server || '尚未选定' }}<small v-if="status?.server_address">{{ status.server_address }}</small></span></div>
    <div class="definition-row"><span>最近成功同步</span><span>{{ displayTime(status?.last_synchronized_at) }}</span></div>
    <p v-if="status && !status.synchronized" class="footnote">{{ status.message }}</p>
    <p v-if="status?.network_servers?.length || status?.runtime_servers?.length" class="footnote">系统还提供了网络时间服务器：{{ [...(status.network_servers || []),...(status.runtime_servers || [])].join('、') }}。实际使用的服务器以上方回读为准。</p>
    <form @submit.prevent="synchronize(true)">
      <div class="inline-form time-presets"><label>国内常用时间服务器<select v-model="selectedServer" aria-label="国内常用时间服务器" :disabled="syncing || disabled || !status?.available"><option value="">选择备选服务器</option><option v-for="server in commonServers" :key="server.host" :value="server.host">{{ server.label }} · {{ server.host }}</option></select></label><button class="secondary" type="button" :disabled="cannotAddServer || syncing || disabled || !status?.available" @click="addServer">添加到列表</button></div>
      <p class="footnote">备选服务器可与自定义地址组合使用；添加后需保存才生效。已在列表中的地址不会重复添加，最多保留 4 个。</p>
      <label class="time-servers">时间服务器<textarea v-model="servers" rows="3" maxlength="1024" :disabled="syncing || disabled || !status?.available" placeholder="ntp.aliyun.com&#10;ntp.tencent.com" @input="dirty=true; error=''; notice=''"></textarea></label>
      <p class="footnote">每行一个主机名或 IP，最多 4 个；可填写内网时间服务器。保存后开启自动同步；按钮仅发起请求，收到有效响应后才显示“已同步”。</p>
      <p class="footnote">校时前请先完成配置提交或回滚。登录会话有效期不受系统时间校正影响。</p>
      <div v-if="visibleError" class="alert danger" role="alert">{{ visibleError }}</div>
      <div v-if="notice && !visibleError" class="alert" role="status">{{ notice }}</div>
      <div class="inline-actions">
        <button class="primary" type="submit" :disabled="syncing || reading || disabled || !status?.available" :aria-busy="syncing"><LoaderCircle v-if="syncing" :size="16" class="spin" />{{ syncing ? '正在发起同步…' : '保存并同步' }}</button>
        <button class="secondary" type="button" :disabled="syncing || reading || disabled || dirty || !status?.available" @click="synchronize(false)">立即同步</button>
        <button class="secondary" type="button" :disabled="reading || syncing" @click="refresh()"><RefreshCw :size="16" />刷新状态</button>
      </div>
    </form>
  </section>
</template>

<style scoped>
.time-summary{display:flex;align-items:center;justify-content:space-between;gap:16px;background:#f5f8fa;border-radius:8px;padding:18px;margin-bottom:12px}.time-summary>div{display:flex;flex-direction:column;gap:9px}.time-summary span{font-size:12px;color:#71858e}.time-summary strong{font-size:20px;font-weight:550;color:#294e55}.time-servers{display:flex;flex-direction:column;gap:8px;margin-top:22px;font-size:12px;color:#617b85}.time-servers textarea{font:13px/1.8 ui-monospace,monospace;border:1px solid #dfe8ec;border-radius:6px;padding:10px;resize:vertical;max-width:100%;box-sizing:border-box;background:#fff;color:#294e55}.time-settings .definition-row>span:last-child{overflow-wrap:anywhere}.time-settings .inline-actions{flex-wrap:wrap}.time-presets{margin-top:22px}.time-presets label{min-width:0;flex:1}.time-presets select{width:100%;min-width:0}
@media(max-width:600px){.time-summary{align-items:flex-start;flex-direction:column}.time-summary strong{font-size:17px}.time-settings .definition-row{gap:12px;align-items:flex-start}}
</style>
