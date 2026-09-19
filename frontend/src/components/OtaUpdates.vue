<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ArrowRight, Github, LoaderCircle, RefreshCw } from 'lucide-vue-next'
import { api } from '../api'
const props = defineProps<{ status: any; currentVersion: string }>()
const emit = defineEmits<{ backups: [] }>()
const state = ref<any>(props.status || {}), error = ref(''), readError = ref(''), acknowledged = ref(false)
const visibleError = computed(() => error.value || readError.value)
const sending = ref(false), reading = ref(false)
let disposed = false, generation = 0, timer: ReturnType<typeof setInterval>|undefined
let uncertainRequest: {version: string; previousJobId?: string}|null = null
const busyStates = ['queued','downloading','preparing','installing','restarting','rolling_back','recovery_required']
const busy = computed(() => busyStates.includes(state.value.state))
const labels: Record<string,string> = {idle:'尚未检查',available:'有新版本',up_to_date:'已是最新',check_failed:'检查失败',
  queued:'已排队',downloading:'下载校验中',preparing:'构建中',installing:'安装中',restarting:'验证中',
  rolling_back:'回退中',rolled_back:'已恢复原版本',succeeded:'更新完成',failed:'更新未完成',recovery_required:'需要恢复',unavailable:'当前不可用'}
const label = computed(() => labels[state.value.state] || '正在读取')
const canInstall = computed(() => state.value.enabled && state.value.state === 'available' && state.value.candidate &&
  acknowledged.value && !sending.value && !reading.value && !visibleError.value)
watch(() => state.value.candidate?.manifest_sha256, () => { acknowledged.value = false })
async function refresh() {
  if (disposed || reading.value || sending.value) return
  reading.value = true
  const current = ++generation
  try {
    const response = await api('/updates')
    if (!disposed && current === generation) {
      state.value = response; readError.value = ''
      if (uncertainRequest && response.job?.id && response.job.id !== uncertainRequest.previousJobId &&
          response.job.version === uncertainRequest.version && ['succeeded','failed','rolled_back'].includes(response.state)) {
        error.value = ''; uncertainRequest = null
      }
    }
  } catch (e) {
    if (!disposed && current === generation) readError.value = busy.value ? '服务暂时断开，正在重新读取更新状态。' : e instanceof Error ? e.message : String(e)
  } finally { reading.value = false }
}
async function check() {
  if (!state.value.enabled || sending.value || busy.value) return
  const current = ++generation
  sending.value = true; error.value = ''; readError.value = ''; acknowledged.value = false
  uncertainRequest = null
  try {
    const response = await api('/updates/check', {})
    if (!disposed && current === generation) state.value = response
  } catch (e) { if (!disposed) error.value = e instanceof Error ? e.message : String(e) }
  finally { sending.value = false }
}
async function install() {
  if (!canInstall.value) return
  const candidate = state.value.candidate
  const previousJobId = state.value.job?.id
  const current = ++generation
  sending.value = true; error.value = ''; acknowledged.value = false
  try {
    const response = await api('/updates/install', {version:candidate.version,manifest_sha256:candidate.manifest_sha256,confirm_restart:true})
    if (!disposed && current === generation) state.value = response
  } catch (e) {
    if (!disposed) {
      uncertainRequest = {version: candidate.version, previousJobId}
      error.value = (e instanceof Error ? e.message : String(e)) + ' 请刷新状态确认结果，不要重复提交。'
    }
  } finally { sending.value = false }
}
onMounted(() => { refresh(); timer = setInterval(refresh,4000) })
onUnmounted(() => { disposed = true; ++generation; clearInterval(timer) })
</script>

<template>
  <section class="card ota-updates" aria-labelledby="ota-heading">
    <div class="card-heading"><div><h2 id="ota-heading">GitHub 在线升级</h2><p>检查稳定版本，配套更新原生交换服务与 Web 面板。</p></div><span class="tag" role="status">{{ label }}</span></div>
    <div class="ota-version-row"><div><span>当前安装版本</span><strong class="mono">{{ state.current_version || currentVersion || '—' }}</strong></div><div><span>更新源</span><span class="ota-repository"><Github :size="15" />AAA404 / fm10k-controlpanel-public</span></div></div>
    <p class="body-copy" aria-live="polite">{{ state.message }}</p>
    <p v-if="visibleError" class="ota-error" role="alert">{{ visibleError }}</p>
    <div v-if="state.candidate" class="ota-candidate">
      <strong>可用版本 <span class="mono">{{ state.candidate.version }}</span></strong>
      <a :href="state.candidate.release_url" target="_blank" rel="noopener noreferrer">查看发布说明</a>
    </div>
    <div v-if="state.candidate && !busy" class="ota-confirm">
      <p>安装会重启交换服务，短暂中断数据转发。当前配置、账户和 HTTPS 证书会保留，健康检查失败时自动回退。</p>
      <label><input v-model="acknowledged" type="checkbox" :disabled="sending" />我已安排维护窗口，确认允许重启交换服务</label>
    </div>
    <div class="ota-actions">
      <button class="secondary" :disabled="!state.enabled || sending || reading || busy" @click="check"><RefreshCw :size="15" />检查更新</button>
      <button v-if="state.candidate && !busy" :disabled="!canInstall" @click="install">安装 {{ state.candidate.version }}</button>
      <button class="text-button" :disabled="sending || reading" @click="refresh">刷新状态</button>
      <span v-if="sending || (busy && state.state !== 'recovery_required')" class="ota-progress"><LoaderCircle :size="16" />{{ sending ? '请求中' : label }}</span>
    </div>
    <p v-if="state.job" class="body-copy">更新任务 <span class="mono">{{ state.job.version }}</span> · {{ labels[state.job.state] || state.job.state }}</p>
    <div class="ota-footer"><span>安装新版前，可在配置管理中导出当前配置。</span><button class="text-button" @click="emit('backups')">查看备份中心<ArrowRight :size="15" /></button></div>
  </section>
</template>

<style scoped>
.ota-actions,.ota-candidate { display:flex; align-items:center; flex-wrap:wrap; gap:12px; margin:16px 0; }
.ota-confirm { padding:14px; border:1px solid var(--border,#dce2e8); border-radius:8px; margin-top:14px; }
.ota-confirm p { margin:0 0 12px; line-height:1.6; }
.ota-confirm label { display:flex; align-items:flex-start; gap:8px; line-height:1.5; }
.ota-confirm input { width:auto; margin-top:4px; }
.ota-error { color:#b42318; line-height:1.6; }
.ota-progress { display:inline-flex; align-items:center; gap:6px; }
.ota-candidate a { font-size:13px; }
</style>
