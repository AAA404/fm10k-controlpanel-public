<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { Settings2, X } from 'lucide-vue-next'
import type { Configuration, PortGroup } from '../types'
import { changeGroupMode, inactiveReferences, vlanDescription, vlanMembers } from '../portModes'

const props = defineProps<{ configuration: Configuration; appliedConfiguration: Configuration; portId: number; disabled?: boolean }>()
const emit = defineEmits<{ close: []; 'update:portId': [port: number] }>()
const dialog = ref<HTMLDialogElement|null>(null)
const epls = [0,1,2,5,6,7]
const base = (group: PortGroup) => epls.indexOf(group.epl)*4+1
const group = computed(() => props.configuration.groups.find(group => props.portId >= base(group) && props.portId < base(group)+4)!)
const module = computed(() => epls.indexOf(group.value.epl) < 3 ? 1 : 2)
const selected = computed(() => props.configuration.ports[props.portId]!)
const activeSlot = computed(() => group.value.mode === 'split' || props.portId === base(group.value))
const appliedGroup = computed(() => props.appliedConfiguration.groups.find(candidate => candidate.epl === group.value.epl)!)
const restoring = computed(() => group.value.mode === 'split' && appliedGroup.value.mode !== 'split')
const savedVlans = computed(() => group.value.split_vlan_backup || (restoring.value ? appliedGroup.value.split_vlan_backup : null))
const commonVlans = computed(() => savedVlans.value?.length === 4 ? vlanMembers(savedVlans.value[0]!).filter(vid => savedVlans.value!.every(port => vlanMembers(port).includes(vid))) : [])
const missingVlans = computed(() => savedVlans.value ? [...new Set(savedVlans.value.flatMap(vlanMembers))].filter(vid => !props.configuration.vlans.some(vlan => vlan.id === vid)).sort((a,b) => a-b) : [])
const blockers = computed(() => inactiveReferences(props.configuration,group.value))

function setMode(event: Event) {
  if (props.disabled) return
  const mode = (event.target as HTMLSelectElement).value as PortGroup['mode']
  changeGroupMode(props.configuration,group.value,mode)
}
function tagged(event: Event) {
  const value = (event.target as HTMLInputElement).value.trim()
  selected.value.tagged_vlans = value ? value.split(/[,，\s]+/).map(Number) : []
}
function disableModule() {
  if (props.disabled) return
  for (const candidate of props.configuration.groups.filter(group => (epls.indexOf(group.epl) < 3 ? 1 : 2) === module.value))
    for (const lane of [0,1,2,3]) props.configuration.ports[base(candidate)+lane]!.enabled = false
}
function close() { dialog.value?.close() }
function trapFocus(event: KeyboardEvent) {
  const controls = [...dialog.value!.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]')]
  const target = event.shiftKey ? controls.at(-1) : controls[0]
  if (document.activeElement === dialog.value || document.activeElement === (event.shiftKey ? controls[0] : controls.at(-1))) {
    event.preventDefault()
    target?.focus()
  }
}
function backdropClick(event: MouseEvent) {
  if (event.target !== dialog.value) return
  const bounds = dialog.value!.getBoundingClientRect()
  if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) close()
}
onMounted(() => { dialog.value?.showModal(); dialog.value?.focus() })
onBeforeUnmount(() => dialog.value?.close())
</script>

<template>
  <dialog ref="dialog" class="modal port-settings-modal" tabindex="-1" aria-labelledby="port-settings-title" aria-describedby="port-settings-help"
    @cancel.prevent="close" @close="emit('close')" @click="backdropClick" @keydown.tab="trapFocus">
    <div class="card-heading">
      <div><p class="eyebrow">OBT {{ module }} / EPL {{ group.epl }}</p><h2 id="port-settings-title"><Settings2 :size="18" /> P{{ portId }} · 端口设置</h2></div>
      <button class="icon-button" aria-label="关闭端口设置" @click="close"><X :size="20" /></button>
    </div>
    <div class="modal-scroll">
      <p id="port-settings-help" class="body-copy">修改先保存为页面草稿，完成后通过页面底部的“预览并校验”统一提交。</p>
      <label class="port-settings-selector">配置端口<select aria-label="配置端口" :value="portId" @change="emit('update:portId', Number(($event.target as HTMLSelectElement).value))"><option v-for="lane in [0,1,2,3]" :key="lane" :value="base(group)+lane">P{{ base(group)+lane }} / Lane {{ lane }}</option></select></label>
      <fieldset :disabled="disabled">
        <section class="port-detail-section">
          <h3>EPL 模式</h3>
          <div class="inline-form"><label>端口组模式<select aria-label="端口组模式" :value="group.mode" @change="setMode"><option value="100g">1 × 100G</option><option value="40g">1 × 40G</option><option value="split">4 × Lane（10G / 25G）</option></select></label><template v-if="group.mode === 'split'"><label v-for="lane in [0,1,2,3]" :key="lane">P{{ base(group)+lane }} / Lane {{ lane }}<select v-model.number="group.lane_speeds[lane]"><option :value="10">10G</option><option :value="25">25G</option></select></label></template></div>
          <p class="footnote">合口默认使用四口共同的 VLAN，并移除子口成员；再次拆分时恢复合并前各口的 VLAN 和启用状态。所有调整会进入提交预览。</p>
          <div v-if="savedVlans" class="port-vlan-plan" aria-label="EPL VLAN 调整">
            <h4>{{ restoring ? '恢复拆分口 VLAN' : '合口与拆分恢复记录' }}</h4>
            <p v-if="!restoring && commonVlans.length">共同 VLAN：{{ commonVlans.join(', ') }}。Native / Tagged 方式沿用主口；下表显示当前草稿。</p>
            <p v-else-if="!restoring" class="warning">四口没有共同 VLAN，默认沿用 P{{ base(group) }} 的 VLAN；其他子口成员将移除并保存，拆分时恢复。</p>
            <p v-if="missingVlans.length" class="warning">原 VLAN {{ missingVlans.join(', ') }} 已删除，恢复时跳过；没有剩余 VLAN 的端口保持关闭。</p>
            <table><thead><tr><th>端口</th><th>合并前</th><th>当前草稿</th></tr></thead><tbody><tr v-for="(port,lane) in savedVlans" :key="lane"><th>P{{ base(group)+lane }}</th><td>{{ vlanDescription(port) }}<small> · {{ port.enabled ? '启用' : '关闭' }}</small></td><td>{{ group.mode !== 'split' && lane > 0 ? '合口占用 · 不参与 VLAN' : vlanDescription(configuration.ports[base(group)+lane]!) }}</td></tr></tbody></table>
            <p class="footnote">提交并确认后，恢复记录随配置保存和备份，刷新、重新登录或重启后仍可恢复。</p>
          </div>
          <p v-else-if="restoring" class="footnote">此 EPL 尚无拆分恢复记录。新子口默认关闭，请选择 VLAN 后启用。</p>
          <div v-if="blockers.length" class="alert warning"><strong>以下子口仍有其他引用，需要调整后提交：</strong><ul><li v-for="blocker in blockers" :key="blocker">{{ blocker }}</li></ul></div>
        </section>
        <section class="port-detail-section"><h3>端口与 VLAN</h3><div v-if="!activeSlot" class="alert warning">此槽位在草稿中被合口占用；清理依赖或拆分后再启用。</div><div class="form-grid">
          <label>用户名称<input v-model="selected.name" maxlength="64" /></label><label class="check"><input v-model="selected.enabled" type="checkbox" :disabled="!activeSlot && !selected.enabled" />管理启用 / 光发射启用</label>
          <label>接口 MTU<input v-model.number="selected.mtu" type="number" min="1514" max="9216" /></label>
          <label>VLAN 模式<select v-model="selected.vlan_mode" :disabled="!activeSlot" aria-label="VLAN 模式"><option value="access">Access</option><option value="trunk">Trunk</option></select></label>
          <label>PVID / Native VLAN<select v-model="selected.pvid" :disabled="!activeSlot" aria-label="PVID / Native VLAN"><option :value="null">未配置</option><option v-for="vlan in configuration.vlans" :key="vlan.id" :value="vlan.id">{{ vlan.id }} · {{ vlan.name }}</option></select></label>
          <label>Tagged VLAN<input :value="selected.tagged_vlans.join(',')" :disabled="!activeSlot || selected.vlan_mode !== 'trunk'" placeholder="10,20" @change="tagged" /></label>
          <label class="check"><input v-model="selected.ingress_filtering" type="checkbox" />入口 VLAN 过滤</label>
        </div></section>
        <section class="port-detail-section"><h3>二层协议</h3><div class="form-grid">
          <label class="check"><input v-model="selected.lldp" type="checkbox" />LLDP 收发</label><label class="check"><input v-model="selected.edge" type="checkbox" />RSTP 边缘端口</label><label class="check"><input v-model="selected.bpdu_guard" type="checkbox" />BPDU 保护</label><label class="check"><input v-model="selected.direct_receiver" type="checkbox" />明确为直连组播接收器</label>
          <label>RSTP 路径开销（0 自动）<input v-model.number="selected.path_cost" type="number" min="0" max="200000000" /></label><label>RSTP 端口优先级<input v-model.number="selected.port_priority" type="number" min="0" max="240" step="16" /></label>
        </div></section>
        <section class="port-detail-section"><h3>限速与风暴抑制</h3><p class="footnote">单位 kbps；0 表示关闭。入口及风暴抑制非零值至少 22000，全卡共享 16 个控制器。</p><div class="form-grid"><label>入方向限速<input v-model.number="selected.ingress_kbps" type="number" min="0" /></label><label>出方向限速<input v-model.number="selected.egress_kbps" type="number" min="0" /></label><label>广播风暴抑制<input v-model.number="selected.storm.broadcast_kbps" type="number" min="0" /></label><label>组播风暴抑制<input v-model.number="selected.storm.multicast_kbps" type="number" min="0" /></label><label>未知单播风暴抑制<input v-model.number="selected.storm.unknown_unicast_kbps" type="number" min="0" /></label></div></section>
        <section class="port-detail-section"><h3>OBT {{ module }} 模块操作</h3><button class="secondary" @click="disableModule">关闭此 OBT 的所有端口（暂存）</button></section>
      </fieldset>
    </div>
    <div class="modal-actions"><span>{{ disabled ? '当前设置只读' : '关闭窗口后保留草稿' }}</span><button class="primary" @click="close">完成设置</button></div>
  </dialog>
</template>
