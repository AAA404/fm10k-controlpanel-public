<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Maximize2, Minimize2, MoveDiagonal2, Settings2 } from 'lucide-vue-next'

const props = defineProps<{ portId:number; epl:number; module:number; activeTab:number; editingRate?:boolean; blocked?:boolean }>()
const emit = defineEmits<{ close:[]; settings:[] }>()
type ViewMode = 'inline'|'window'|'maximized'
const mode = ref<ViewMode>('inline')
const dialog = ref<HTMLDialogElement|null>(null), content = ref<HTMLElement|null>(null)
const dialogHost = ref<HTMLElement|null>(null)
const expandButton = ref<HTMLButtonElement|null>(null), returnButton = ref<HTMLButtonElement|null>(null)
const viewport = ref({width:window.innerWidth,height:window.innerHeight})
const preferredSize = ref<{width:number;height:number}|null>(null)
const floating = computed(() => mode.value !== 'inline')
const narrow = computed(() => viewport.value.width <= 700)
const limits = computed(() => ({width:Math.max(0,viewport.value.width-(narrow.value?0:32)),height:Math.max(0,viewport.value.height-(narrow.value?0:32))}))
const size = computed(() => {
  const max = limits.value
  if (narrow.value || mode.value === 'maximized') return max
  const preferred = preferredSize.value || {width:Math.min(1100,viewport.value.width-48),height:viewport.value.height*.85}
  return {width:Math.min(max.width,Math.max(Math.min(640,max.width),preferred.width)),height:Math.min(max.height,Math.max(Math.min(420,max.height),preferred.height))}
})
const scrollPositions = new Map<string,number>()
let disposed = false, previousOverflow:string|undefined, previousPaddingRight:string|undefined
let drag:{target:HTMLElement;pointerId:number;x:number;y:number;width:number;height:number}|null = null
const body = () => content.value?.querySelector<HTMLElement>('.port-detail-body')
const scrollKey = (tab = props.activeTab) => [props.portId,mode.value,tab].join(':')
function rememberScroll(tab = props.activeTab) { scrollPositions.set(scrollKey(tab),body()?.scrollTop || 0) }
function restoreScroll() { const element=body();if(element)element.scrollTop=scrollPositions.get(scrollKey()) || 0 }
function unlockPage() {
  if (previousOverflow === undefined) return
  document.documentElement.style.overflow=previousOverflow
  if(previousPaddingRight!==undefined)document.body.style.paddingRight=previousPaddingRight
  previousOverflow=undefined
  previousPaddingRight=undefined
}
function stopResize() {
  const previous=drag;drag=null
  if(previous?.target.hasPointerCapture(previous.pointerId))previous.target.releasePointerCapture(previous.pointerId)
}
async function enlarge() {
  if (props.blocked || floating.value) return
  rememberScroll();mode.value='window'
  await nextTick()
  if(disposed || !floating.value || props.blocked || !dialog.value)return
  previousOverflow=document.documentElement.style.overflow
  previousPaddingRight=document.body.style.paddingRight
  const scrollbarWidth=window.innerWidth-document.documentElement.clientWidth
  if(scrollbarWidth>0)document.body.style.paddingRight=(parseFloat(getComputedStyle(document.body).paddingRight)+scrollbarWidth)+'px'
  document.documentElement.style.overflow='hidden'
  dialog.value.showModal()
  restoreScroll()
  returnButton.value?.focus({preventScroll:true})
}
async function returnToCard(focus = true) {
  if(!floating.value)return
  rememberScroll();stopResize()
  mode.value='inline'
  dialog.value?.close()
  unlockPage()
  await nextTick()
  if(disposed)return
  restoreScroll()
  if(focus)expandButton.value?.focus({preventScroll:true})
}
async function toggleMaximize() {
  rememberScroll();stopResize()
  mode.value=mode.value==='maximized'?'window':'maximized'
  await nextTick();restoreScroll()
}
function resizeStart(event:PointerEvent) {
  if(event.button!==0 || mode.value!=='window' || narrow.value)return
  event.preventDefault()
  const target=event.currentTarget as HTMLElement
  drag={target,pointerId:event.pointerId,x:event.clientX,y:event.clientY,...size.value}
  target.setPointerCapture(event.pointerId)
}
function resizeMove(event:PointerEvent) {
  if(!drag || drag.pointerId!==event.pointerId)return
  // The dialog stays centered, so both edges move by half of the size change.
  const max=limits.value
  preferredSize.value={width:Math.min(max.width,Math.max(Math.min(640,max.width),drag.width+2*(event.clientX-drag.x))),
    height:Math.min(max.height,Math.max(Math.min(420,max.height),drag.height+2*(event.clientY-drag.y)))}
}
function resizeKey(event:KeyboardEvent) {
  const step=event.shiftKey?40:20
  const delta:Record<string,[number,number]>={ArrowLeft:[-step,0],ArrowRight:[step,0],ArrowUp:[0,-step],ArrowDown:[0,step]}
  const change=delta[event.key]
  if(!change || narrow.value || mode.value!=='window')return
  event.preventDefault();event.stopPropagation()
  const max=limits.value
  preferredSize.value={width:Math.min(max.width,Math.max(Math.min(640,max.width),size.value.width+change[0])),
    height:Math.min(max.height,Math.max(Math.min(420,max.height),size.value.height+change[1]))}
}
function escapeDetail(event:KeyboardEvent) {
  const owner=(event.target as Element).closest('dialog')
  // A nested eye dialog owns its Escape; the rate editor stops its own event.
  if(event.defaultPrevented || (owner && owner!==dialog.value))return
  event.preventDefault();event.stopPropagation()
  if(floating.value)void returnToCard()
  else emit('close')
}
function cancelDialog(event:Event) {
  if(event.target!==dialog.value)return
  event.preventDefault();void returnToCard()
}
function closedDialog(event:Event) {
  if(event.target===dialog.value && !dialog.value?.open)void returnToCard()
}
function trapFocus(event:KeyboardEvent) {
  if((event.target as Element).closest('dialog')!==dialog.value)return
  const controls=[...dialog.value!.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), summary, [tabindex="0"]')]
    .filter(element=>element.getClientRects().length>0 && !element.closest('[inert]'))
  const first=controls[0],last=controls.at(-1)
  if(document.activeElement===dialog.value || document.activeElement===(event.shiftKey?first:last)){
    event.preventDefault();(event.shiftKey?last:first)?.focus()
  }
}
function resizedViewport() {stopResize();viewport.value={width:window.innerWidth,height:window.innerHeight}}
watch(() => props.activeTab,async (_tab,previous) => {rememberScroll(previous);await nextTick();restoreScroll()})
watch(() => props.portId,async () => {scrollPositions.clear();await nextTick();restoreScroll()})
watch(() => props.blocked,blocked => {
  if(!blocked)return
  content.value?.querySelectorAll<HTMLDialogElement>('dialog[open]').forEach(child=>child.close())
  void returnToCard(false)
})
onMounted(() => window.addEventListener('resize',resizedViewport))
onBeforeUnmount(() => {disposed=true;stopResize();dialog.value?.close();unlockPage();window.removeEventListener('resize',resizedViewport)})
</script>

<template>
  <div class="port-inspector-host">
    <p v-if="floating" class="port-inspector-placeholder" aria-hidden="true">P{{ portId }} 详情已放大</p>
    <Teleport to="body">
      <dialog ref="dialog" class="port-inspector-dialog" :class="{maximized:mode==='maximized'}" :style="{width:size.width+'px',height:size.height+'px'}"
        tabindex="-1" :aria-labelledby="'port-inspector-title-'+epl" @cancel="cancelDialog" @close="closedDialog" @keydown.tab="trapFocus">
        <div ref="dialogHost" class="port-inspector-dialog-content"></div>
        <footer class="port-inspector-footer">
          <span>{{ narrow ? '全屏详情' : mode === 'maximized' ? '最大化' : Math.round(size.width)+' × '+Math.round(size.height) }}</span>
          <button v-if="!narrow && mode==='window'" type="button" class="port-inspector-resize" aria-label="调整端口详情窗口大小，方向键调整" title="拖动或使用方向键调整大小"
            @pointerdown="resizeStart" @pointermove="resizeMove" @pointerup="stopResize" @pointercancel="stopResize" @lostpointercapture="stopResize" @keydown="resizeKey"><MoveDiagonal2 :size="16" />调整大小</button>
        </footer>
      </dialog>
    </Teleport>
    <Teleport :to="dialogHost || 'body'" :disabled="!floating">
      <div :id="'port-details-'+epl" ref="content" class="expanded-port-detail" :class="{'port-inspector-floating':floating}" @keydown.esc="escapeDetail">
        <div class="port-detail-heading" :class="{'editing-rate':editingRate}">
          <h2 :id="'port-inspector-title-'+epl" :aria-label="'P'+portId+' · 端口详情'"><small v-if="floating">OBT {{ module }} / EPL {{ epl }}</small>P{{ portId }}</h2>
          <slot name="actions" />
          <button v-if="!floating" :id="'port-detail-expand-'+portId" ref="expandButton" type="button" class="port-detail-expand" aria-label="放大端口详情" title="放大端口详情" :disabled="blocked" @click="enlarge"><Maximize2 :size="14" /></button>
          <div v-else class="port-inspector-actions">
            <button type="button" class="port-inspector-settings" :aria-label="'设置端口 P'+portId" aria-haspopup="dialog" @click="emit('settings')"><Settings2 :size="14" />设置</button>
            <button v-if="!narrow" type="button" :aria-label="mode==='maximized'?'还原窗口大小':'最大化端口详情'" @click="toggleMaximize"><Minimize2 v-if="mode==='maximized'" :size="14" /><Maximize2 v-else :size="14" />{{ mode==='maximized'?'还原大小':'最大化' }}</button>
            <button ref="returnButton" type="button" class="port-inspector-return" @click="returnToCard()"><Minimize2 :size="14" />回到卡片</button>
          </div>
        </div>
        <div v-if="floating" class="port-inspector-navigation"><slot name="navigation" /></div>
        <slot />
      </div>
    </Teleport>
  </div>
</template>
