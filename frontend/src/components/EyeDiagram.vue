<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, watch } from 'vue'
import { api } from '../api'
import type { EyeScan } from '../types'

const props=defineProps<{port:number; lane:number; mode:string; profile:string; speed:number; disabled?:boolean}>()
const snapshot=ref<EyeScan|null>(null), error=ref(''), pollError=ref(''), busy=ref(false), preset=ref('standard')
const signalSource=ref<'external'|'internal_loopback'>('external')
const tracking=ref(false)
const largeCanvas=ref<HTMLCanvasElement|null>(null), dialog=ref<HTMLDialogElement|null>(null)
const canvas=ref<HTMLCanvasElement|null>(null), point=ref<{x:number;y:number}|null>(null)
const current=computed(()=>snapshot.value?.port===props.port && snapshot.value?.lane===props.lane ? snapshot.value : null)
const active=(scan:EyeScan|null)=>!!scan && ['preparing','running','cancelling'].includes(scan.state)
const needsPoll=(scan:EyeScan|null)=>active(scan) || scan?.state==='reading'
const otherActive=computed(()=>active(snapshot.value) && !current.value)
const state=computed(()=>({preparing:'准备采集',running:'采集中',cancelling:'正在取消',reading:'正在读取结果',complete:'采集完成',cancelled:'已取消',failed:'采集失败'}[current.value?.state || ''] || '待采集'))
const colors=['#182c65','#176a9d','#25bfc1','#dee164','#ee733b','#bb3150']
const plot={left:64,top:42,width:648,height:300}
let generation=0, timer:ReturnType<typeof setTimeout>|undefined, disposed=false
function color(ratio:number, floor:number) {
  const t=ratio<=floor ? 0 : Math.min(1,Math.max(0,(Math.log10(ratio)-Math.log10(floor))/-Math.log10(floor)))
  const i=Math.min(colors.length-2,Math.floor(t*(colors.length-1))), f=t*(colors.length-1)-i
  const rgb=(hex:string)=>[1,3,5].map(n=>parseInt(hex.slice(n,n+2),16))
  const a=rgb(colors[i]), b=rgb(colors[i+1])
  return `rgb(${a.map((v,n)=>Math.round(v+(b[n]-v)*f)).join(',')})`
}
function draw() {
  for(const c of [canvas.value,largeCanvas.value]) if(c && current.value) paint(c,current.value)
}
function paint(c:HTMLCanvasElement,s:EyeScan) {
  const ctx=c.getContext('2d'); if(!ctx) return
  c.width=768; c.height=438
  ctx.fillStyle='#101b2c'; ctx.fillRect(0,0,c.width,c.height)
  ctx.font='14px system-ui'; ctx.fillStyle='#e2edf5'
  ctx.fillText(`RX eye · P${s.port} / L${s.lane} · ${s.speed_mbps/1000}G${s.signal_source==='internal_prbs31_loopback'?' · INTERNAL PRBS31 LOOPBACK':''}${s.source==='simulator'?' · SIMULATION':''}`,plot.left,24)
  const cw=plot.width/(s.x_points-1), ch=plot.height/(s.y_points-1)
  ctx.save(); ctx.beginPath(); ctx.rect(plot.left,plot.top,plot.width,plot.height); ctx.clip()
  ctx.fillStyle='#263343'; ctx.fillRect(plot.left,plot.top,plot.width,plot.height)
  for(let x=0;x<s.errors.length;x++) for(let y=0;y<s.y_points;y++) {
    ctx.fillStyle=color(s.errors[x][y]/s.dwell_bits,1/s.dwell_bits)
    ctx.fillRect(plot.left+x*cw-cw/2,plot.top+plot.height-y*ch-ch/2,cw+0.5,ch+0.5)
  }
  ctx.strokeStyle='#d5e6ec55'; ctx.setLineDash([3,4]); ctx.beginPath()
  ctx.moveTo(plot.left+plot.width/2,plot.top);ctx.lineTo(plot.left+plot.width/2,plot.top+plot.height)
  const centerY=plot.top+plot.height-(128/s.y_step)*ch
  ctx.moveTo(plot.left,centerY);ctx.lineTo(plot.left+plot.width,centerY);ctx.stroke();ctx.restore()
  ctx.setLineDash([]);ctx.strokeStyle='#738394';ctx.strokeRect(plot.left,plot.top,plot.width,plot.height)
  ctx.font='12px system-ui';ctx.fillStyle='#adbdcd';ctx.textAlign='center'
  for(const x of [-1,-0.5,0,0.5,1]) ctx.fillText(String(x),plot.left+(x+1)*plot.width/2,plot.top+plot.height+19)
  ctx.fillText('Phase (UI)',plot.left+plot.width/2,plot.top+plot.height+37)
  ctx.textAlign='right'
  for(const y of [-128,-64,0,64,128-s.y_step]) {
    const py=plot.top+plot.height-((y+128)/s.y_step)*ch
    ctx.fillText(String(y),plot.left-10,py+4)
  }
  ctx.save();ctx.translate(17,plot.top+plot.height/2);ctx.rotate(-Math.PI/2);ctx.textAlign='center';ctx.fillText('Threshold (DAC)',0,0);ctx.restore()
  const barX=plot.left+315, barY=396, barW=250
  for(let i=0;i<barW;i++){ctx.fillStyle=color(10**(-Math.log10(s.dwell_bits)*(1-i/barW)),1/s.dwell_bits);ctx.fillRect(barX+i,barY,1,9)}
  ctx.font='11px system-ui';ctx.fillStyle='#adbdcd';ctx.textAlign='left'
  ctx.fillText(`XOR error ratio · ${s.dwell_bits.toExponential(0)} bits/point`,plot.left,barY+8)
  ctx.fillText(`0 / ≤ 1e-${Math.log10(s.dwell_bits)}`,barX,barY+26);ctx.textAlign='right';ctx.fillText('1',barX+barW,barY+26)
  ctx.textAlign='left';ctx.fillText(new Date(s.started_at*1000).toLocaleString('zh-CN',{hour12:false}),plot.left,430)
  ctx.textAlign='right';ctx.fillText(`${s.state.toUpperCase()} · ${s.columns_done}/${s.x_points} columns · ${s.restored?'restored':'restore pending'}`,plot.left+plot.width,430)
}
const pointText=computed(()=>{
  const p=point.value,s=current.value
  if(!p || !s || !s.errors[p.x]) return '移动到图上查看采样点；灰色区域尚未采集。'
  const n=s.errors[p.x][p.y]
  return `${((p.x-s.x_resolution)/s.x_resolution).toFixed(3)} UI · ${-128+p.y*s.y_step} DAC · ${n.toLocaleString()} / ${s.dwell_bits.toLocaleString()} · ${n===0?'未计到错误':(n/s.dwell_bits).toExponential(2)}`
})
function inspect(event:MouseEvent) {
  const c=event.currentTarget as HTMLCanvasElement,s=current.value;if(!c || !s) return
  const r=c.getBoundingClientRect(), px=(event.clientX-r.left)*c.width/r.width, py=(event.clientY-r.top)*c.height/r.height
  if(px<plot.left || px>plot.left+plot.width || py<plot.top || py>plot.top+plot.height){point.value=null;return}
  point.value={x:Math.round((px-plot.left)/plot.width*(s.x_points-1)),y:Math.round((plot.top+plot.height-py)/plot.height*(s.y_points-1))}
}
function keyboard(event:KeyboardEvent) {
  const s=current.value;if(!s || !['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) return
  event.preventDefault();const p=point.value || {x:s.x_resolution,y:128/s.y_step}
  point.value={x:Math.max(0,Math.min(s.x_points-1,p.x+(event.key==='ArrowLeft'?-1:event.key==='ArrowRight'?1:0))),
    y:Math.max(0,Math.min(s.y_points-1,p.y+(event.key==='ArrowDown'?-1:event.key==='ArrowUp'?1:0)))}
}
async function poll(token:number) {
  try {
    const s=await api<EyeScan>('/optics/eye')
    if(disposed || token!==generation) return
    snapshot.value=s;pollError.value=''
    await nextTick();draw()
  } catch(e) {if(!disposed && token===generation) pollError.value=e instanceof Error?e.message:String(e)}
  finally {if(!disposed && token===generation && needsPoll(snapshot.value)) timer=setTimeout(()=>poll(token),1000)}
}
function loadExisting() {
  tracking.value=true
  if(timer)clearTimeout(timer)
  void poll(++generation)
}
async function start() {
  if(props.disabled || busy.value || active(snapshot.value)) return
  tracking.value=true
  const token=++generation
  if(timer)clearTimeout(timer)
  const options=preset.value==='quick'?{x_resolution:16,y_step:4,dwell_bits:100000}:
    preset.value==='dense'?{x_resolution:64,y_step:1,dwell_bits:10000000}:{x_resolution:64,y_step:2,dwell_bits:1000000}
  busy.value=true;error.value=''
  try {
    const s=await api<EyeScan>(`/optics/ports/${props.port}/eye`,{lane:props.lane,signal_source:signalSource.value,request_id:crypto.randomUUID().replaceAll('-',''),...options})
    if(token!==generation || disposed) return
    snapshot.value=s;point.value=null;await nextTick();draw()
  } catch(e){if(token===generation) error.value=e instanceof Error?e.message:String(e)}
  finally{if(token===generation){busy.value=false;timer=setTimeout(()=>poll(token),500)}}
}
async function cancel() {
  const s=current.value;if(!s?.id)return
  const token=++generation;if(timer)clearTimeout(timer)
  busy.value=true
  try {const value=await api<EyeScan>(`/optics/eyes/${s.id}/cancel`,{});if(token===generation)snapshot.value=value}
  catch(e){if(token===generation)error.value=e instanceof Error?e.message:String(e)}
  finally{if(token===generation){busy.value=false;timer=setTimeout(()=>poll(token),500)}}
}
function expand() {dialog.value?.showModal();draw();largeCanvas.value?.focus()}
function save(blob:Blob,name:string) {const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
async function download(format:string) {
  const s=current.value;if(!s?.id)return
  try {
    if(format==='png') {draw();canvas.value?.toBlob(blob=>{if(blob)save(blob,`eye-P${s.port}-L${s.lane}-${s.id}.png`)});return}
    const response=await fetch(`/api/v1/optics/eyes/${s.id}/export?format=${format}`,{credentials:'same-origin'})
    if(!response.ok){const value=await response.json();throw new Error(value.detail || '导出失败')}
    save(await response.blob(),`eye-P${s.port}-L${s.lane}-${s.id}.${format}`)
  } catch(e){error.value=e instanceof Error?e.message:String(e)}
}
watch(()=>[props.port,props.lane,props.mode,props.profile],()=>{
  if(timer)clearTimeout(timer);snapshot.value=null;error.value='';pollError.value='';busy.value=false;point.value=null;signalSource.value='external'
  const token=++generation
  // Opening a panel does not attach to an old native acquisition. Only an
  // explicit start/read action opts this inspector into tracking results.
  if(tracking.value) void poll(token)
},{immediate:true})
onUnmounted(()=>{disposed=true;++generation;if(timer)clearTimeout(timer)})
</script>

<template>
  <section class="eye-diagram" aria-label="RX 二维眼图">
    <div class="optics-section-heading"><h3>RX 二维眼图</h3><span class="tag" :class="{amber:current?.state==='failed'}">{{ state }}</span></div>
    <p class="optics-note">采集当前 Lane 的电气侧接收眼图。采集时暂时暂停该 Lane 的均衡，可能影响链路；结束后恢复。</p>
    <p class="optics-note">此板需所有数据口 Link Down 后离线采集。采集期间暂停各 Lane 的自动均衡，结束后校验并恢复。</p>
    <div class="eye-controls">
      <select v-model="signalSource" aria-label="眼图信号来源" :disabled="busy || active(current)">
        <option value="external">外部接收信号</option><option value="internal_loopback">内部 PRBS31 回环自检</option>
      </select>
      <select v-model="preset" aria-label="眼图采样精度" :disabled="busy || active(current)">
        <option value="quick">快速 · 33 × 64</option><option value="standard">标准 · 129 × 128</option><option value="dense">精细 · 129 × 256</option>
      </select>
      <button type="button" class="secondary" :disabled="disabled || busy || active(snapshot)" @click="start">{{ busy && !active(current)?'正在启动':'开始采集' }}</button>
      <button type="button" class="text-button" :disabled="busy || needsPoll(snapshot)" @click="loadExisting">读取上次结果</button>
      <button v-if="active(current)" type="button" class="text-button" :disabled="busy || current?.state==='cancelling'" @click="cancel">取消</button>
    </div>
    <p v-if="signalSource==='internal_loopback'" class="optics-note">仅用于 Link Down 的端口。临时切换本 Lane 的发送码型与回环，结束后恢复；自检结果不代表光模块或光纤链路质量。</p>
    <p v-if="otherActive" class="optics-state-note">P{{ snapshot?.port }} · L{{ snapshot?.lane }} 正在采集。</p>
    <p v-if="error || pollError" class="optics-state-note" role="alert">{{ error || pollError }}</p>
    <template v-if="current?.id">
      <p class="optics-note">采集开始于 {{ new Date(current.started_at*1000).toLocaleString('zh-CN',{hour12:false}) }}<span v-if="current.state==='reading'"> · 正在读取已有结果，未启动新采样</span></p>
      <p v-if="current.speed_mbps!==speed*1000" class="optics-state-note">此结果采于 {{ current.speed_mbps/1000 }}G；当前 Lane 速率为 {{ speed }}G。</p>
      <p class="eye-progress" aria-live="polite">{{ current.source==='simulator'?'模拟数据 · ':'' }}{{ current.signal_source==='internal_prbs31_loopback'?'内部 PRBS31 回环 · ':'外部信号 · ' }}{{ current.columns_done }} / {{ current.x_points }} 列 · {{ (current.elapsed_ms/1000).toFixed(1) }} 秒<span v-if="current.restored"> · 状态已恢复</span></p>
      <p v-if="current.temporary_master" class="optics-note">离线采集。{{ current.restored?'采集前状态已恢复。':'结束时恢复采集前状态。' }}</p>
      <progress v-if="active(current)" :value="current.columns_done" :max="current.x_points" aria-label="眼图采集进度" />
      <p v-if="current.message" class="optics-state-note">{{ current.message }}</p>
      <canvas ref="canvas" class="eye-canvas" role="img" tabindex="0" :aria-label="`P${port} Lane ${lane} 的接收眼图，${current.columns_done} 列已采集，方向键查看采样点`" @mousemove="inspect" @mouseleave="point=null" @keydown="keyboard" />
      <p class="eye-point">{{ pointText }}</p>
      <dl v-if="current.metrics" class="optics-values">
        <div><dt>眼宽 / 眼高（阈值 10⁻⁴）</dt><dd>{{ current.metrics.width_clipped?'≥ ':'' }}{{ current.metrics.eye_width_ui?.toFixed(3) ?? '—' }} UI / {{ current.metrics.height_clipped?'≥ ':'' }}{{ current.metrics.eye_height_dac ?? '—' }} DAC</dd></div>
        <div><dt>中心错误计数</dt><dd>{{ current.metrics.center_errors }} / {{ current.dwell_bits.toLocaleString() }}</dd></div>
      </dl>
      <p v-if="current.metrics && current.metrics.eye_width_ui===null" class="optics-state-note">中心错误比高于 10⁻⁴，当前阈值下无可报告的连续开口。</p>
      <div v-if="current.errors.length" class="eye-downloads"><button class="text-button" @click="expand">放大眼图</button><button class="text-button" @click="download('png')">导出 PNG</button><button class="text-button" @click="download('csv')">导出 CSV</button><button class="text-button" @click="download('json')">导出 JSON</button></div>
      <p class="optics-note">颜色表示偏移采样器与主采样器的 XOR 错误比。0 次错误的检测分辨率为 {{ (1/current.dwell_bits).toExponential(0) }}；不是 PRBS BER 认证。纵轴为原始 DAC 刻度。</p>
    </template>
    <p v-else class="optics-note">点击“开始采集”生成实测矩阵。TX 眼图需要外部测量设备。</p>
    <dialog v-if="current?.id" ref="dialog" class="eye-dialog" aria-label="放大的接收眼图">
      <div class="optics-section-heading"><h3>P{{ port }} · L{{ lane }} 接收眼图</h3><button class="text-button" @click="dialog?.close()">关闭</button></div>
      <canvas ref="largeCanvas" class="eye-canvas" tabindex="0" role="img" aria-label="放大的二维接收眼图，方向键查看采样点" @mousemove="inspect" @mouseleave="point=null" @keydown="keyboard" />
      <p class="eye-point">{{ pointText }}</p>
    </dialog>
  </section>
</template>
