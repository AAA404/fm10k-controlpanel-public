<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { RotateCcw } from 'lucide-vue-next'
import type { FanCurve } from '../types'

const props = defineProps<{
  modelValue: FanCurve
  disabled?: boolean
  temperature?: number|null
  actualPwm?: number|null
}>()
const emit = defineEmits<{ 'update:modelValue': [value: FanCurve] }>()
const svg = ref<SVGSVGElement|null>(null)
const selectedPoint = ref(0), dragging = ref<number|null>(null), feedback = ref('')
const names = ['闲置', '负载', '满速']
const x = (temperature: number) => 54 + (temperature - 10) / 90 * 612
const y = (pwm: number) => 286 - pwm * 2.3
const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, Math.round(value)))
const points = computed(() => [
  { temperature: props.modelValue.idle_temperature_c, pwm: props.modelValue.idle_speed_percent },
  { temperature: props.modelValue.load_temperature_c, pwm: props.modelValue.load_speed_percent },
  { temperature: props.modelValue.critical_temperature_c, pwm: 100 },
])
const current = computed(() => points.value[selectedPoint.value]!)
const line = computed(() => [{ temperature: 10, pwm: points.value[0]!.pwm }, ...points.value, { temperature: 100, pwm: 100 }]
  .map(point => String(x(point.temperature)) + ',' + y(point.pwm)).join(' '))
const coordinateStyle = computed(() => ({
  left: String(Math.max(2, Math.min(68, x(current.value.temperature) / 720 * 100 - 10))) + '%'
}))
function updatePoint(index: number, temperature: number, pwm: number) {
  if (props.disabled || !Number.isFinite(temperature) || !Number.isFinite(pwm)) return
  const f = { ...props.modelValue }
  if (index === 0) {
    f.idle_temperature_c = clamp(temperature, 10, Math.min(80, f.load_temperature_c - 10))
    f.idle_speed_percent = clamp(pwm, 25, f.load_speed_percent)
  } else if (index === 1) {
    f.load_temperature_c = clamp(temperature, Math.max(20, f.idle_temperature_c + 10), Math.min(90, f.critical_temperature_c - 1))
    f.load_speed_percent = clamp(pwm, f.idle_speed_percent, 100)
  } else {
    f.critical_temperature_c = clamp(temperature, Math.max(30, f.load_temperature_c + 1), 100)
  }
  emit('update:modelValue', f)
}
async function enterCoordinate(axis: 'temperature'|'pwm', event: Event) {
  const input = event.target as HTMLInputElement
  const raw = input.valueAsNumber
  if (!Number.isFinite(raw)) {
    input.value = String(current.value[axis])
    feedback.value = '请输入有效坐标。'
    return
  }
  updatePoint(selectedPoint.value, axis === 'temperature' ? raw : current.value.temperature, axis === 'pwm' ? raw : current.value.pwm)
  await nextTick()
  input.value = String(current.value[axis])
  feedback.value = '坐标已暂存；温度递增、负载温度至少高于闲置 10°C，满速点固定 100%。'
}
function move(event: PointerEvent) {
  if (dragging.value === null || props.disabled || !svg.value) return
  const matrix = svg.value.getScreenCTM()
  if (!matrix) return
  const point = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse())
  updatePoint(dragging.value, 10 + (point.x - 54) / 612 * 90, (286 - point.y) / 2.3)
}
function begin(index: number, event: PointerEvent) {
  if (props.disabled || event.button !== 0 || !svg.value) return
  event.preventDefault()
  selectedPoint.value = dragging.value = index
  svg.value.setPointerCapture(event.pointerId)
  move(event)
}
function end(event: PointerEvent) {
  if (svg.value?.hasPointerCapture(event.pointerId)) svg.value.releasePointerCapture(event.pointerId)
  dragging.value = null
}
function keyMove(index: number, event: KeyboardEvent) {
  if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key) || props.disabled) return
  event.preventDefault(); selectedPoint.value = index
  const delta = event.shiftKey ? 5 : 1, point = points.value[index]!
  updatePoint(index, point.temperature + (event.key === 'ArrowRight' ? delta : event.key === 'ArrowLeft' ? -delta : 0),
    point.pwm + (event.key === 'ArrowUp' ? delta : event.key === 'ArrowDown' ? -delta : 0))
}
function restoreDefault() {
  if (props.disabled) return
  emit('update:modelValue', { sensor:'fm10840_core', idle_temperature_c:35, load_temperature_c:70,
    critical_temperature_c:80, idle_speed_percent:50, load_speed_percent:80, hysteresis_c:4, response_time_s:10.9 })
  feedback.value = '默认曲线已暂存，预览并提交后生效。'
}
watch(() => props.disabled, value => { if (value) dragging.value = null })
</script>

<template>
  <section class="card fan-curve-editor">
    <div class="card-heading"><div><h2>硬件风扇曲线</h2><p>拖动折点调整，或选择折点输入坐标。控制源：FM10840 核心温度。</p></div><button class="secondary" :disabled="disabled" @click="restoreDefault"><RotateCcw :size="15" />恢复默认</button></div>
    <div class="curve-tabs" aria-label="选择曲线折点">
      <button v-for="(point,index) in points" :key="index" :class="{ active:selectedPoint === index }" :aria-pressed="selectedPoint === index" @click="selectedPoint = index"><b>{{ index+1 }}</b>{{ names[index] }}<span>{{ point.temperature }}°C / {{ point.pwm }}%</span></button>
    </div>
    <div class="curve-canvas" :class="{ dragging: dragging !== null }">
      <svg ref="svg" viewBox="0 0 720 410" aria-label="可编辑的温度与风扇 PWM 曲线" @pointermove="move" @pointerup="end" @pointercancel="end">
        <g v-for="p in [25,50,75,100]" :key="p"><line x1="54" x2="666" :y1="y(p)" :y2="y(p)" class="grid-line" /><text x="12" :y="y(p)+4">{{ p }}%</text></g>
        <g v-for="t in [10,25,40,55,70,85,100]" :key="t"><text :x="x(t)" y="309" text-anchor="middle">{{ t }}°C</text></g>
        <polygon :points="'54,286 ' + line + ' 666,286'" class="curve-area" />
        <polyline :points="line" class="curve-line" />
        <line :x1="x(current.temperature)" :y1="y(current.pwm)+12" :x2="x(current.temperature)" y2="322" class="curve-guide" />
        <g v-for="(point,index) in points" :key="index">
          <circle :cx="x(point.temperature)" :cy="y(point.pwm)" r="20" class="curve-hit-target" :class="{ selected:selectedPoint === index }" role="slider" :tabindex="disabled ? -1 : 0"
            :aria-label="names[index] + '折点，左右键调温度，上下键调PWM'" :aria-valuenow="point.temperature" :aria-valuemin="10" :aria-valuemax="100" :aria-valuetext="point.temperature + '摄氏度，PWM ' + point.pwm + '%'"
            :aria-disabled="disabled" @pointerdown="begin(index,$event)" @keydown="keyMove(index,$event)" @focus="selectedPoint = index" />
          <circle :cx="x(point.temperature)" :cy="y(point.pwm)" r="7" class="curve-handle" :class="{ selected:selectedPoint === index }" />
          <text :x="x(point.temperature)" :y="y(point.pwm)-18" text-anchor="middle" class="curve-coordinate" :class="{selected:selectedPoint === index}">{{ point.temperature }}° / {{ point.pwm }}%</text>
        </g>
        <circle v-if="temperature != null && actualPwm != null" :cx="x(Math.max(10,Math.min(100,temperature)))" :cy="y(actualPwm)" r="4" class="curve-point" />
      </svg>
      <div class="coordinate-editor" :style="coordinateStyle" :aria-label="names[selectedPoint] + '折点坐标'">
        <strong>{{ names[selectedPoint] }}点坐标</strong>
        <label>温度 °C<input type="number" :value="current.temperature" min="10" max="100" :disabled="disabled" :aria-label="names[selectedPoint] + '点温度'" @change="enterCoordinate('temperature',$event)" /></label>
        <label>PWM %<input type="number" :value="current.pwm" min="25" max="100" :disabled="disabled || selectedPoint === 2" :aria-label="names[selectedPoint] + '点PWM'" @change="enterCoordinate('pwm',$event)" /></label>
      </div>
    </div>
    <div class="chart-legend"><span><i class="dot green"></i>拟配置曲线</span><span><i class="dot blue"></i>当前核心温度 / PWM</span></div>
    <p v-if="feedback" class="curve-feedback" role="status">{{ feedback }}</p>
    <div class="inline-form curve-behaviour"><label>回差（°C）<input type="number" :value="modelValue.hysteresis_c" min="1" max="15" :disabled="disabled" @change="emit('update:modelValue', {...modelValue,hysteresis_c:Number(($event.target as HTMLInputElement).value)})" /></label><label>响应时间<select :value="modelValue.response_time_s" :disabled="disabled" @change="emit('update:modelValue', {...modelValue,response_time_s:Number(($event.target as HTMLSelectElement).value)})"><option v-for="time in [5.45,10.9,21.6,43.7]" :key="time" :value="time">{{ time }} 秒</option></select></label><p class="body-copy">满速点固定 100%，PWM 下限 25%。Atom 温度用于监测；此曲线始终使用交换芯片核心温度。</p></div>
    <p class="footnote">坐标修改先暂存，预览并提交后量化为 LM96163 的 12 点硬件 LUT。关闭页面后硬件温控继续运行。方向键微调，Shift + 方向键每次调整 5。</p>
  </section>
</template>
