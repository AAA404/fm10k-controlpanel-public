<script setup lang="ts">
import { ChevronDown } from 'lucide-vue-next'
defineProps<{portId:number; speed:number; original:number; options:number[]; disabled?:boolean}>()
const emit = defineEmits<{'update:speed':[value:number]; save:[]; cancel:[]}>()
</script>

<template>
  <div class="port-rate-editor" role="group" :aria-label="'P'+portId+' 速率调整'" @keydown.esc.stop.prevent="emit('cancel')">
    <label><span class="port-rate-label">速率</span><span class="port-speed-field">
      <select :id="'port-rate-'+portId" :value="speed" class="port-speed-select" :aria-label="'P'+portId+' 端口速率'" :disabled="disabled"
        @change="emit('update:speed',Number(($event.target as HTMLSelectElement).value))">
        <option v-for="rate in options" :key="rate" :value="rate">{{ rate }}G</option>
      </select><ChevronDown class="port-speed-chevron" :size="12" aria-hidden="true" />
    </span></label>
    <div class="port-rate-actions"><button type="button" @click="emit('cancel')">取消</button><button type="button" class="save" :disabled="disabled || speed === original" @click="emit('save')">暂存</button></div>
  </div>
</template>
