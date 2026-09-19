<script setup lang="ts">
import { ArrowRight, Github } from 'lucide-vue-next'
defineProps<{ status: any; currentVersion: string }>()
const emit = defineEmits<{ backups: [] }>()
</script>

<template>
  <section class="card ota-updates" aria-labelledby="ota-heading">
    <div class="card-heading"><div><h2 id="ota-heading">GitHub 在线升级</h2><p>升级入口已预留，待项目公开后接入。</p></div><span class="tag">后续版本</span></div>
    <div class="ota-version-row"><div><span>当前安装版本</span><strong class="mono">{{ status.current_version || currentVersion || '—' }}</strong></div><div><span>计划更新源</span><span class="ota-repository"><Github :size="15" />AAA404 / fm10k-controlpanel-public</span></div></div>
    <p class="body-copy">当前版本通过 Debian 安装包更新。在线版本检查、下载、安装和自动回退将在仓库公开后启用。</p>
    <button class="secondary" disabled>在线升级尚未启用</button>
    <div class="ota-footer"><span>安装新版前，可在配置管理中导出当前配置。</span><button class="text-button" @click="emit('backups')">查看备份中心<ArrowRight :size="15" /></button></div>
  </section>
</template>
