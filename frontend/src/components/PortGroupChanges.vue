<script setup lang="ts">
defineProps<{ changes: {
  epl: number; before_mode: string; after_mode: string; notes: string[];
  ports: {port: number; before: string; after: string; was_active: boolean; active: boolean; enabled_before: boolean; enabled_after: boolean}[];
}[] }>()
const mode = (value: string) => value === 'split' ? '4 × Lane' : '1 × '+value.toUpperCase()
</script>

<template>
  <section v-if="changes?.length" class="group-change-review" aria-label="EPL 与 VLAN 联动变更">
    <h3>EPL 与 VLAN 联动变更</h3>
    <article v-for="change in changes" :key="change.epl" class="port-vlan-plan">
      <h4>EPL {{ change.epl }}：{{ mode(change.before_mode) }} → {{ mode(change.after_mode) }}</h4>
      <table><thead><tr><th scope="col">端口</th><th scope="col">修改前</th><th scope="col">修改后</th></tr></thead><tbody>
        <tr v-for="port in change.ports" :key="port.port"><th scope="row">P{{ port.port }}</th>
          <td>{{ port.was_active ? port.before : '合口占用' }}<small v-if="port.was_active">{{ port.enabled_before ? '管理启用' : '管理关闭' }}</small></td>
          <td>{{ port.active ? port.after : port.was_active && port.before !== '未加入 VLAN' ? '合口占用 · 移除 VLAN 成员' : '合口占用' }}<small v-if="port.active">{{ port.enabled_after ? '管理启用' : '管理关闭' }}</small></td>
        </tr>
      </tbody></table>
      <p v-for="note in change.notes" :key="note" class="footnote">{{ note }}</p>
    </article>
  </section>
</template>
