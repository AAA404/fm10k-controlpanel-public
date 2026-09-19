<script setup lang="ts">
import { ref, watch } from 'vue'
import { Check, KeyRound, LoaderCircle } from 'lucide-vue-next'
import { api, ApiError, setCsrf } from '../api'
const props = defineProps<{ username: string; disabled?: boolean }>()
const emit = defineEmits<{ updated: [username:string]; expired: [] }>()
const name = ref(props.username), current = ref(''), password = ref(''), confirmation = ref('')
const busy = ref(false), error = ref(''), message = ref('')
watch(() => props.username, value => { name.value = value })
async function save() {
  if (busy.value || props.disabled) return
  error.value = ''; message.value = ''
  if (password.value !== confirmation.value) { error.value = '两次输入的新密码不一致'; return }
  if (name.value === props.username && !password.value) { error.value = '管理员信息没有变化'; return }
  busy.value = true
  try {
    const result = await api('/auth/administrator', { username:name.value,current_password:current.value,
      new_password:password.value || null,confirm_password:confirmation.value || null })
    setCsrf(result.csrf); emit('updated',result.username)
    message.value = '管理员信息已更新，其他登录会话已失效。'
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
    if (e instanceof ApiError && (e.status === 401 || e.code === 'account_write_uncertain')) emit('expired')
  } finally {
    busy.value = false
    current.value = password.value = confirmation.value = ''
  }
}
</script>
<template>
  <section class="card administrator-settings">
    <div class="card-heading"><div><h2>Web 管理员</h2><p>修改管理员用户名或密码，需要验证当前密码。</p></div><KeyRound :size="20" /></div>
    <form @submit.prevent="save">
      <fieldset :disabled="busy || disabled">
        <div class="form-grid">
          <label>管理员用户名<input v-model="name" autocomplete="username" pattern="[a-zA-Z0-9_.\-]{3,64}" minlength="3" maxlength="64" required /></label>
          <label>当前密码<input v-model="current" type="password" autocomplete="current-password" maxlength="256" required /></label>
          <label>新密码<input v-model="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" placeholder="仅改用户名时留空" /></label>
          <label>再次输入新密码<input v-model="confirmation" type="password" autocomplete="new-password" minlength="12" maxlength="256" :required="!!password" /></label>
        </div>
        <p class="footnote">新密码至少 12 位。保存后当前页面使用新会话继续，其他会话需要重新登录。此处只修改 Web 管理员。</p>
        <div v-if="error" class="alert danger" role="alert">{{ error }}</div><div v-if="message" class="alert success" role="status">{{ message }}</div>
        <button class="primary" :disabled="busy || disabled" :aria-busy="busy"><LoaderCircle v-if="busy" :size="16" class="spin" /><Check v-else :size="16" />{{ busy ? '正在更新管理员…' : '保存管理员信息' }}</button>
      </fieldset>
    </form>
  </section>
</template>
