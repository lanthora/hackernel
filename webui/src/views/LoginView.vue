<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../lib/api'
import { loadSession } from '../lib/session'
const route = useRoute(),
  router = useRouter()
const username = ref(''),
  password = ref(''),
  busy = ref(false)
const error = ref(route.query.unavailable ? '无法连接管理服务，请确认服务正常后重试。' : '')
async function login() {
  busy.value = true
  error.value = ''
  try {
    await api('/auth/login', { username: username.value, password: password.value })
    await loadSession()
    const target = String(route.query.redirect || '/overview')
    await router.replace(
      /^\/(overview|events|policies|settings|users)(\?|$)/.test(target) ? target : '/overview'
    )
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
</script>
<template>
  <main class="login-page">
    <section class="login-intro">
      <h1>HIDS</h1>
      <p>主机入侵检测系统</p>
      <p>查看安全事件，管理进程、文件和网络防护。</p>
      <span class="subtle">Linux 主机管理</span>
    </section>
    <section class="login-card">
      <p class="eyebrow">欢迎使用 HIDS</p>
      <h2>登录管理控制台</h2>
      <p class="muted">使用主机管理账户继续。</p>
      <form @submit.prevent="login">
        <label
          >用户名<input
            v-model.trim="username"
            autocomplete="username"
            required
            maxlength="128"
            autofocus /></label
        ><label
          >密码<input
            v-model="password"
            type="password"
            autocomplete="current-password"
            required
            maxlength="72"
        /></label>
        <p v-if="error" class="notice error" role="alert">{{ error }}</p>
        <button class="primary full" :disabled="busy">
          {{ busy ? '正在登录…' : '登录控制台 →' }}
        </button>
      </form>
      <p class="setup-note">
        首次使用：数据库中没有账户时，本次输入的用户名和密码将创建为管理员（密码为 8–72
        字节）。请在可信的本机环境中完成初始化。
      </p>
    </section>
  </main>
</template>
