<script setup lang="ts">
import { t } from '../lib/i18n'

import AppIcon from '../components/AppIcon.vue'
import LanguageSwitcher from '../components/LanguageSwitcher.vue'
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
      /^\/(overview|events|policies|settings|users|protection\/(process|file|net))([?#]|$)/.test(
        target
      )
        ? target
        : '/overview'
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
    <section class="login-window" aria-labelledby="login-heading">
      <header class="login-window-bar">
        <div>
          <AppIcon name="shield" :size="19" /><strong>{{ t('product.name') }}</strong>
        </div>
        <LanguageSwitcher />
      </header>
      <div class="login-window-body">
        <h2 id="login-heading">{{ t('登录管理控制台') }}</h2>
        <p class="muted">{{ t('使用主机管理账户继续。') }}</p>
        <form @submit.prevent="login">
          <label
            >{{ t('用户名')
            }}<input
              v-model.trim="username"
              autocomplete="username"
              required
              maxlength="128"
              autofocus /></label
          ><label
            >{{ t('密码')
            }}<input
              v-model="password"
              type="password"
              autocomplete="current-password"
              required
              maxlength="72"
          /></label>
          <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
          <div class="login-actions">
            <span class="muted">{{ t('Linux 主机管理') }}</span
            ><button class="primary" :disabled="busy">{{ t(busy ? '正在登录…' : '登录') }}</button>
          </div>
        </form>
        <details class="setup-note">
          <summary>{{ t('首次使用与账户初始化') }}</summary>
          <p>
            {{
              t(
                '首次使用：数据库中没有账户时，本次输入的用户名和密码将创建为管理员（密码为 8–72 字节）。请在可信的本机环境中完成初始化。'
              )
            }}
          </p>
        </details>
      </div>
    </section>
  </main>
</template>
