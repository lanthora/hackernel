<script setup lang="ts">
import { t } from '../lib/i18n'

import LanguageSwitcher from '../components/LanguageSwitcher.vue'
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../lib/api'
import { currentUser } from '../lib/session'
import { ref } from 'vue'
import OverviewPanel from '../components/OverviewPanel.vue'
import EventsPanel from '../components/EventsPanel.vue'
import PoliciesPanel from '../components/PoliciesPanel.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import UsersPanel from '../components/UsersPanel.vue'
const route = useRoute(),
  router = useRouter(),
  error = ref('')
const links = [
  { id: 'overview', label: '安全概览', icon: '◈' },
  { id: 'events', label: '安全事件', icon: '≋' },
  { id: 'policies', label: '防护策略', icon: '▤' },
  { id: 'settings', label: '系统设置', icon: '⚙' },
  { id: 'users', label: '账户管理', icon: '◎' }
]
const page = computed(() => String(route.params.page))
const title = computed(() => links.find((link) => link.id === page.value)?.label)
async function logout() {
  try {
    await api('/auth/logout')
    currentUser.value = null
    await router.replace('/login')
  } catch (e) {
    error.value = errorMessage(e)
  }
}
</script>
<template>
  <div class="console-shell">
    <aside class="sidebar">
      <RouterLink to="/overview" class="brand"
        ><span
          >{{ t('product.name') }}<small>{{ t('主机安全控制台') }}</small></span
        ></RouterLink
      >
      <p class="nav-label">{{ t('工作空间') }}</p>
      <nav>
        <RouterLink v-for="link in links" :key="link.id" :to="'/' + link.id"
          ><span>{{ link.icon }}</span
          >{{ t(link.label) }}</RouterLink
        >
      </nav>
      <div class="sidebar-footer">
        <span class="dot"></span> {{ t('主机防护服务')
        }}<small>{{ t('防护服务独立于界面运行') }}</small>
      </div>
    </aside>
    <div class="workspace">
      <header class="topbar">
        <span>{{ t('工作空间') }} <span class="muted">/</span> {{ t(title) }}</span>
        <div class="account">
          <LanguageSwitcher />
          <span>{{ currentUser?.aliasName || currentUser?.username }}</span
          ><button class="text-button" @click="logout">{{ t('退出登录') }}</button>
        </div>
      </header>
      <main class="content">
        <div class="page-heading">
          <div>
            <p class="eyebrow">{{ t('product.description') }}</p>
            <h1>{{ t(title) }}</h1>
          </div>
          <span class="pill neutral">{{ t('本机管理') }}</span>
        </div>
        <p v-if="error" role="alert" class="notice error">{{ t(error) }}</p>
        <OverviewPanel v-if="page === 'overview'" /><EventsPanel
          v-else-if="page === 'events'"
        /><PoliciesPanel v-else-if="page === 'policies'" /><SettingsPanel
          v-else-if="page === 'settings'"
        /><UsersPanel v-else-if="page === 'users'" />
      </main>
      <footer class="workspace-footer">{{ t('product.name') }}</footer>
    </div>
  </div>
</template>
