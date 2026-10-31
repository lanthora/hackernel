<script setup lang="ts">
import { t } from '../lib/i18n'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../lib/api'
import { currentUser } from '../lib/session'
import AppIcon from '../components/AppIcon.vue'
import LanguageSwitcher from '../components/LanguageSwitcher.vue'
import OverviewPanel from '../components/OverviewPanel.vue'
import ProtectionPanel from '../components/ProtectionPanel.vue'
import EventsPanel from '../components/EventsPanel.vue'
import PoliciesPanel from '../components/PoliciesPanel.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import UsersPanel from '../components/UsersPanel.vue'
const route = useRoute(),
  router = useRouter(),
  error = ref('')
const host = window.location.hostname
const links = [
  { id: 'overview', label: '防护控制台' },
  { id: 'events', label: '安全事件' },
  { id: 'policies', label: '防护策略' },
  { id: 'settings', label: '系统设置' },
  { id: 'users', label: '账户管理' }
]
const page = computed(() => (route.params.module ? 'protection' : String(route.params.page)))
const currentPage = computed(() => links.find((link) => link.id === page.value))
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
    <header class="app-header">
      <RouterLink to="/overview" class="brand"
        ><span class="brand-icon"><AppIcon name="shield" :size="22" /></span
        ><span>{{ t('product.name') }}</span></RouterLink
      >
      <nav class="app-nav" :aria-label="t('主导航')">
        <RouterLink
          v-for="link in links"
          :key="link.id"
          :to="'/' + link.id"
          :class="{ 'nav-current': link.id === 'overview' && page === 'protection' }"
          >{{ t(link.label) }}</RouterLink
        >
      </nav>
      <div class="account">
        <LanguageSwitcher /><span class="account-name">{{
          currentUser?.aliasName || currentUser?.username
        }}</span
        ><button class="text-button" @click="logout">{{ t('退出登录') }}</button>
      </div>
    </header>
    <main :key="route.path" class="content">
      <div class="content-inner">
        <p v-if="error" role="alert" class="notice error">{{ t(error) }}</p>
        <header v-if="currentPage && page !== 'overview'" class="page-heading">
          <h1>{{ t(currentPage.label) }}</h1>
        </header>
        <OverviewPanel v-if="page === 'overview'" />
        <ProtectionPanel v-else-if="page === 'protection'" :key="String(route.params.module)" />
        <EventsPanel v-else-if="page === 'events'" />
        <PoliciesPanel v-else-if="page === 'policies'" />
        <SettingsPanel v-else-if="page === 'settings'" />
        <UsersPanel v-else-if="page === 'users'" />
      </div>
    </main>
    <footer class="workspace-footer">
      <span>{{ t('管理主机') }} · {{ host }}</span
      ><span>{{ t('防护服务独立于界面运行') }}</span>
    </footer>
  </div>
</template>
