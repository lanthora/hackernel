<script setup lang="ts">
import { t } from '../lib/i18n'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage } from '../lib/api'
import { currentUser } from '../lib/session'
import AppIcon from '../components/AppIcon.vue'
import LanguageSwitcher from '../components/LanguageSwitcher.vue'
import OverviewPanel from '../components/OverviewPanel.vue'
import EventsPanel from '../components/EventsPanel.vue'
import PoliciesPanel from '../components/PoliciesPanel.vue'
import SettingsPanel from '../components/SettingsPanel.vue'
import UsersPanel from '../components/UsersPanel.vue'
const route = useRoute(),
  router = useRouter(),
  error = ref('')
const host = window.location.hostname
const links = [
  { id: 'overview', label: '防护控制台', icon: 'shield' },
  { id: 'events', label: '安全事件', icon: 'events' },
  { id: 'policies', label: '防护策略', icon: 'file' },
  { id: 'settings', label: '系统设置', icon: 'settings' },
  { id: 'users', label: '账户管理', icon: 'users' }
]
const page = computed(() => String(route.params.page))
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
    <aside class="sidebar">
      <RouterLink to="/overview" class="brand"
        ><AppIcon name="shield" :size="22" /><span
          >{{ t('product.name') }}<small>{{ t('主机安全控制台') }}</small></span
        ></RouterLink
      >
      <p class="nav-label">{{ t('工作空间') }}</p>
      <nav :aria-label="t('主导航')">
        <RouterLink v-for="link in links" :key="link.id" :to="'/' + link.id"
          ><AppIcon :name="link.icon" :size="17" /><span>{{ t(link.label) }}</span></RouterLink
        >
      </nav>
      <div class="sidebar-footer">
        <AppIcon name="net" :size="14" /><span
          >{{ t('管理主机') }}<small>{{ host }}</small></span
        >
      </div>
    </aside>
    <div class="workspace">
      <header class="topbar">
        <div class="window-heading">
          <AppIcon :name="currentPage?.icon || 'shield'" :size="17" />
          <h1>{{ t(currentPage?.label) }}</h1>
        </div>
        <div class="account">
          <LanguageSwitcher /><span class="account-name"
            ><AppIcon name="users" :size="14" />{{
              currentUser?.aliasName || currentUser?.username
            }}</span
          ><button class="text-button" @click="logout">{{ t('退出登录') }}</button>
        </div>
      </header>
      <main class="content">
        <p v-if="error" role="alert" class="notice error">{{ t(error) }}</p>
        <OverviewPanel v-if="page === 'overview'" /><EventsPanel
          v-else-if="page === 'events'"
        /><PoliciesPanel v-else-if="page === 'policies'" /><SettingsPanel
          v-else-if="page === 'settings'"
        /><UsersPanel v-else-if="page === 'users'" />
      </main>
      <footer class="workspace-footer">
        <span>{{ t('product.name') }}</span
        ><span>{{ t('防护服务独立于界面运行') }}</span>
      </footer>
    </div>
  </div>
</template>
