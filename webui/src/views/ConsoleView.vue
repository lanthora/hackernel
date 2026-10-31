<script setup lang="ts">
import { t } from '../lib/i18n'
import { computed, ref, watch, provide } from 'vue'
import { useDialog } from '../lib/dialog'
import { useProtection, protectionKey } from '../lib/protection'
import { useRoute, useRouter } from 'vue-router'
import { api, errorMessage, modules, type Module } from '../lib/api'
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
  error = ref(''),
  toolsOpen = ref(false)
const toolsDialog = useDialog(
  () => toolsOpen.value,
  () => {
    toolsOpen.value = false
  }
)
watch(
  () => route.fullPath,
  () => {
    toolsOpen.value = false
  }
)
const host = window.location.hostname
const protection = useProtection()
provide(protectionKey, protection)
const { core, refreshing, pending, refresh } = protection
const links = [
  { id: 'overview', label: '防护控制台', icon: 'shield' },
  { id: 'events', label: '安全事件', icon: 'events' },
  { id: 'policies', label: '防护策略', icon: 'file' },
  { id: 'settings', label: '系统设置', icon: 'settings' },
  { id: 'users', label: '账户管理', icon: 'users' }
]
const toolLinks = links.filter((link) => link.id === 'settings' || link.id === 'users')
const page = computed(() => (route.params.module ? 'protection' : String(route.params.page)))
const currentPage = computed(() => links.find((link) => link.id === page.value))
const eventTitles: Record<Module, string> = {
  process: '进程事件',
  file: '文件事件',
  net: '网络事件'
}
const currentTitle = computed(() =>
  page.value === 'events'
    ? t(eventTitles[modules.find((m) => m.id === route.query.module)?.id || 'process'])
    : t(currentPage.value?.label)
)
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
    <main :key="route.path" class="content">
      <div class="content-inner">
        <p v-if="error" role="alert" class="notice error">{{ t(error) }}</p>
        <RouterLink
          v-if="page !== 'overview' && page !== 'protection'"
          class="back-link"
          to="/overview"
          ><AppIcon name="arrow" :size="15" />{{ t('返回防护主页') }}</RouterLink
        >
        <header v-if="currentPage && page !== 'overview'" class="page-heading">
          <h1>{{ currentTitle }}</h1>
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
      <span class="footer-connection"
        ><span class="status-dot" :class="{ connected: core?.coreOnline }"></span
        >{{ t(core ? (core.coreOnline ? '防护核心已连接' : '防护核心未连接') : '核心状态未知')
        }}<button
          class="text-button"
          :disabled="refreshing || pending !== null"
          :aria-label="t('刷新状态')"
          @click="refresh(true)"
        >
          <AppIcon name="refresh" :size="14" /></button
      ></span>
    </footer>
    <button
      class="tools-launcher"
      :aria-expanded="toolsOpen"
      aria-controls="console-tools"
      aria-haspopup="dialog"
      @click="toolsOpen = !toolsOpen"
    >
      <AppIcon :name="toolsOpen ? 'close' : 'grid'" :size="19" /><span>{{ t('工具与账户') }}</span>
    </button>
    <div v-if="toolsOpen" class="tools-backdrop" @click.self="toolsOpen = false">
      <section
        id="console-tools"
        ref="toolsDialog"
        class="tools-popover"
        role="dialog"
        aria-modal="true"
        :aria-label="t('控制台工具')"
      >
        <header class="tools-heading">
          <div>
            <strong>{{ t('product.name') }}</strong>
            <p>{{ host }}</p>
          </div>
          <button class="text-button" :aria-label="t('关闭工具菜单')" @click="toolsOpen = false">
            <AppIcon name="close" :size="18" />
          </button>
        </header>
        <p v-if="error" role="alert" class="notice error">{{ t(error) }}</p>
        <nav class="tools-navigation" :aria-label="t('主导航')">
          <RouterLink
            v-for="link in toolLinks"
            :key="link.id"
            :to="'/' + link.id"
            @click="toolsOpen = false"
            ><AppIcon :name="link.icon" :size="21" /><span>{{ t(link.label) }}</span></RouterLink
          >
        </nav>
        <div class="tools-preferences"><LanguageSwitcher /></div>
        <div class="tools-account">
          <span
            ><AppIcon name="users" :size="17" />{{
              currentUser?.aliasName || currentUser?.username
            }}</span
          ><button class="text-button" @click="logout">{{ t('退出登录') }}</button>
        </div>
      </section>
    </div>
  </div>
</template>
