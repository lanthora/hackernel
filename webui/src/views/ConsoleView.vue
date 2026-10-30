<script setup lang="ts">
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
        ><span>HIDS<small>主机安全控制台</small></span></RouterLink
      >
      <p class="nav-label">工作空间</p>
      <nav>
        <RouterLink v-for="link in links" :key="link.id" :to="'/' + link.id"
          ><span>{{ link.icon }}</span
          >{{ link.label }}</RouterLink
        >
      </nav>
      <div class="sidebar-footer">
        <span class="dot"></span> 主机防护服务<small>防护服务独立于界面运行</small>
      </div>
    </aside>
    <div class="workspace">
      <header class="topbar">
        <span>工作空间 <span class="muted">/</span> {{ title }}</span>
        <div class="account">
          <span>{{ currentUser?.aliasName || currentUser?.username }}</span
          ><button class="text-button" @click="logout">退出登录</button>
        </div>
      </header>
      <main class="content">
        <div class="page-heading">
          <div>
            <p class="eyebrow">主机入侵检测系统</p>
            <h1>{{ title }}</h1>
          </div>
          <span class="pill neutral">本机管理</span>
        </div>
        <p v-if="error" role="alert" class="notice error">{{ error }}</p>
        <OverviewPanel v-if="page === 'overview'" /><EventsPanel
          v-else-if="page === 'events'"
        /><PoliciesPanel v-else-if="page === 'policies'" /><SettingsPanel
          v-else-if="page === 'settings'"
        /><UsersPanel v-else-if="page === 'users'" />
      </main>
      <footer class="workspace-footer">HIDS · 主机入侵检测系统</footer>
    </div>
  </div>
</template>
