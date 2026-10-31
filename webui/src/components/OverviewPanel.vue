<script setup lang="ts">
import { t, formatClock } from '../lib/i18n'

import { ref, onMounted, onUnmounted } from 'vue'
import {
  api,
  errorMessage,
  modules,
  type ModuleStatus,
  type CoreStatus,
  type Module
} from '../lib/api'
const states = ref<Partial<Record<Module, ModuleStatus>>>({}),
  core = ref<CoreStatus | null>(null)
const error = ref(''),
  loading = ref(false),
  updated = ref<number | null>(null)
let timer: ReturnType<typeof setInterval>,
  active = true
async function refresh() {
  if (loading.value || document.hidden) return
  loading.value = true
  const results = await Promise.allSettled([
    api<CoreStatus>('/ctrl/status'),
    ...modules.map((m) => api<ModuleStatus>(`/${m.id}/showModuleStatus`))
  ])
  if (!active) return
  error.value = ''
  core.value = results[0].status === 'fulfilled' ? (results[0].value as CoreStatus) : null
  modules.forEach((m, index) => {
    const result = results[index + 1]
    states.value[m.id] = result.status === 'fulfilled' ? (result.value as ModuleStatus) : undefined
  })
  const failed = results.find((result) => result.status === 'rejected')
  if (failed?.status === 'rejected') error.value = errorMessage(failed.reason)
  updated.value = Date.now()
  loading.value = false
}
onMounted(() => {
  refresh()
  timer = setInterval(refresh, 10000)
})
onUnmounted(() => {
  active = false
  clearInterval(timer)
})
</script>
<template>
  <section class="health-banner">
    <div class="health-symbol">◈</div>
    <div>
      <p class="eyebrow">{{ t('核心连接') }}</p>
      <h2>
        {{
          core ? (core.coreOnline ? t('防护核心已连接') : t('防护核心未连接')) : t('核心状态未知')
        }}
      </h2>
      <p>
        {{
          core?.coreOnline
            ? t('管理服务可以与防护核心通信。')
            : t('请检查主机防护服务；连接恢复前无法确认策略执行结果。')
        }}
      </p>
    </div>
    <button @click="refresh" :disabled="loading">
      {{ loading ? t('刷新中…') : t('刷新状态') }}
    </button>
  </section>
  <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
  <div class="section-heading">
    <h2>{{ t('防护模块') }}</h2>
    <span class="muted"
      >{{ t('每 10 秒刷新 ·') }} {{ updated ? formatClock(updated) : t('等待响应') }}</span
    >
  </div>
  <div class="module-grid">
    <article v-for="m in modules" :key="m.id" class="panel module-card">
      <div class="module-heading">
        <span class="module-icon">{{ m.id === 'process' ? '⌘' : m.id === 'file' ? '▤' : '⇄' }}</span
        ><span class="pill" :class="states[m.id]?.status === 1 ? 'success' : 'neutral'">{{
          states[m.id]
            ? states[m.id]?.status === 1
              ? t('配置启用')
              : t('配置关闭')
            : t('状态未知')
        }}</span>
      </div>
      <h2>{{ t(m.name) }}</h2>
      <p class="muted">{{ t(m.description) }}</p>
      <div class="metrics">
        <div>
          <strong>{{ states[m.id]?.policyCount ?? '—' }}</strong
          ><span>{{ t('策略 / 记录') }}</span>
        </div>
        <div>
          <strong>{{ states[m.id]?.unreadEventCount ?? '—' }}</strong
          ><span>{{ t('待处理事件') }}</span>
        </div>
      </div>
      <RouterLink :to="{ path: '/events', query: { module: m.id } }" class="card-link"
        >{{ t('查看安全事件') }} <span>↗</span></RouterLink
      >
      <RouterLink class="card-link" :to="{ path: '/settings', hash: '#' + m.id }"
        >{{ t('配置防护') }} →</RouterLink
      >
    </article>
  </div>
  <div class="panel explanation">
    <h3>{{ t('状态说明') }}</h3>
    <p class="muted">
      {{
        t(
          '模块状态来自已保存配置；核心连接仅代表通信正常。当前核心接口不提供各模块实时启用状态，实际执行结果以操作反馈为准。关闭浏览器不会停止后台防护。'
        )
      }}
    </p>
  </div>
</template>
