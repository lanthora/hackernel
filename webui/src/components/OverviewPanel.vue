<script setup lang="ts">
import { t, formatClock } from '../lib/i18n'
import { modules } from '../lib/api'
import { useProtection } from '../lib/protection'
import AppIcon from './AppIcon.vue'
const {
  states,
  core,
  refreshing,
  pending,
  connectionError,
  updated,
  savedMode,
  refresh,
  tileState
} = useProtection()
</script>
<template>
  <header class="dashboard-heading">
    <div>
      <h1>{{ t('主机防护') }}</h1>
      <p>{{ t('防护状态、策略与待处理事项') }}</p>
    </div>
    <div class="dashboard-connection">
      <span class="status-dot" :class="{ connected: core?.coreOnline }"></span
      ><span>{{
        t(core ? (core.coreOnline ? '防护核心已连接' : '防护核心未连接') : '核心状态未知')
      }}</span
      ><button
        class="text-button"
        :disabled="refreshing || pending !== null"
        :aria-label="t('刷新状态')"
        @click="refresh(true)"
      >
        <AppIcon name="refresh" :size="15" />
      </button>
    </div>
  </header>
  <p v-if="connectionError" role="alert" class="notice error">{{ t(connectionError) }}</p>
  <p v-else-if="core && !core.coreOnline" role="status" class="notice warning">
    {{ t('请检查主机防护服务；连接恢复前无法确认策略执行结果。') }}
  </p>
  <div class="protection-tiles">
    <section
      v-for="m in modules"
      :key="m.id"
      class="protection-tile"
      :class="tileState(m.id)"
      :aria-labelledby="'protection-' + m.id"
    >
      <header class="tile-top">
        <span class="tile-icon"><AppIcon :name="m.id" :size="30" /></span
        ><RouterLink
          class="tile-configure"
          :aria-label="t('配置{module}', { module: t(m.name) })"
          :to="'/protection/' + m.id"
        >
          <AppIcon name="settings" :size="14" /><span>{{ t('配置') }}</span>
        </RouterLink>
      </header>
      <h2 :id="'protection-' + m.id">
        <RouterLink class="tile-main-link" :to="'/protection/' + m.id">{{ t(m.name) }}</RouterLink>
      </h2>
      <div class="tile-state">
        <span class="tile-state-label"
          ><span></span
          >{{
            t(
              tileState(m.id) === 'unknown'
                ? '状态未知'
                : states[m.id]?.status === 1
                ? '已开启'
                : '已关闭'
            )
          }}</span
        ><span v-if="m.id === 'process' && savedMode !== undefined" class="tile-mode">{{
          t(['关闭判定', '审计模式', '防御模式'][savedMode])
        }}</span>
      </div>
      <dl class="tile-metric">
        <dt>{{ t('当前策略') }}</dt>
        <dd>
          {{ states[m.id]?.policyCount ?? '—' }}<span>{{ t('条') }}</span>
        </dd>
      </dl>
      <RouterLink
        class="tile-attention"
        :class="{ actionable: (states[m.id]?.unreadEventCount ?? 0) > 0 }"
        :to="{ path: '/events', query: { module: m.id } }"
        :aria-label="t('查看{module}待处理事项', { module: t(m.name) })"
        ><div>
          <strong>{{ states[m.id]?.unreadEventCount ?? '—' }}</strong
          ><span>{{ t('待处理事项') }}</span>
        </div>
        <span class="tile-attention-action"
          >{{ t((states[m.id]?.unreadEventCount ?? 0) > 0 ? '去处理' : '查看记录')
          }}<AppIcon name="arrow" :size="14" /></span
      ></RouterLink>
    </section>
  </div>
  <div class="control-bottom">
    <span>{{ t('每 10 秒刷新 ·') }} {{ updated ? formatClock(updated) : t('等待响应') }}</span>
  </div>
</template>
