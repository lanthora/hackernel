<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { t } from '../lib/i18n'
import { modules, type Module } from '../lib/api'
import { useProtection } from '../lib/protection'
import AppIcon from './AppIcon.vue'
import PoliciesPanel from './PoliciesPanel.vue'
const route = useRoute()
const configuring = computed(() => route.params.module as Module)
const moduleInfo = computed(() => modules.find((m) => m.id === configuring.value)!)
const {
  states,
  core,
  refreshing,
  pending,
  connectionError,
  feedback,
  savedMode,
  savedDefault,
  mode,
  defaultStatus,
  dirty,
  refresh,
  toggle,
  saveProcess,
  resetProcess,
  tileState
} = useProtection()
</script>
<template>
  <RouterLink class="back-link" to="/overview"
    ><AppIcon name="arrow" :size="15" />{{ t('返回防护主页') }}</RouterLink
  >
  <header class="dashboard-heading detail-heading">
    <div>
      <h1>{{ t(moduleInfo.name) }}</h1>
      <p>{{ t('管理此项防护的开关、模式与策略。') }}</p>
    </div>
    <span class="detail-status" :class="tileState(configuring)"
      ><span class="status-dot" :class="{ connected: tileState(configuring) === 'enabled' }"></span
      >{{
        t(
          tileState(configuring) === 'unknown'
            ? '状态未知'
            : states[configuring]?.status === 1
            ? '已开启'
            : '已关闭'
        )
      }}</span
    >
  </header>
  <p v-if="connectionError" role="alert" class="notice error">{{ t(connectionError) }}</p>
  <section
    class="rule-inspector module-configuration"
    :aria-label="t('配置{module}', { module: t(modules.find((m) => m.id === configuring)?.name) })"
  >
    <div class="configuration-switch-row">
      <div>
        <strong>{{ t('模块开关') }}</strong>
        <p>{{ t('启用或关闭此项防护功能。') }}</p>
      </div>
      <div class="protection-switch">
        <span>{{
          t(
            states[configuring] ? (states[configuring]?.status === 1 ? '已开启' : '已关闭') : '未知'
          )
        }}</span
        ><button
          type="button"
          role="switch"
          :aria-checked="states[configuring]?.status === 1"
          :aria-label="
            t('切换{module}', { module: t(modules.find((m) => m.id === configuring)?.name) })
          "
          :disabled="refreshing || pending !== null || !states[configuring] || !core?.coreOnline"
          @click="toggle(modules.find((m) => m.id === configuring)!)"
        >
          <span></span>
        </button>
      </div>
    </div>
    <template v-if="configuring === 'process'"
      ><form class="process-properties" @submit.prevent="saveProcess">
        <label
          >{{ t('工作模式')
          }}<select v-model.number="mode" :disabled="pending !== null || savedMode === undefined">
            <option v-if="savedMode === undefined" disabled :value="undefined">
              {{ t('等待响应') }}
            </option>
            <option :value="0">{{ t('关闭判定') }}</option>
            <option :value="1">{{ t('审计模式') }}</option>
            <option :value="2">{{ t('防御模式') }}</option>
          </select></label
        ><label
          >{{ t('新命令的默认状态')
          }}<select
            v-model.number="defaultStatus"
            :disabled="pending !== null || savedDefault === undefined"
          >
            <option v-if="savedDefault === undefined" disabled :value="undefined">
              {{ t('等待响应') }}
            </option>
            <option :value="0">{{ t('待处理') }}</option>
            <option :value="1">{{ t('不信任') }}</option>
            <option :value="2">{{ t('信任') }}</option>
          </select></label
        >
        <div class="protection-save-row">
          <button
            class="primary"
            :disabled="!dirty || pending !== null || refreshing || !core?.coreOnline"
          >
            {{ t(pending === 'process' ? '正在应用…' : '保存配置') }}</button
          ><button type="button" :disabled="!dirty || pending !== null" @click="resetProcess">
            {{ t('还原') }}</button
          ><small v-if="dirty" class="unsaved-label">{{ t('有未保存的更改') }}</small>
        </div>
      </form>
      <p v-if="states.process?.status === 1 && savedMode === 0" class="inline-warning">
        {{ t('模块已开启，请选择审计或防御模式并保存。') }}
      </p>
      <RouterLink class="configuration-events" to="/events?module=process"
        >{{ t('命令信任与事件') }} →</RouterLink
      ></template
    >
    <PoliciesPanel v-else :module="configuring" embedded @changed="refresh(true)" />
    <p v-if="pending === configuring" class="card-feedback" role="status">{{ t('正在应用…') }}</p>
    <p v-else-if="feedback[configuring]?.error" class="card-feedback failure" role="alert">
      {{ t(feedback[configuring]?.error) }}
    </p>
    <p v-else-if="feedback[configuring]?.success" class="card-feedback" role="status">
      {{ t(feedback[configuring]?.success) }}
    </p>
  </section>
</template>
