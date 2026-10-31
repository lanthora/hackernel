<script setup lang="ts">
import { t, formatClock } from '../lib/i18n'
import { ref, reactive, computed, nextTick, onMounted, onUnmounted } from 'vue'
import AppIcon from './AppIcon.vue'
import PoliciesPanel from './PoliciesPanel.vue'
import {
  api,
  errorMessage,
  modules,
  type ModuleStatus,
  type CoreStatus,
  type Module
} from '../lib/api'

const states = ref<Partial<Record<Module, ModuleStatus>>>({})
const core = ref<CoreStatus | null>(null),
  refreshing = ref(false),
  pending = ref<Module | null>(null)
const connectionError = ref(''),
  updated = ref<number | null>(null)
const feedback = reactive<Partial<Record<Module, { error?: string; success?: string }>>>({})
const savedMode = ref<number>(),
  savedDefault = ref<number>()
const mode = ref<number>(),
  defaultStatus = ref<number>()
const dirty = computed(
  () => mode.value !== savedMode.value || defaultStatus.value !== savedDefault.value
)
const configuring = ref<Module | null>(null)
const inspector = ref<HTMLElement | null>(null)
let active = true
async function refresh(force = false) {
  if (refreshing.value || (!force && (document.hidden || pending.value))) return
  refreshing.value = true
  const results = await Promise.allSettled([
    api<CoreStatus>('/ctrl/status'),
    ...modules.map((m) => api<ModuleStatus>(`/${m.id}/showModuleStatus`)),
    api<{ judge: number }>('/process/showWorkMode'),
    api<{ status: number }>('/process/showDefaultEventStatus')
  ])
  if (!active) return
  core.value = results[0].status === 'fulfilled' ? (results[0].value as CoreStatus) : null
  modules.forEach((m, index) => {
    const result = results[index + 1]
    states.value[m.id] = result.status === 'fulfilled' ? (result.value as ModuleStatus) : undefined
  })
  const modeResult = results[4],
    defaultResult = results[5]
  if (modeResult.status === 'fulfilled') {
    const clean = mode.value === savedMode.value
    savedMode.value = (modeResult.value as { judge: number }).judge
    if (clean) mode.value = savedMode.value
  }
  if (defaultResult.status === 'fulfilled') {
    const clean = defaultStatus.value === savedDefault.value
    savedDefault.value = (defaultResult.value as { status: number }).status
    if (clean) defaultStatus.value = savedDefault.value
  }
  const failure = results.find((result) => result.status === 'rejected')
  connectionError.value = failure?.status === 'rejected' ? errorMessage(failure.reason) : ''
  updated.value = Date.now()
  refreshing.value = false
}
async function toggle(m: { id: Module; name: string }) {
  if (pending.value || refreshing.value || !states.value[m.id] || !core.value?.coreOnline) return
  const enabled = states.value[m.id]?.status === 1
  if (enabled && !window.confirm(t('确定关闭{p0}？', { p0: t(m.name) }))) return
  pending.value = m.id
  feedback[m.id] = {}
  try {
    await api(`/${m.id}/${enabled ? 'disableModule' : 'enableModule'}`)
    feedback[m.id] = { success: enabled ? '模块已关闭' : '模块已启用' }
  } catch (error) {
    feedback[m.id] = { error: errorMessage(error) }
  } finally {
    await refresh(true)
    pending.value = null
  }
}
async function saveProcess() {
  if (pending.value || refreshing.value || !core.value?.coreOnline || !dirty.value) return
  if (
    mode.value === 2 &&
    savedMode.value !== 2 &&
    !window.confirm(t('切换到防御模式后，不受信任的命令可能无法执行。确定应用？'))
  )
    return
  if (
    defaultStatus.value === 2 &&
    savedDefault.value !== 2 &&
    !window.confirm(t('确定默认信任新命令？这会降低对未知命令的防护。'))
  )
    return
  pending.value = 'process'
  feedback.process = {}
  try {
    if (mode.value !== undefined && mode.value !== savedMode.value) {
      await api('/process/updateWorkMode', { judge: mode.value })
      savedMode.value = mode.value
    }
    if (defaultStatus.value !== undefined && defaultStatus.value !== savedDefault.value) {
      await api('/process/updateDefaultEventStatus', { status: defaultStatus.value })
      savedDefault.value = defaultStatus.value
    }
    feedback.process = { success: '配置已保存' }
  } catch (error) {
    feedback.process = { error: errorMessage(error) }
  } finally {
    await refresh(true)
    pending.value = null
  }
}
function resetProcess() {
  mode.value = savedMode.value
  defaultStatus.value = savedDefault.value
}
let configurationOpener: HTMLElement | null = null
function tileState(module: Module): 'enabled' | 'disabled' | 'unknown' {
  if (!core.value?.coreOnline || !states.value[module]) return 'unknown'
  return states.value[module]?.status === 1 ? 'enabled' : 'disabled'
}
async function openConfiguration(module: Module) {
  configurationOpener = document.activeElement as HTMLElement | null
  configuring.value = module
  await nextTick()
  inspector.value?.focus({ preventScroll: true })
  inspector.value?.scrollIntoView({ block: 'nearest' })
}
async function closeConfiguration() {
  if (pending.value) return
  configuring.value = null
  await nextTick()
  if (configurationOpener?.isConnected) configurationOpener.focus()
}
let timer: ReturnType<typeof setInterval>
onMounted(() => {
  refresh()
  timer = setInterval(() => refresh(), 10000)
})
onUnmounted(() => {
  active = false
  clearInterval(timer)
})
</script>
<template>
  <header class="dashboard-heading">
    <div>
      <h2>{{ t('主机防护') }}</h2>
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
      :class="[tileState(m.id), { selected: configuring === m.id }]"
      :aria-labelledby="'protection-' + m.id"
    >
      <header class="tile-top">
        <span class="tile-icon"><AppIcon :name="m.id" :size="30" /></span
        ><button
          class="tile-configure"
          :aria-label="t('配置{module}', { module: t(m.name) })"
          @click="openConfiguration(m.id)"
        >
          <AppIcon name="settings" :size="14" /><span>{{ t('配置') }}</span
          ><span
            v-if="m.id === 'process' && dirty"
            class="draft-dot"
            :aria-label="t('有未保存的更改')"
          ></span>
        </button>
      </header>
      <h2 :id="'protection-' + m.id">{{ t(m.name) }}</h2>
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
  <section
    v-if="configuring"
    class="rule-inspector module-configuration"
    ref="inspector"
    tabindex="-1"
    :aria-label="t('配置{module}', { module: t(modules.find((m) => m.id === configuring)?.name) })"
  >
    <header class="inspector-heading">
      <div>
        <AppIcon :name="configuring" :size="18" />
        <h2>
          {{ t('配置{module}', { module: t(modules.find((m) => m.id === configuring)?.name) }) }}
        </h2>
      </div>
      <button
        class="text-button"
        :disabled="pending !== null"
        :aria-label="t('关闭配置')"
        @click="closeConfiguration"
      >
        <AppIcon name="close" :size="16" />
      </button>
    </header>
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
  <div class="control-bottom">
    <span>{{ t('每 10 秒刷新 ·') }} {{ updated ? formatClock(updated) : t('等待响应') }}</span>
    <details>
      <summary>{{ t('关于防护状态') }}</summary>
      <p>{{ t('开关显示已保存配置，操作成功后更新。关闭界面不会停止后台防护。') }}</p>
    </details>
  </div>
</template>
