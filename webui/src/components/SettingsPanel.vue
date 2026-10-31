<script setup lang="ts">
import { t } from '../lib/i18n'

import { onMounted, ref } from 'vue'
import {
  api,
  modules,
  errorMessage,
  type Module,
  type ModuleStatus,
  type CoreStatus
} from '../lib/api'
const states = ref<Partial<Record<Module, ModuleStatus>>>({}),
  core = ref<CoreStatus | null>(null)
const mode = ref(0),
  defaultStatus = ref(0),
  busy = ref(false),
  error = ref(''),
  success = ref('')
const modeLoaded = ref(false),
  defaultLoaded = ref(false)
async function load() {
  const results = await Promise.allSettled([
    api<CoreStatus>('/ctrl/status'),
    api<{ judge: number }>('/process/showWorkMode'),
    api<{ status: number }>('/process/showDefaultEventStatus'),
    ...modules.map((m) => api<ModuleStatus>(`/${m.id}/showModuleStatus`))
  ])
  core.value = results[0].status === 'fulfilled' ? (results[0].value as CoreStatus) : null
  modeLoaded.value = results[1].status === 'fulfilled'
  defaultLoaded.value = results[2].status === 'fulfilled'
  if (results[1].status === 'fulfilled') mode.value = (results[1].value as { judge: number }).judge
  if (results[2].status === 'fulfilled')
    defaultStatus.value = (results[2].value as { status: number }).status
  modules.forEach((m, i) => {
    const result = results[i + 3]
    states.value[m.id] = result.status === 'fulfilled' ? (result.value as ModuleStatus) : undefined
  })
  const failure = results.find((r) => r.status === 'rejected')
  if (failure?.status === 'rejected') error.value = errorMessage(failure.reason)
}
async function apply(path: string, body: unknown = {}, confirm?: string) {
  if (confirm && !window.confirm(t(confirm))) return
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api(path, body)
    success.value = '操作成功'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
function toggleModule(m: { id: Module; name: string }) {
  const enabled = states.value[m.id]?.status === 1
  return apply(
    `/${m.id}/${enabled ? 'disableModule' : 'enableModule'}`,
    {},
    enabled ? t('确定关闭{p0}？', { p0: t(m.name) }) : undefined
  )
}
function saveMode() {
  return apply(
    '/process/updateWorkMode',
    { judge: mode.value },
    mode.value === 2 ? '切换到防御模式后，不受信任的命令可能无法执行。确定应用？' : undefined
  )
}
function saveDefault() {
  return apply(
    '/process/updateDefaultEventStatus',
    { status: defaultStatus.value },
    defaultStatus.value === 2 ? '确定默认信任新命令？这会降低对未知命令的防护。' : undefined
  )
}
function toggleDebug() {
  return apply(`/ctrl/${core.value?.debugEnabled ? 'disableDebug' : 'enableDebug'}`)
}
async function checkCore() {
  busy.value = true
  error.value = ''
  await load()
  busy.value = false
}
function stopCore() {
  return apply('/ctrl/shutdown', {}, '确定停止防护核心？此操作将中断主机防护。')
}
onMounted(async () => {
  busy.value = true
  await load()
  busy.value = false
})
</script>
<template>
  <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
  <p v-if="success" class="notice success" role="status">{{ t(success) }}</p>
  <section class="panel settings-section">
    <h2>{{ t('防护模块') }}</h2>
    <p class="muted">{{ t('开关展示已保存配置，操作需要核心连接正常。') }}</p>
    <div v-for="m in modules" :key="m.id" :id="m.id" class="setting-row">
      <div>
        <h3>{{ t(m.name) }}</h3>
        <p v-if="m.id === 'process'" class="muted">
          {{ t('启用模块后，请选择并保存工作模式。建议先使用审计模式。') }}
        </p>
        <p class="muted">
          {{
            states[m.id]
              ? states[m.id]?.status === 1
                ? t('配置启用')
                : t('配置关闭')
              : t('配置未知')
          }}
        </p>
      </div>
      <button :disabled="busy || !states[m.id] || !core?.coreOnline" @click="toggleModule(m)">
        {{ states[m.id]?.status === 1 ? t('关闭模块') : t('启用模块') }}
      </button>
    </div>
  </section>
  <section class="panel settings-section">
    <h2>{{ t('进程执行策略') }}</h2>
    <form @submit.prevent="saveMode">
      <label
        >{{ t('工作模式')
        }}<select v-model.number="mode" :disabled="!modeLoaded">
          <option :value="0">{{ t('关闭判定') }}</option>
          <option :value="1">{{ t('审计模式') }}</option>
          <option :value="2">{{ t('防御模式') }}</option>
        </select></label
      >
      <p class="muted">{{ t('审计模式记录执行事件；防御模式对命令执行进行信任判定。') }}</p>
      <button class="primary" :disabled="busy || !core?.coreOnline || !modeLoaded">
        {{ t('保存工作模式') }}
      </button>
    </form>
    <hr />
    <form @submit.prevent="saveDefault">
      <label
        >{{ t('新命令的默认状态')
        }}<select v-model.number="defaultStatus" :disabled="!defaultLoaded">
          <option :value="0">{{ t('待处理') }}</option>
          <option :value="1">{{ t('不信任') }}</option>
          <option :value="2">{{ t('信任') }}</option>
        </select></label
      ><button :disabled="busy || !defaultLoaded">{{ t('保存默认状态') }}</button>
    </form>
  </section>
  <section class="panel settings-section">
    <h2>{{ t('诊断与服务') }}</h2>
    <div class="setting-row">
      <div>
        <h3>{{ t('核心通信') }}</h3>
        <p class="muted">
          {{ core ? (core.coreOnline ? t('已连接') : t('未连接')) : t('未知') }}
        </p>
      </div>
      <button :disabled="busy" @click="checkCore">{{ t('重新检查') }}</button>
    </div>
    <div class="setting-row">
      <div>
        <h3>{{ t('性能诊断') }}</h3>
        <p class="muted">
          {{ core ? (core.debugEnabled ? t('已开启') : t('已关闭')) : t('未知') }}
          {{ t('· 仅在排查问题时启用 pprof。') }}
        </p>
      </div>
      <button :disabled="busy || !core" @click="toggleDebug">
        {{ core?.debugEnabled ? t('关闭诊断') : t('开启诊断') }}
      </button>
    </div>
    <div class="setting-row">
      <div>
        <h3>{{ t('停止防护核心') }}</h3>
        <p class="muted">{{ t('停止后会失去防护能力。systemd 可能按服务配置重新启动核心。') }}</p>
      </div>
      <button class="danger-text" :disabled="busy || !core?.coreOnline" @click="stopCore">
        {{ t('停止核心') }}
      </button>
    </div>
  </section>
</template>
