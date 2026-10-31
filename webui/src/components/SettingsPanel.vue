<script setup lang="ts">
import { t } from '../lib/i18n'
import { onMounted, ref } from 'vue'
import { api, errorMessage, type CoreStatus } from '../lib/api'
const core = ref<CoreStatus | null>(null),
  busy = ref(false),
  error = ref(''),
  success = ref('')
async function load() {
  try {
    core.value = await api<CoreStatus>('/ctrl/status')
  } catch (e) {
    core.value = null
    error.value = errorMessage(e)
  }
}
async function apply(path: string, confirmation?: string) {
  if (confirmation && !window.confirm(t(confirmation))) return
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api(path)
    success.value = '操作成功'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function checkCore() {
  busy.value = true
  error.value = ''
  await load()
  busy.value = false
}
function toggleDebug() {
  return apply(`/ctrl/${core.value?.debugEnabled ? 'disableDebug' : 'enableDebug'}`)
}
function stopCore() {
  return apply('/ctrl/shutdown', '确定停止防护核心？此操作将中断主机防护。')
}
onMounted(checkCore)
</script>
<template>
  <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
  <p v-if="success" class="notice success" role="status">{{ t(success) }}</p>
  <div class="settings-shortcut">
    <span>{{ t('防护开关和模式已集中在防护控制台。') }}</span
    ><RouterLink to="/overview">{{ t('打开防护控制台') }} →</RouterLink>
  </div>
  <section class="panel settings-section">
    <h2>{{ t('诊断与服务') }}</h2>
    <div class="setting-row">
      <div>
        <h3>{{ t('核心通信') }}</h3>
        <p class="muted">{{ t(core ? (core.coreOnline ? '已连接' : '未连接') : '未知') }}</p>
      </div>
      <button :disabled="busy" @click="checkCore">{{ t('重新检查') }}</button>
    </div>
    <div class="setting-row">
      <div>
        <h3>{{ t('性能诊断') }}</h3>
        <p class="muted">
          {{ t(core ? (core.debugEnabled ? '已开启' : '已关闭') : '未知') }}
          {{ t('· 仅在排查问题时启用 pprof。') }}
        </p>
      </div>
      <button :disabled="busy || !core" @click="toggleDebug">
        {{ t(core?.debugEnabled ? '关闭诊断' : '开启诊断') }}
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
