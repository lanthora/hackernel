import { t } from './i18n'
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { api, errorMessage, modules, type ModuleStatus, type CoreStatus, type Module } from './api'

export function useProtection() {
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
      states.value[m.id] =
        result.status === 'fulfilled' ? (result.value as ModuleStatus) : undefined
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
  function tileState(module: Module): 'enabled' | 'disabled' | 'unknown' {
    if (!core.value?.coreOnline || !states.value[module]) return 'unknown'
    return states.value[module]?.status === 1 ? 'enabled' : 'disabled'
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

  return {
    states,
    core,
    refreshing,
    pending,
    connectionError,
    updated,
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
  }
}
