<script setup lang="ts">
import { t } from '../lib/i18n'

import { useDialog } from '../lib/dialog'
import { ref, watch, computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  api,
  errorMessage,
  modules,
  permissionsText,
  formatTime,
  type Module,
  type EventRecord
} from '../lib/api'
const route = useRoute()
const module = computed<Module>(() =>
  modules.some((m) => m.id === route.query.module) ? (route.query.module as Module) : 'process'
)
const rows = ref<EventRecord[]>([]),
  cursors = ref([0]),
  busy = ref(false),
  error = ref(''),
  success = ref(''),
  detail = ref<EventRecord | null>(null)
const hasNext = ref(false),
  search = ref(''),
  unread = ref(false)
const visibleRows = computed(() =>
  rows.value.filter(
    (row) =>
      (!unread.value || row.status === 0) &&
      JSON.stringify(row).toLowerCase().includes(search.value.toLowerCase())
  )
)
let generation = 0
async function load() {
  const ticket = ++generation
  busy.value = true
  error.value = ''
  try {
    const data = await api<EventRecord[] | null>(`/${module.value}/listEvents`, {
      limit: 26,
      offset: cursors.value[cursors.value.length - 1]
    })
    if (ticket !== generation) return
    rows.value = (data || []).slice(0, 25)
    hasNext.value = (data || []).length > 25
  } catch (e) {
    if (ticket === generation) {
      error.value = errorMessage(e)
      rows.value = []
    }
  } finally {
    if (ticket === generation) busy.value = false
  }
}
watch(
  module,
  () => {
    rows.value = []
    cursors.value = [0]
    success.value = ''
    detail.value = null
    search.value = ''
    unread.value = false
    load()
  },
  { immediate: true }
)
async function update(row: EventRecord, status: number) {
  if (
    module.value === 'process' &&
    status === 1 &&
    !window.confirm(t(t('将此命令设为不信任？在防御模式下可能阻止其执行。')))
  )
    return
  busy.value = true
  success.value = ''
  error.value = ''
  try {
    await api(`/${module.value}/updateEventStatus`, { id: row.id, status })
    success.value = module.value === 'process' ? '命令信任策略已更新' : '事件状态已更新'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function remove(row: EventRecord) {
  if (!window.confirm(t(t('确定删除这条事件记录？此操作无法撤销。')))) return
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api(`/${module.value}/${module.value === 'process' ? 'deleteEvents' : 'deleteEvent'}`, {
      id: row.id
    })
    success.value = '事件已删除'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
function next() {
  if (rows.value.length) cursors.value.push(rows.value[rows.value.length - 1].id)
  load()
}
function previous() {
  cursors.value.pop()
  load()
}
const detailFields: Record<string, string> = {
  id: '事件编号',
  status: '处理状态',
  workdir: '工作目录',
  binary: '可执行文件',
  argv: '命令参数',
  count: '累计次数',
  judge: '判定模式',
  path: '文件路径',
  perm: '防护与审计',
  timestamp: '发生时间',
  saddr: '源地址',
  daddr: '目标地址',
  sport: '源端口',
  dport: '目标端口',
  protocol: '协议编号',
  policy: '命中策略编号'
}
function detailValue(key: string, value: unknown) {
  if (key === 'timestamp') return formatTime(Number(value))
  if (key === 'perm') return permissionsText(Number(value))
  if (key === 'status')
    return t(
      (module.value === 'process' ? ['待处理', '不信任', '信任'] : ['未读', '已读'])[
        Number(value)
      ] || '未知'
    )
  if (key === 'judge') return t(['关闭判定', '审计', '防御'][Number(value)] || '未知')
  return value
}
const dialog = useDialog(
  () => !!detail.value,
  () => {
    detail.value = null
  }
)
</script>
<template>
  <div class="toolbar">
    <div class="inline">
      <input
        v-model="search"
        type="search"
        :placeholder="t('筛选当前页记录…')"
        :aria-label="t('筛选当前页记录')"
      /><label class="check"><input v-model="unread" type="checkbox" />{{ t('仅待处理') }}</label>
    </div>
    <button :disabled="busy" @click="load">{{ t('刷新事件') }}</button>
  </div>
  <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
  <p v-if="success" class="notice success" role="status">{{ t(success) }}</p>
  <section class="panel table-panel">
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>{{ t('ID / 状态') }}</th>
            <th>
              {{ module === 'process' ? t('命令') : module === 'file' ? t('文件') : t('网络连接') }}
            </th>
            <th>
              {{ module === 'process' ? t('执行信息') : t('事件信息') }}
            </th>
            <th>{{ t('操作') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="row in visibleRows" :key="row.id">
            <td>
              <span class="mono">#{{ row.id }}</span
              ><br /><span class="pill" :class="row.status === 0 ? 'warning' : 'neutral'">{{
                module === 'process'
                  ? [t('待处理'), t('不信任'), t('信任')][row.status]
                  : [t('未读'), t('已读')][row.status]
              }}</span>
            </td>
            <td class="wide-cell">
              <strong>{{
                row.binary || row.path || `${row.saddr}:${row.sport} → ${row.daddr}:${row.dport}`
              }}</strong>
              <div class="muted mono wrap">
                {{
                  module === 'process'
                    ? row.argv
                    : module === 'file'
                    ? permissionsText(row.perm || 0)
                    : t('协议 {p0} · 策略 #{p1}', {
                        p0: row.protocol,
                        p1: row.policy
                      })
                }}
              </div>
            </td>
            <td class="muted">
              {{
                module === 'process'
                  ? t('累计 {p0} 次 · {p1}', {
                      p0: row.count,
                      p1: [t('关闭判定'), t('审计'), t('防御')][row.judge || 0]
                    })
                  : formatTime(row.timestamp)
              }}
            </td>
            <td>
              <div class="row-actions">
                <button @click="detail = row">{{ t('详情') }}</button
                ><template v-if="module === 'process'"
                  ><button :disabled="busy || row.status === 2" @click="update(row, 2)">
                    {{ t('信任') }}</button
                  ><button :disabled="busy || row.status === 1" @click="update(row, 1)">
                    {{ t('不信任') }}
                  </button></template
                ><button v-else :disabled="busy" @click="update(row, row.status === 0 ? 1 : 0)">
                  {{ row.status === 0 ? t('标记已读') : t('标记未读') }}</button
                ><button
                  class="danger-text"
                  :disabled="busy || (module === 'process' && row.status === 2)"
                  :title="
                    module === 'process' && row.status === 2
                      ? t('请先取消信任，避免删除生效中的策略')
                      : ''
                  "
                  @click="remove(row)"
                >
                  {{ t('删除') }}
                </button>
              </div>
            </td>
          </tr>
          <tr v-if="!visibleRows.length">
            <td colspan="4" class="empty">
              {{
                busy
                  ? t('正在加载事件…')
                  : error
                  ? t('加载失败，请重试')
                  : t('当前没有符合条件的事件')
              }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div class="pagination">
      <span>{{
        t('第 {page} 页 · 当前页 {count} 条 · 按 ID 递增', {
          page: cursors.length,
          count: rows.length
        })
      }}</span>
      <div>
        <button :disabled="busy || cursors.length === 1" @click="previous">{{ t('上一页') }}</button
        ><button :disabled="busy || !hasNext" @click="next">{{ t('下一页') }}</button>
      </div>
    </div>
  </section>
  <div
    v-if="detail"
    class="modal-backdrop"
    @click.self="detail = null"
    @keydown.esc="detail = null"
  >
    <section
      class="modal"
      ref="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="event-detail"
    >
      <div class="section-heading">
        <h2 id="event-detail">{{ t('事件 #{id}', { id: detail.id }) }}</h2>
        <button autofocus @click="detail = null">{{ t('关闭') }}</button>
      </div>
      <dl class="detail-list">
        <template v-for="(value, key) in detail" :key="key"
          ><dt>{{ t(detailFields[key] || key) }}</dt>
          <dd>{{ detailValue(key, value) }}</dd></template
        >
      </dl>
    </section>
  </div>
</template>
