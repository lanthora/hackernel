<script setup lang="ts">
import { t } from '../lib/i18n'

import FilePicker from './FilePicker.vue'
import { useDialog } from '../lib/dialog'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  api,
  errorMessage,
  modules,
  permissionBits,
  permissionsText,
  type Module,
  type FilePolicy,
  type NetPolicy
} from '../lib/api'
const route = useRoute(),
  router = useRouter()
const module = computed<Module>(() =>
  modules.some((m) => m.id === route.query.module) ? (route.query.module as Module) : 'file'
)
const fileRows = ref<FilePolicy[]>([]),
  netRows = ref<NetPolicy[]>([]),
  cursors = ref([0]),
  hasNext = ref(false)
const error = ref(''),
  success = ref(''),
  busy = ref(false),
  showForm = ref(false),
  editing = ref<number | null>(null)
const path = ref(''),
  selectedBits = ref<number[]>([1, 2, 3])
function newNet(): NetPolicy {
  return {
    priority: 0,
    addr: {
      src: { begin: '0.0.0.0', end: '255.255.255.255' },
      dst: { begin: '0.0.0.0', end: '255.255.255.255' }
    },
    protocol: { begin: 0, end: 255 },
    port: { src: { begin: 0, end: 65535 }, dst: { begin: 0, end: 65535 } },
    flags: 3,
    response: 3
  }
}
const net = ref<NetPolicy>(newNet())
let generation = 0
async function load() {
  if (module.value === 'process') return
  const ticket = ++generation
  busy.value = true
  error.value = ''
  try {
    const data = await api<(FilePolicy | NetPolicy)[] | null>(`/${module.value}/listPolicies`, {
      limit: 26,
      offset: cursors.value[cursors.value.length - 1]
    })
    if (ticket !== generation) return
    hasNext.value = (data || []).length > 25
    if (module.value === 'file') fileRows.value = (data || []).slice(0, 25) as FilePolicy[]
    else netRows.value = (data || []).slice(0, 25) as NetPolicy[]
  } catch (e) {
    if (ticket === generation) {
      error.value = errorMessage(e)
      fileRows.value = []
      netRows.value = []
    }
  } finally {
    if (ticket === generation) busy.value = false
  }
}
watch(
  module,
  () => {
    generation++
    showForm.value = false
    cursors.value = [0]
    success.value = ''
    load()
  },
  { immediate: true }
)
function openForm(policy?: FilePolicy) {
  error.value = ''
  editing.value = policy?.id ?? null
  path.value = policy?.path || ''
  selectedBits.value = policy
    ? permissionBits.map((_, i) => i).filter((i) => policy.perm & (1 << i))
    : [1, 2, 3]
  net.value = newNet()
  showForm.value = true
}
async function save() {
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    if (module.value === 'file') {
      const perm = selectedBits.value.reduce((mask, bit) => mask | (1 << bit), 0)
      if (!path.value) throw new Error('请先选择文件或目录')
      if (!perm) throw new Error('请至少选择一项防护或审计操作')
      await api(
        `/file/${editing.value ? 'updatePolicy' : 'addPolicy'}`,
        editing.value ? { id: editing.value, perm } : { path: path.value, perm }
      )
    } else {
      if (!window.confirm(t(t('应用此网络规则？请确认规则不会阻断当前管理连接。')))) return
      await api('/net/addPolicy', net.value)
    }
    showForm.value = false
    success.value = '策略已应用并保存'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function remove(id: number) {
  if (!window.confirm(t(t('确定移除此防护策略？')))) return
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api(`/${module.value}/deletePolicy`, { id })
    success.value = '策略已移除'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function clearFiles() {
  if (!window.confirm(t(t('确定清空全部文件防护策略？所有文件保护规则将被移除。')))) return
  busy.value = true
  error.value = ''
  try {
    await api('/file/clearPolicies')
    cursors.value = [0]
    success.value = '文件策略已清空'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
function next() {
  const list = module.value === 'file' ? fileRows.value : netRows.value
  if (list.length) cursors.value.push(list[list.length - 1].id!)
  load()
}
function previous() {
  cursors.value.pop()
  load()
}
const dialog = useDialog(
  () => showForm.value,
  () => {
    if (!busy.value) showForm.value = false
  }
)
</script>
<template>
  <div class="tabs">
    <button
      v-for="m in modules"
      :key="m.id"
      :class="{ active: module === m.id }"
      :disabled="busy"
      @click="router.replace({ query: { module: m.id } })"
    >
      {{ t(m.name) }}
    </button>
  </div>
  <section v-if="module === 'process'" class="panel explanation">
    <h2>{{ t('命令信任策略') }}</h2>
    <p class="muted">
      {{
        t(
          '进程策略由执行记录生成，按工作目录、可执行文件和参数匹配。前往进程事件列表，将命令设为信任或不信任；在系统设置中选择审计或防御模式。'
        )
      }}
    </p>
    <RouterLink class="button primary" to="/events?module=process">{{
      t('管理命令信任 →')
    }}</RouterLink>
  </section>
  <template v-else
    ><div class="toolbar">
      <p class="muted">
        {{
          module === 'file'
            ? t('选择主机上的文件或目录，设置防护与审计操作。')
            : t('IPv4 范围匹配；优先级数值越小，匹配优先级越高。')
        }}
      </p>
      <div class="inline">
        <button :disabled="busy" @click="load">{{ t('刷新') }}</button
        ><button v-if="module === 'file'" :disabled="busy" @click="clearFiles">
          {{ t('清空策略') }}</button
        ><button class="primary" :disabled="busy" @click="openForm()">
          {{ t('＋ 添加策略') }}
        </button>
      </div>
    </div>
    <p v-if="error && !showForm" class="notice error" role="alert">{{ t(error) }}</p>
    <p v-if="success" class="notice success" role="status">{{ t(success) }}</p>
    <section class="panel table-panel">
      <div class="table-scroll">
        <table v-if="module === 'file'">
          <thead>
            <tr>
              <th>ID</th>
              <th>{{ t('文件路径') }}</th>
              <th>{{ t('防护与审计') }}</th>
              <th>{{ t('状态') }}</th>
              <th>{{ t('操作') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in fileRows" :key="row.id">
              <td>#{{ row.id }}</td>
              <td class="mono wrap">{{ row.path }}</td>
              <td>{{ permissionsText(row.perm) }}</td>
              <td>
                <span class="pill" :class="row.status === 0 ? 'success' : 'warning'">{{
                  [t('正常'), t('未知'), t('冲突'), t('文件不存在')][row.status] || t('未知')
                }}</span>
              </td>
              <td>
                <div class="row-actions">
                  <button :disabled="busy" @click="openForm(row)">{{ t('编辑') }}</button
                  ><button class="danger-text" :disabled="busy" @click="remove(row.id)">
                    {{ t('删除') }}
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="!fileRows.length">
              <td colspan="5" class="empty">
                {{ busy ? t('正在加载…') : error ? t('加载失败，请重试') : t('暂无文件策略') }}
              </td>
            </tr>
          </tbody>
        </table>
        <table v-else>
          <thead>
            <tr>
              <th>{{ t('ID / 优先级') }}</th>
              <th>{{ t('地址范围') }}</th>
              <th>{{ t('协议 / 端口') }}</th>
              <th>{{ t('匹配 / 动作') }}</th>
              <th>{{ t('操作') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in netRows" :key="row.id">
              <td>
                #{{ row.id }}<br /><span class="muted">{{ t('优先级') }} {{ row.priority }}</span>
              </td>
              <td class="mono">
                {{ t('源') }} {{ row.addr.src.begin }} – {{ row.addr.src.end }}<br />{{
                  t('目标')
                }}
                {{ row.addr.dst.begin }} – {{ row.addr.dst.end }}
              </td>
              <td>
                {{ t('协议') }} {{ row.protocol.begin }} – {{ row.protocol.end }}<br /><span
                  class="muted"
                  >{{ t('源端口') }} {{ row.port.src.begin }}–{{ row.port.src.end }}<br />{{
                    t('目标端口')
                  }}
                  {{ row.port.dst.begin }}–{{ row.port.dst.end }}</span
                >
              </td>
              <td>
                {{ row.flags & 1 ? t('入站 ') : '' }}{{ row.flags & 2 ? t('出站 ') : ''
                }}{{ row.flags & 4 ? t('握手包 ') : '' }}{{ row.flags & 8 ? t('无数据包') : ''
                }}<br /><span class="pill" :class="row.response & 1 ? 'success' : 'warning'"
                  >{{ row.response & 1 ? t('放行') : t('阻止')
                  }}{{ row.response & 2 ? t(' · 记录日志') : '' }}</span
                >
              </td>
              <td>
                <button class="danger-text" :disabled="busy" @click="remove(row.id!)">
                  {{ t('删除') }}
                </button>
              </td>
            </tr>
            <tr v-if="!netRows.length">
              <td colspan="5" class="empty">
                {{ busy ? t('正在加载…') : error ? t('加载失败，请重试') : t('暂无网络策略') }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="pagination">
        <span>{{ t('第 {page} 页 · 每页最多 25 条', { page: cursors.length }) }}</span>
        <div>
          <button :disabled="busy || cursors.length === 1" @click="previous">
            {{ t('上一页') }}</button
          ><button :disabled="busy || !hasNext" @click="next">{{ t('下一页') }}</button>
        </div>
      </div>
    </section>
  </template>
  <div v-if="showForm" class="modal-backdrop" @click.self="!busy && (showForm = false)">
    <section
      class="modal"
      ref="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="policy-title"
    >
      <div class="section-heading">
        <h2 id="policy-title">
          {{ t(module === 'file' ? (editing ? '编辑文件策略' : '添加文件策略') : '添加网络策略') }}
        </h2>
        <button :disabled="busy" @click="showForm = false">{{ t('关闭') }}</button>
      </div>
      <form @submit.prevent="save">
        <template v-if="module === 'file'">
          <div v-if="editing !== null" class="file-picker-selection">
            <span class="muted">{{ t('防护目标') }}</span
            ><strong class="mono wrap">{{ path }}</strong>
          </div>
          <FilePicker v-else v-model="path" :disabled="busy" />
          <fieldset>
            <legend>{{ t('防护与审计操作') }}</legend>
            <div class="checkbox-grid">
              <label v-for="(label, bit) in permissionBits" :key="bit" class="check"
                ><input v-model="selectedBits" type="checkbox" :value="bit" />{{ t(label) }}</label
              >
            </div>
          </fieldset>
          <p class="muted">{{ t('禁止操作可能影响系统服务，请谨慎选择。') }}</p></template
        >
        <template v-else
          ><div class="form-grid">
            <label
              >{{ t('优先级')
              }}<input
                v-model.number="net.priority"
                type="number"
                min="-128"
                max="127"
                required /></label
            ><label
              >{{ t('流量方向')
              }}<select v-model.number="net.flags">
                <option :value="1">{{ t('入站') }}</option>
                <option :value="2">{{ t('出站') }}</option>
                <option :value="3">{{ t('入站与出站') }}</option>
                <option :value="5">{{ t('入站 TCP 握手') }}</option>
                <option :value="6">{{ t('出站 TCP 握手') }}</option>
                <option :value="7">{{ t('双向 TCP 握手') }}</option>
                <option :value="9">{{ t('入站 TCP 无数据') }}</option>
                <option :value="10">{{ t('出站 TCP 无数据') }}</option>
                <option :value="11">{{ t('双向 TCP 无数据') }}</option>
              </select></label
            >
          </div>
          <fieldset v-for="side in (['src', 'dst'] as const)" :key="side">
            <legend>{{ t(side === 'src' ? '源地址与端口' : '目标地址与端口') }}</legend>
            <div class="form-grid">
              <label
                >{{ t('起始 IPv4') }}<input v-model.trim="net.addr[side].begin" required /></label
              ><label
                >{{ t('结束 IPv4') }}<input v-model.trim="net.addr[side].end" required /></label
              ><label
                >{{ t('起始端口')
                }}<input
                  v-model.number="net.port[side].begin"
                  type="number"
                  min="0"
                  max="65535"
                  required /></label
              ><label
                >{{ t('结束端口')
                }}<input
                  v-model.number="net.port[side].end"
                  type="number"
                  :min="net.port[side].begin"
                  max="65535"
                  required
              /></label>
            </div>
          </fieldset>
          <div class="form-grid">
            <label
              >{{ t('协议起始编号')
              }}<input
                v-model.number="net.protocol.begin"
                type="number"
                min="0"
                max="255"
                required /></label
            ><label
              >{{ t('协议结束编号')
              }}<input
                v-model.number="net.protocol.end"
                type="number"
                :min="net.protocol.begin"
                max="255"
                required /></label
            ><label
              >{{ t('匹配后的动作')
              }}<select v-model.number="net.response">
                <option :value="3">{{ t('放行并记录日志') }}</option>
                <option :value="2">{{ t('阻止并记录日志') }}</option>
                <option :value="1">{{ t('放行') }}</option>
                <option :value="0">{{ t('阻止') }}</option>
              </select></label
            >
          </div>
          <p class="muted">
            {{ t('协议编号：ICMP = 1，TCP = 6，UDP = 17；0–255 匹配全部协议。范围包含两端。') }}
          </p></template
        >
        <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
        <div class="form-actions">
          <button type="button" :disabled="busy" @click="showForm = false">{{ t('取消') }}</button
          ><button class="primary" :disabled="busy || (module === 'file' && !path)">
            {{ busy ? t('正在应用…') : t('应用策略') }}
          </button>
        </div>
      </form>
    </section>
  </div>
</template>
