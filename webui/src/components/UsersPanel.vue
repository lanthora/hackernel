<script setup lang="ts">
import { t } from '../lib/i18n'

import { useDialog } from '../lib/dialog'
import { onMounted, ref } from 'vue'
import { api, errorMessage, type User } from '../lib/api'
import { currentUser, loadSession } from '../lib/session'
const rows = ref<User[]>([]),
  busy = ref(false),
  error = ref(''),
  success = ref(''),
  showForm = ref(false)
const form = ref({ userID: 0, username: '', aliasName: '', password: '', permissions: '{*}' })
async function load() {
  busy.value = true
  error.value = ''
  try {
    rows.value = (await api<User[] | null>('/admin/listAllUsers')) || []
  } catch (e) {
    error.value = errorMessage(e)
    rows.value = []
  } finally {
    busy.value = false
  }
}
function open(user?: User) {
  form.value = {
    userID: user?.userID || 0,
    username: user?.username || '',
    aliasName: user?.aliasName || '',
    password: '',
    permissions: user?.permissions || '{*}'
  }
  error.value = ''
  showForm.value = true
}
async function save() {
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api(`/admin/${form.value.userID ? 'updateUserInfo' : 'addUser'}`, form.value)
    showForm.value = false
    form.value.password = ''
    success.value = '账户已保存'
    await loadSession()
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
async function remove(user: User) {
  if (!window.confirm(t(t('确定删除账户 {p0}？', { p0: user.username })))) return
  busy.value = true
  error.value = ''
  success.value = ''
  try {
    await api('/admin/deleteUser', { userID: user.userID })
    success.value = '账户已删除'
    await load()
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    busy.value = false
  }
}
onMounted(load)
const dialog = useDialog(
  () => showForm.value,
  () => {
    if (!busy.value) showForm.value = false
  }
)
</script>
<template>
  <div class="toolbar">
    <p class="muted">{{ t('管理控制台账户与接口访问权限。') }}</p>
    <div class="inline">
      <button :disabled="busy" @click="load">{{ t('刷新') }}</button
      ><button class="primary" :disabled="busy" @click="open()">{{ t('＋ 创建账户') }}</button>
    </div>
  </div>
  <p v-if="error && !showForm" class="notice error" role="alert">{{ t(error) }}</p>
  <p v-if="success" class="notice success" role="status">{{ t(success) }}</p>
  <section class="panel table-panel">
    <div class="table-scroll">
      <table>
        <thead>
          <tr>
            <th>{{ t('用户名') }}</th>
            <th>{{ t('显示名称') }}</th>
            <th>{{ t('权限表达式') }}</th>
            <th>{{ t('操作') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in rows" :key="user.userID">
            <td>
              <strong>{{ user.username }}</strong
              ><span v-if="user.userID === currentUser?.userID" class="pill neutral">{{
                t('当前账户')
              }}</span>
            </td>
            <td>{{ user.aliasName }}</td>
            <td class="mono wrap">{{ user.permissions }}</td>
            <td>
              <div class="row-actions">
                <button :disabled="busy" @click="open(user)">{{ t('编辑') }}</button
                ><button
                  class="danger-text"
                  :disabled="busy || user.userID === currentUser?.userID"
                  @click="remove(user)"
                >
                  {{ t('删除') }}
                </button>
              </div>
            </td>
          </tr>
          <tr v-if="!rows.length">
            <td colspan="4" class="empty">
              {{ busy ? t('正在加载账户…') : error ? t('无法加载账户') : t('暂无账户') }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
  <div v-if="showForm" class="modal-backdrop" @click.self="!busy && (showForm = false)">
    <section
      class="modal"
      ref="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="user-title"
    >
      <div class="section-heading">
        <h2 id="user-title">
          {{ form.userID ? t('编辑账户') : t('创建账户') }}
        </h2>
        <button :disabled="busy" @click="showForm = false">{{ t('关闭') }}</button>
      </div>
      <form @submit.prevent="save">
        <label
          >{{ t('用户名')
          }}<input
            v-model.trim="form.username"
            autocomplete="off"
            required
            maxlength="128" /></label
        ><label
          >{{ t('显示名称')
          }}<input v-model.trim="form.aliasName" required maxlength="128" /></label
        ><label
          >{{ form.userID ? t('新密码（编辑时必须重新设置）') : t('密码')
          }}<input
            v-model="form.password"
            type="password"
            autocomplete="new-password"
            required
            minlength="8"
            maxlength="72" /></label
        ><label
          >{{ t('权限表达式') }}<input v-model.trim="form.permissions" required placeholder="{*}"
        /></label>
        <p class="muted">
          {{
            t(
              '使用 glob 表达式匹配接口路径。全部权限：{*}；只读示例：{/process/listEvents,/process/show*,/file/list*,/file/show*,/net/list*,/net/show*,/ctrl/status}。会话信息和退出登录始终可用。'
            )
          }}
        </p>
        <p v-if="error" class="notice error" role="alert">{{ t(error) }}</p>
        <div class="form-actions">
          <button type="button" :disabled="busy" @click="showForm = false">{{ t('取消') }}</button
          ><button class="primary" :disabled="busy">
            {{ busy ? t('保存中…') : t('保存账户') }}
          </button>
        </div>
      </form>
    </section>
  </div>
</template>
