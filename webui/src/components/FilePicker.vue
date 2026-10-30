<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { api, errorMessage } from '../lib/api'
interface Entry {
  name: string
  path: string
  directory: boolean
  symlink: boolean
  selectable: boolean
}
interface Directory {
  path: string
  parent: string
  entries: Entry[]
  nextCursor: string
}
defineProps<{ modelValue: string; disabled?: boolean }>()
const emit = defineEmits<{ (event: 'update:modelValue', value: string): void }>()
const directory = ref<Directory | null>(null),
  busy = ref(false),
  error = ref(''),
  search = ref('')
const cursors = ref([''])
let generation = 0
async function load(path: string, after = '') {
  const ticket = ++generation
  busy.value = true
  error.value = ''
  try {
    const result = await api<Directory>('/file/browse', { path, after, search: search.value })
    if (ticket === generation) directory.value = result
  } catch (e) {
    if (ticket === generation) error.value = errorMessage(e)
  } finally {
    if (ticket === generation) busy.value = false
  }
}
function navigate(path: string) {
  cursors.value = ['']
  search.value = ''
  load(path)
}
function filter() {
  cursors.value = ['']
  load(directory.value?.path || '/')
}
function next() {
  if (!directory.value?.nextCursor) return
  cursors.value.push(directory.value.nextCursor)
  load(directory.value.path, directory.value.nextCursor)
}
function previous() {
  cursors.value.pop()
  load(directory.value?.path || '/', cursors.value[cursors.value.length - 1])
}
function choose(path: string) {
  emit('update:modelValue', path)
}
onMounted(() => {
  navigate('/')
})
onUnmounted(() => {
  generation++
})
</script>
<template>
  <section class="file-picker" aria-label="选择被管理主机上的文件或目录">
    <p class="muted">从被管理主机的文件系统中选择文件或目录。</p>
    <div class="file-picker-location">
      <span class="mono wrap">{{ directory?.path || '/' }}</span
      ><button
        type="button"
        :disabled="busy || disabled || !directory || directory.path === directory.parent"
        @click="navigate(directory!.parent)"
      >
        上一级
      </button>
    </div>
    <div class="file-picker-search">
      <input
        v-model="search"
        type="search"
        aria-label="筛选目录中的名称"
        placeholder="按名称筛选当前目录"
        :disabled="busy || disabled"
        @keydown.enter.prevent="filter"
      /><button type="button" :disabled="busy || disabled" @click="filter">查找</button
      ><button
        type="button"
        :disabled="busy || disabled || !directory"
        @click="choose(directory!.path)"
      >
        选择当前目录
      </button>
    </div>
    <p v-if="error" class="notice error" role="alert">
      {{ error }}
      <button type="button" :disabled="busy || disabled" @click="load(directory?.path || '/')">
        重试
      </button>
    </p>
    <div class="file-picker-entries" :aria-busy="busy">
      <p v-if="busy" class="empty">正在读取目录…</p>
      <template v-else-if="directory && !error"
        ><div
          v-for="entry in directory.entries"
          :key="entry.name"
          class="file-picker-entry"
          :class="{ selected: modelValue === entry.path }"
        >
          <div class="file-picker-name">
            <button
              v-if="entry.directory"
              type="button"
              class="text-button"
              :disabled="disabled"
              @click="navigate(entry.path)"
            >
              {{ entry.name }}/</button
            ><span v-else class="mono wrap">{{ entry.name }}</span
            ><small class="muted">{{
              entry.symlink
                ? '符号链接'
                : entry.directory
                ? '目录'
                : entry.selectable
                ? '文件'
                : '不可选择'
            }}</small>
          </div>
          <div class="inline">
            <button
              v-if="entry.directory"
              type="button"
              :disabled="disabled"
              @click="navigate(entry.path)"
            >
              打开</button
            ><button
              type="button"
              :disabled="disabled || !entry.selectable"
              :aria-label="'选择 ' + entry.name"
              @click="choose(entry.path)"
            >
              选择
            </button>
          </div>
        </div>
        <p v-if="!directory.entries.length" class="empty">
          {{ search ? '没有匹配的文件或目录' : '目录为空' }}
        </p></template
      >
    </div>
    <div class="pagination">
      <span>第 {{ cursors.length }} 页</span>
      <div>
        <button
          type="button"
          :disabled="busy || disabled || cursors.length === 1"
          @click="previous"
        >
          上一页</button
        ><button type="button" :disabled="busy || disabled || !directory?.nextCursor" @click="next">
          下一页
        </button>
      </div>
    </div>
    <div class="file-picker-selection">
      <span class="muted">已选择</span
      ><strong class="mono wrap">{{ modelValue || '尚未选择文件或目录' }}</strong>
    </div>
  </section>
</template>
