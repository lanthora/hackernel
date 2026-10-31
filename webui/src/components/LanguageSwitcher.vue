<script setup lang="ts">
import { locale, setLocale, t } from '../lib/i18n'
function change(event: Event) {
  setLocale((event.target as HTMLSelectElement).value)
}
</script>
<template>
  <label class="language-switcher"
    ><span>{{ t('语言') }}</span
    ><select :value="locale" :aria-label="t('语言')" @change="change">
      <option value="zh-CN" lang="zh-CN">简体中文</option>
      <option value="en" lang="en">English</option>
    </select></label
  >
</template>
