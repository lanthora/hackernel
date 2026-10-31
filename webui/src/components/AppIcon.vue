<script setup lang="ts">
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 18 })
const paths: Record<string, string[]> = {
  shield: ['M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z', 'm8 12 3 3 5-6'],
  process: ['M8 3v3m8-3v3M8 18v3m8-3v3M3 8h3m-3 8h3m12-8h3m-3 8h3', 'M6 6h12v12H6z', 'M9 9h6v6H9z'],
  file: ['M5 3h9l5 5v13H5V3Z', 'M14 3v6h5', 'M8 13h8m-8 4h6'],
  net: ['M8 7h8m-4 4v5m-6 0h12M6 16v2m12-2v2', 'M8 3h8v8H8zM3 18h6v3H3zM15 18h6v3h-6z'],
  events: ['M5 3h14v18H5z', 'M8 7h8m-8 5h8m-8 5h5'],
  settings: ['M4 7h16M4 17h16', 'M8 4v6m8 4v6'],
  users: [
    'M16 21v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2',
    'M9.5 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z',
    'M17 4a4 4 0 0 1 0 7m4 10v-2a4 4 0 0 0-3-3.87'
  ],
  refresh: ['M20 7v5h-5', 'M4 17v-5h5', 'M6 7a7 7 0 0 1 12-2l2 2M4 17l2 2a7 7 0 0 0 12-2'],
  arrow: ['M5 12h14m-5-5 5 5-5 5'],
  close: ['m6 6 12 12M6 18 18 6'],
  plus: ['M12 5v14M5 12h14'],
  grid: ['M4 4h5v5H4zM15 4h5v5h-5zM4 15h5v5H4zM15 15h5v5h-5z']
}
</script>
<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.6"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path v-for="(d, index) in paths[name] || paths.shield" :key="index" :d="d" />
  </svg>
</template>
