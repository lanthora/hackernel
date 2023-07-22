<template>
  <div>
    <div class="circle"></div>
  </div>
</template>

<script setup lang="ts">
// 这里可以写你的 TypeScript 代码
</script>

<style>
.circle {
  width: 50px;
  height: 50px;
  border: 10px solid #eee;
  border-top-color: #0099ff;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
</style>
