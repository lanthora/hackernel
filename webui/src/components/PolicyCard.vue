<template>
  <div class="process-card">
    <div class="process-header">{{ title }}</div>
    <div class="process-body">
      <p class="process-text">当前状态: {{ status }}</p>
      <p class="process-text">当前策略数: {{ policyCount }}</p>
      <p class="process-text">未读事件数: {{ unreadCount }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";

// define the props object to receive the parameters
const props = defineProps({
  title: String,
  status: String,
  policyCount: Number,
  unreadCount: Number
});

// use the props to initialize the data
const title = ref(props.title);
const policyCount = ref(props.policyCount);
const unreadCount = ref(props.unreadCount);
const status = ref(props.status);

</script>

<style scoped>
.process-card {
  border: 1px solid #0099ff;
  margin: 1rem;
}

.process-header {
  background-color: #0099ff;
  color: white;
  padding: 0.5rem;
}

.process-body {
  padding: 0.5rem;
}

.process-text {
  margin: 0;
}

</style>
