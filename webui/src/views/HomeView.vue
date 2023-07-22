<template>
  <div>
    <div class="flex-container">
      <PolicyCard v-bind="procInfo"></PolicyCard>
      <PolicyCard v-bind="fileInfo"></PolicyCard>
      <PolicyCard v-bind="netInfo"></PolicyCard>
    </div>
  </div>
</template>

<script setup lang="ts">
import PolicyCard from '../components/PolicyCard.vue'; 

const procInfo = {
  title: "进程防护",
  status: "启用",
  policyCount: 1,
  unreadCount: 2
};

const fileInfo = {
  title: "文件防护",
  status: "启用",
  policyCount: 1,
  unreadCount: 2
};

const netInfo = {
  title: "网络防护",
  status: "启用",
  policyCount: 1,
  unreadCount: 2
};

</script>

<style scoped>
.flex-container {
  display: flex;
  flex-direction: row;
  justify-content: space-around;
  align-items: center;
}
</style>
