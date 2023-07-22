<template>
  <div>
    <form @submit.prevent="login" class="form">
      <div class="input-group">
        <label for="username">用户名:</label>
        <input type="text" id="username" v-model="username" required>
      </div>
      <div class="input-group">
        <label for="password">密码:</label>
        <input type="password" id="password" v-model="password" required>
      </div>
      <div class="button-group">
        <button type="submit">登录</button>
      </div>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const username = ref('')
const password = ref('')

const login = () => {
  // 这里可以写登录的逻辑，比如发送请求到后端验证用户名和密码
  alert(`欢迎 ${username.value} 登录!`)
}
</script>

<style scoped>

.form {
  width: 400px;
  margin: auto;
  border: 1px solid #ccc;
  padding: 20px;
  box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

.input-group {
  margin: 10px 0;
}

.input-group label {
  display: block;
  font-weight: bold;
}

.input-group input {
  width: 100%;
  padding: 10px;
  border: 1px solid #ccc;
  outline: none;
}

.button-group {
  text-align: center;
}

.button-group button {
  padding: 10px 20px;
  background: #0099ff;
  color: white;
  border: none;
  cursor: pointer;
}
</style>
