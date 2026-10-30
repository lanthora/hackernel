import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: Object.fromEntries(
      ['/auth', '/admin', '/ctrl', '/process', '/file', '/net'].map((path) => [
        path,
        { target: process.env.HACKERNEL_API || 'http://127.0.0.1:8080', changeOrigin: false }
      ])
    )
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
