import { ref } from 'vue'
import { api, ApiError, type User } from './api'
export const currentUser = ref<User | null>(null)
export async function loadSession() {
  try {
    currentUser.value = await api<User>('/auth/showCurrentUserInfo')
  } catch (error) {
    currentUser.value = null
    if (!(error instanceof ApiError && error.status === 100)) throw error
  }
  return currentUser.value
}
