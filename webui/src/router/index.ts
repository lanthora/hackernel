import { createRouter, createWebHistory } from 'vue-router'
import LoginView from '../views/LoginView.vue'
import ConsoleView from '../views/ConsoleView.vue'
import { currentUser, loadSession } from '../lib/session'
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  scrollBehavior(to, _from, saved) {
    if (saved) return saved
    return to.hash ? { el: to.hash, top: 24 } : { top: 0 }
  },
  routes: [
    { path: '/', redirect: '/overview' },
    { path: '/home', redirect: '/overview' },
    { path: '/login', component: LoginView },
    { path: '/:page(overview|events|policies|settings|users)', component: ConsoleView },
    { path: '/protection/:module(process|file|net)', component: ConsoleView },
    { path: '/:pathMatch(.*)*', redirect: '/overview' }
  ]
})
router.beforeEach(async (to) => {
  if (to.path === '/login') return true
  try {
    if (!currentUser.value) await loadSession()
  } catch {
    return { path: '/login', query: { unavailable: '1' } }
  }
  if (!currentUser.value) return { path: '/login', query: { redirect: to.fullPath } }
})
window.addEventListener('session-expired', () => {
  currentUser.value = null
  if (router.currentRoute.value.path !== '/login') router.replace('/login')
})
export default router
