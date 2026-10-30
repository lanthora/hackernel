export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}
export async function api<T = void>(path: string, body: unknown = {}): Promise<T> {
  const controller = new AbortController()
  const timeout = window.setTimeout(() => controller.abort(), 15000)
  try {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    })
    if (!response.ok) throw new Error(`服务请求失败（HTTP ${response.status}）`)
    const result = await response.json()
    if (result.status !== 0) {
      if (result.status === 100) window.dispatchEvent(new Event('session-expired'))
      throw new ApiError(result.status, result.message || '操作失败')
    }
    return result.data as T
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError')
      throw new Error('请求超时，请检查服务连接后重试')
    if (error instanceof TypeError) throw new Error('无法连接管理服务，请检查网络或服务状态')
    throw error
  } finally {
    window.clearTimeout(timeout)
  }
}
export const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : '操作失败'
export type Module = 'process' | 'file' | 'net'
export const modules: { id: Module; name: string; description: string }[] = [
  { id: 'process', name: '进程防护', description: '管理命令信任与执行模式' },
  { id: 'file', name: '文件防护', description: '保护关键文件与目录' },
  { id: 'net', name: '网络防护', description: '管理主机网络访问规则' }
]
export interface User {
  userID: number
  username: string
  aliasName: string
  permissions: string
}
export interface ModuleStatus {
  status: number
  policyCount: number
  unreadEventCount: number
}
export interface CoreStatus {
  coreOnline: boolean
  debugEnabled: boolean
}
export interface EventRecord {
  id: number
  status: number
  workdir?: string
  binary?: string
  argv?: string
  count?: number
  judge?: number
  path?: string
  perm?: number
  timestamp?: number
  saddr?: string
  daddr?: string
  sport?: number
  dport?: number
  protocol?: number
  policy?: number
}
export interface FilePolicy {
  id: number
  path: string
  perm: number
  status: number
  timestamp: number
}
export interface Range<T> {
  begin: T
  end: T
}
export interface NetPolicy {
  id?: number
  priority: number
  addr: { src: Range<string>; dst: Range<string> }
  protocol: Range<number>
  port: { src: Range<number>; dst: Range<number> }
  flags: number
  response: number
}
export const permissionBits = [
  '禁止读',
  '禁止写',
  '禁止删除',
  '禁止重命名',
  '审计读',
  '审计写',
  '审计删除',
  '审计重命名'
]
export const permissionsText = (perm: number) =>
  permissionBits.filter((_, bit) => perm & (1 << bit)).join('、') || '无'
export const formatTime = (timestamp?: number) =>
  timestamp ? new Date(timestamp * 1000).toLocaleString('zh-CN', { hour12: false }) : '—'
