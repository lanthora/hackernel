import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'
import { createRequire } from 'node:module'
import ts from 'typescript'

const require = createRequire(import.meta.url)
const javascript = ts.transpileModule(
  fs.readFileSync(new URL('../src/lib/protection.ts', import.meta.url), 'utf8'),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true } }
).outputText
function setup() {
  const server = {
    coreOnline: true,
    modules: { process: 0, file: 0, net: 0 },
    mode: 0,
    defaultStatus: 0
  }
  const calls = [],
    overrides = new Map()
  let confirmation = true
  const api = async (path, body = {}) => {
    calls.push({ path, body })
    if (overrides.has(path)) return overrides.get(path)(body)
    if (path === '/ctrl/status') return { coreOnline: server.coreOnline, debugEnabled: false }
    if (path === '/process/showWorkMode') return { judge: server.mode }
    if (path === '/process/showDefaultEventStatus') return { status: server.defaultStatus }
    if (path === '/process/updateWorkMode') {
      server.mode = body.judge
      return
    }
    if (path === '/process/updateDefaultEventStatus') {
      server.defaultStatus = body.status
      return
    }
    const [, module, action] = path.split('/')
    if (action === 'showModuleStatus')
      return { status: server.modules[module], policyCount: 0, unreadEventCount: 0 }
    if (action === 'enableModule') {
      server.modules[module] = 1
      return
    }
    if (action === 'disableModule') {
      server.modules[module] = 0
      return
    }
    throw new Error(`Unexpected API ${path}`)
  }
  const module = { exports: {} }
  vm.runInNewContext(javascript, {
    exports: module.exports,
    module,
    document: { hidden: false },
    setInterval,
    clearInterval,
    window: { confirm: () => confirmation },
    require(name) {
      if (name === 'vue')
        return { ...require('vue'), inject: () => null, onMounted() {}, onUnmounted() {} }
      if (name === './i18n') return { t: (value) => String(value ?? ''), formatClock: () => '' }
      if (name === './api')
        return {
          api,
          errorMessage: (error) => error.message,
          modules: ['process', 'file', 'net'].map((id) => ({ id }))
        }
      if (name.endsWith('.vue')) return {}
      throw new Error(`Unexpected import ${name}`)
    }
  })
  const view = module.exports.useProtection()
  return {
    view,
    server,
    calls,
    overrides,
    confirm(value) {
      confirmation = value
    }
  }
}

test('module switches update only after successful server acknowledgement and retain state on failure', async () => {
  const app = setup()
  await app.view.refresh(true)
  let complete
  app.overrides.set(
    '/file/enableModule',
    () =>
      new Promise((resolve) => {
        complete = () => {
          app.server.modules.file = 1
          resolve()
        }
      })
  )
  const switching = app.view.toggle({ id: 'file', name: 'File protection' })
  assert.equal(app.view.pending.value, 'file')
  assert.equal(app.view.states.value.file.status, 0)
  complete()
  await switching
  assert.equal(app.view.states.value.file.status, 1)
  app.overrides.set('/file/disableModule', async () => {
    throw new Error('Core rejected operation')
  })
  await app.view.toggle({ id: 'file', name: 'File protection' })
  assert.equal(app.view.states.value.file.status, 1)
  assert.equal(app.view.feedback.file.error, 'Core rejected operation')
  assert.equal(app.view.pending.value, null)
})

test('polling preserves unsaved edits and reset uses the latest saved values', async () => {
  const app = setup()
  await app.view.refresh(true)
  app.view.mode.value = 2
  app.server.mode = 1
  await app.view.refresh(true)
  assert.equal(app.view.savedMode.value, 1)
  assert.equal(app.view.mode.value, 2)
  assert.equal(app.view.dirty.value, true)
  app.view.resetProcess()
  assert.equal(app.view.mode.value, 1)
  assert.equal(app.view.dirty.value, false)
})

test('saving process settings writes only changed fields and preserves failed edits for retry', async () => {
  const app = setup()
  await app.view.refresh(true)
  app.view.mode.value = 1
  app.view.defaultStatus.value = 2
  app.overrides.set('/process/updateDefaultEventStatus', async () => {
    throw new Error('Default status rejected')
  })
  await app.view.saveProcess()
  assert.equal(app.server.mode, 1)
  assert.equal(app.view.savedMode.value, 1)
  assert.equal(app.view.defaultStatus.value, 2)
  assert.equal(app.view.dirty.value, true)
  assert.equal(app.view.feedback.process.error, 'Default status rejected')
  app.overrides.delete('/process/updateDefaultEventStatus')
  const previousModeWrites = app.calls.filter(
    (call) => call.path === '/process/updateWorkMode'
  ).length
  await app.view.saveProcess()
  assert.equal(app.server.defaultStatus, 2)
  assert.equal(app.view.dirty.value, false)
  assert.equal(
    app.calls.filter((call) => call.path === '/process/updateWorkMode').length,
    previousModeWrites
  )
})

test('cancelled confirmations and disconnected core never issue control requests', async () => {
  const app = setup()
  app.server.modules.process = 1
  await app.view.refresh(true)
  app.confirm(false)
  await app.view.toggle({ id: 'process', name: 'Process protection' })
  app.view.mode.value = 2
  await app.view.saveProcess()
  assert.equal(
    app.calls.some(
      (call) => call.path === '/process/disableModule' || call.path === '/process/updateWorkMode'
    ),
    false
  )
  app.confirm(true)
  app.server.coreOnline = false
  await app.view.refresh(true)
  await app.view.toggle({ id: 'file', name: 'File protection' })
  await app.view.saveProcess()
  assert.equal(
    app.calls.some(
      (call) => call.path.includes('enableModule') || call.path.includes('updateWorkMode')
    ),
    false
  )
})

test('tile color represents enabled, disabled and unknown states without treating an offline core as enabled', async () => {
  const app = setup()
  await app.view.refresh(true)
  assert.equal(app.view.tileState('process'), 'disabled')
  app.server.modules.process = 1
  await app.view.refresh(true)
  assert.equal(app.view.tileState('process'), 'enabled')
  app.server.coreOnline = false
  await app.view.refresh(true)
  assert.equal(app.view.tileState('process'), 'unknown')
  app.server.coreOnline = true
  app.overrides.set('/file/showModuleStatus', async () => {
    throw new Error('Permission denied')
  })
  await app.view.refresh(true)
  assert.equal(app.view.tileState('file'), 'unknown')
})
