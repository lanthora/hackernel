import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { nextTick } from 'vue'
import { parse } from '@vue/compiler-sfc'
import { baseParse } from '@vue/compiler-dom'

const root = fileURLToPath(new URL('../', import.meta.url))
const require = createRequire(import.meta.url)
const english = JSON.parse(fs.readFileSync(path.join(root, 'src/lib/locales/en.json'), 'utf8'))
const source = fs.readFileSync(path.join(root, 'src/lib/i18n.ts'), 'utf8')
const javascript = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, esModuleInterop: true }
}).outputText
function runtime(language = 'zh-CN', saved, blocked = false) {
  const storage = new Map(saved ? [['hids.locale', saved]] : [])
  const document = {
    title: '',
    documentElement: { lang: '' },
    icon: '',
    querySelector() {
      return {
        setAttribute(_name, value) {
          document.icon = value
        }
      }
    }
  }
  const module = { exports: {} }
  vm.runInNewContext(javascript, {
    exports: module.exports,
    module,
    require: (name) => (name === './locales/en.json' ? english : require(name)),
    navigator: { language },
    document,
    localStorage: {
      getItem(key) {
        if (blocked) throw new Error('blocked')
        return storage.get(key)
      },
      setItem(key, value) {
        if (blocked) throw new Error('blocked')
        storage.set(key, value)
      }
    }
  })
  return { ...module.exports, storage, document }
}

test('Chinese product branding has no HIDS label; English uses HIDS', async () => {
  const app = runtime('zh-TW')
  assert.equal(app.t('product.name'), '主机入侵检测系统')
  assert.equal(app.document.title, '主机入侵检测系统')
  assert.equal(app.document.icon, '/favicon.svg')
  app.setLocale('en')
  await nextTick()
  assert.equal(app.t('product.name'), 'HIDS')
  assert.equal(app.document.documentElement.lang, 'en')
  assert.match(app.document.title, /HIDS/)
  assert.equal(app.document.icon, '/favicon-en.svg')
  assert.equal(app.storage.get('hids.locale'), 'en')
  app.setLocale('zh-CN')
  await nextTick()
  assert.doesNotMatch(app.document.title, /HIDS/)
})

test('saved preference overrides browser locale and storage failures are tolerated', () => {
  assert.equal(runtime('en-US', 'zh-CN').locale.value, 'zh-CN')
  assert.equal(runtime('fr-FR').locale.value, 'en')
  const app = runtime('zh-CN', undefined, true)
  app.setLocale('en')
  assert.equal(app.locale.value, 'en')
  app.setLocale('invalid')
  assert.equal(app.locale.value, 'en')
})

test('parameter interpolation preserves user data and permission expressions', () => {
  const app = runtime('en')
  assert.equal(app.t('第 {page} 页', { page: 3 }), 'Page 3')
  assert.equal(app.t('确定删除账户 {p0}？', { p0: '<user>中文' }), 'Delete account <user>中文?')
  assert.match(
    app.t(
      '使用 glob 表达式匹配接口路径。全部权限：{*}；只读示例：{/process/listEvents,/process/show*,/file/list*,/file/show*,/net/list*,/net/show*,/ctrl/status}。会话信息和退出登录始终可用。'
    ),
    /\{\*\}/
  )
  assert.equal(app.t('登录失败'), 'Sign-in failed')
  assert.equal(app.t('opaque API detail'), 'opaque API detail')
  assert.equal(app.t('constructor'), 'constructor')
})

test('all UI source messages and server errors have English translations', () => {
  const chinese = /[\u3400-\u9fff]/
  function inspectScript(code, filename) {
    const tree = ts.createSourceFile(filename, code, ts.ScriptTarget.Latest, true)
    function visit(node) {
      if (ts.isStringLiteral(node) && chinese.test(node.text))
        assert.ok(
          Object.hasOwn(english, node.text),
          `${filename}: missing English message ${node.text}`
        )
      ts.forEachChild(node, visit)
    }
    visit(tree)
  }
  for (const folder of ['components', 'views']) {
    for (const filename of fs
      .readdirSync(path.join(root, 'src', folder))
      .filter((name) => name.endsWith('.vue'))) {
      if (filename === 'LanguageSwitcher.vue') continue // The language names are intentionally endonyms.
      const { descriptor } = parse(
        fs.readFileSync(path.join(root, 'src', folder, filename), 'utf8')
      )
      inspectScript(descriptor.scriptSetup.content, filename)
      function inspect(node) {
        if (node.type === 2)
          assert.ok(
            !chinese.test(node.content),
            `${filename}: untranslated template text ${node.content}`
          )
        if (node.type === 5) inspectScript(`const value = (${node.content.content})`, filename)
        for (const prop of node.props || []) {
          if (prop.type === 6 && prop.value)
            assert.ok(!chinese.test(prop.value.content), `${filename}: untranslated attribute`)
          if (prop.type === 7 && prop.exp) inspectScript(prop.exp.content, filename)
        }
        for (const child of node.children || []) inspect(child)
      }
      inspect(baseParse(descriptor.template.content))
    }
  }
  inspectScript(fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8'), 'api.ts')
  const server = fs.readFileSync(path.join(root, '../apps/internal/web/render/render.go'), 'utf8')
  for (const match of server.matchAll(/"([^"\n]*[\u3400-\u9fff][^"\n]*)"/g))
    assert.ok(Object.hasOwn(english, match[1]), `Untranslated API error: ${match[1]}`)
})
