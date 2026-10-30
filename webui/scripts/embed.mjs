import { access, cp, mkdir, readdir, rm } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
const source = new URL('../dist/', import.meta.url)
const target = new URL('../../apps/internal/web/webui/', import.meta.url)
await access(new URL('index.html', source))
await mkdir(target, { recursive: true })
for (const name of await readdir(target)) {
  if (name !== '.gitkeep') await rm(new URL(name, target), { recursive: true, force: true })
}
await cp(source, target, { recursive: true })
console.log(`Frontend assets prepared for go:embed: ${fileURLToPath(target)}`)
