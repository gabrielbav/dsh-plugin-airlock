// Wrap the CommonJS browser build in the DSH client module loader factory:
// window.__ModuleLoader__.load({ id, factory(require) }) with the package name as id.
import { readFileSync, rmSync, writeFileSync } from 'node:fs'

const { name } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const raw = new URL('../lib/client.raw.cjs', import.meta.url)
const code = readFileSync(raw, 'utf8').replace(/\n\/\/# sourceMappingURL=.*$/m, '')
const wrapped = `window.__ModuleLoader__.load({ id: ${JSON.stringify(name)}, factory: (require) => {\nvar module = { exports: {} }; var exports = module.exports;\n${code}\nreturn module.exports; } });\n`
writeFileSync(new URL('../lib/client.js', import.meta.url), wrapped)
rmSync(raw)
rmSync(new URL('../lib/client.raw.cjs.map', import.meta.url), { force: true })
