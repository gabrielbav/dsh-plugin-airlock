import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, expect, it } from 'vitest'
import { apply, Config, inject, name, type AirlockService } from '../src/host/index.ts'
import type { FetchRoute, HostContext, InstallGate } from '../src/host/dsh.ts'

let root: string
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'airlock-plugin-')) })
afterEach(async () => { await rm(root, { recursive: true, force: true }) })

/** Mount the plugin on a recording context. */
function mount() {
  const disposers: (() => void | Promise<void>)[] = []
  const gates: InstallGate[] = []
  const routes = new Map<string, FetchRoute>()
  const provided = new Map<string, unknown>()
  const ctx: HostContext = {
    pluginManager: { registerInstallGate: (gate) => { gates.push(gate); return () => { gates.splice(gates.indexOf(gate), 1) } } },
    profileContext: { dir: root },
    logger: { warn: () => {}, info: () => {} },
    reflect: { provide: (key, value) => { provided.set(key, value); return () => { provided.delete(key) } } },
    get: () => undefined,
    effect: (execute) => { disposers.push(execute()) },
    inject: (_names, callback) => {
      callback({ ...ctx, connection: { fetch: { register: (route) => { routes.set(route.path, route); return () => { routes.delete(route.path) } } } } })
    },
  }
  const validated = Config['~standard'].validate({ scanners: Object.fromEntries(['cisco-skill-scanner', 'skillscan', 'cisco-mcp-scanner', 'osv-scanner', 'trivy', 'gitleaks'].map(id => [id, { enabled: false }])) })
  if (!('value' in validated)) throw new Error('config refused')
  apply(ctx, validated.value)
  const call = async (endpoint: string, payload: unknown) => {
    const route = routes.get(`/api/airlock.${endpoint}`)
    if (route === undefined) throw new Error(`no route ${endpoint}`)
    const response = await route.fetch(new Request('http://host/api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ type: 'client-request', rpcId: 'r1', method: `airlock.${endpoint}`, payload }) }))
    return (await response.json() as { result: { ok: boolean; value?: unknown; error?: { message: string } } }).result
  }
  return { gates, routes, provided, call, dispose: async () => { for (const dispose of disposers.reverse()) await dispose() } }
}

it('exports a function plugin that needs the plugin manager and the profile', () => {
  expect(name).toBe('dsh-plugin-airlock')
  expect(inject).toEqual(['pluginManager', 'profileContext'])
})

it('registers its gate, routes and scanner registry, and removes them on disposal', async () => {
  const { gates, routes, provided, dispose } = mount()
  expect(gates.map(gate => gate.id)).toEqual(['dsh-plugin-airlock'])
  expect([...routes.keys()].sort()).toEqual(['installScanner', 'models', 'report', 'reports', 'saveSettings', 'scanners', 'settings'].map(item => `/api/airlock.${item}`))
  expect(provided.has('airlock')).toBe(true)
  await dispose()
  expect(gates).toEqual([])
  expect(routes.size).toBe(0)
  expect(provided.size).toBe(0)
})

it('saves validated settings as an owner-only file and refuses invalid ones', async () => {
  const { call } = mount()
  const saved = await call('saveSettings', { settings: { policy: { requireLlm: false, passScore: 80 } } })
  expect(saved).toMatchObject({ ok: true, value: { effective: { policy: { requireLlm: false, passScore: 80 } } } })
  expect((await stat(join(root, '.airlock', 'settings.json'))).mode & 0o777).toBe(0o600)
  expect(await call('saveSettings', { settings: { policy: { blockScore: 99 } } })).toMatchObject({ ok: false, error: { message: expect.stringMatching(/must not exceed/) } })
  expect(await call('settings', {})).toMatchObject({ ok: true, value: { settings: { policy: { passScore: 80 } } } })
  expect(await call('installScanner', { id: 'not-a-scanner' })).toMatchObject({ ok: false })
})

it('scans with plugin-registered scanners and the saved policy, and stores the report', async () => {
  const { gates, call, provided } = mount()
  await call('saveSettings', { settings: { policy: { requireLlm: false } } })
  const airlock = provided.get('airlock') as AirlockService
  const unregister = airlock.registerScanner({ id: 'house-rules', name: 'House rules', run: async () => ({ id: 'house-rules', status: 'clean', findings: [], durationMs: 0, usedLlm: false }) })
  expect(() => airlock.registerScanner({ id: 'trivy', name: 'x', run: async () => { throw new Error() } })).toThrow(/reserved/)
  const scanners = await call('scanners', {})
  expect(scanners).toMatchObject({ ok: true, value: expect.arrayContaining([expect.objectContaining({ id: 'house-rules', origin: 'plugin' })]) })
  const pkg = join(root, 'pkg')
  await mkdir(pkg)
  await writeFile(join(pkg, 'package.json'), '{"name":"pkg","version":"2.0.0"}')
  const verdict = await gates[0]!.vet({
    spec: pkg, registry: null, signal: new AbortController().signal, log: () => {},
    fetch: async (dir) => {
      await mkdir(join(dir, 'node_modules'), { recursive: true })
      await writeFile(join(dir, 'package.json'), '{"dependencies":{"pkg":"file:x"}}')
      return { exitCode: 0, output: '', packageDir: pkg }
    },
  })
  try {
    expect(verdict.report).toMatchObject({ level: 'pass', score: 100, packageName: 'pkg' })
    expect(JSON.parse(await readFile(join(root, '.airlock', 'reports', 'pkg.json'), 'utf8'))).toMatchObject({ digest: verdict.report.digest })
    expect(await call('report', { name: 'pkg' })).toMatchObject({ ok: true, value: { version: '2.0.0' } })
  } finally {
    await verdict.dispose()
    unregister()
  }
})

it('bridges OpenAI chat requests to the selected DSH model behind a bearer token', async () => {
  const { startLlmBridge, BRIDGE_MODEL } = await import('../src/host/llm-bridge.ts')
  const seen: unknown[] = []
  const llm = {
    listProviders: () => [{ id: 'p', name: 'Provider' }],
    listModels: async () => [{ provider: 'p', id: 'm', name: 'Model' }],
    async *stream(options: unknown) {
      seen.push(options)
      yield { type: 'text-delta', text: '{"verdict":' }
      yield { type: 'text-delta', text: '"safe"}' }
      yield { type: 'finish', reason: { kind: 'stop' } }
    },
  }
  const bridge = await startLlmBridge(llm, { provider: 'p', model: 'm' }, new AbortController().signal)
  try {
    const url = `${bridge.baseUrl}/chat/completions`
    const body = JSON.stringify({ model: BRIDGE_MODEL, messages: [{ role: 'system', content: 'judge' }, { role: 'user', content: [{ type: 'text', text: 'skill text' }] }] })
    expect((await fetch(url, { method: 'POST', body })).status).toBe(401)
    const answer = await (await fetch(url, { method: 'POST', body, headers: { authorization: `Bearer ${bridge.apiKey}` } })).json() as { choices: { message: { content: string } }[] }
    expect(answer.choices[0]?.message.content).toBe('{"verdict":"safe"}')
    expect(seen[0]).toMatchObject({ provider: 'p', model: 'm', system: 'judge', messages: [{ role: 'user', content: [{ type: 'text', text: 'skill text' }] }] })
    expect(bridge.calls()).toBe(1)
  } finally {
    await bridge.close()
  }
})
