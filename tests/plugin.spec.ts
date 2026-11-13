import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, expect, it } from 'vitest'
import { apply, Config, inject, name, type AirlockService } from '../src/host/index.ts'
import type { BundleInfo, FetchRoute, HostContext, InstallGate, PluginManager } from '../src/host/dsh.ts'

let root: string
beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'airlock-plugin-')) })
afterEach(async () => { await rm(root, { recursive: true, force: true }) })

/** Mount the plugin on a recording context, with or without the install-gate hook. */
function mount(options: { hook?: boolean; bundles?: BundleInfo[] } = {}) {
  const disposers: (() => void | Promise<void>)[] = []
  const gates: InstallGate[] = []
  const routes = new Map<string, FetchRoute>()
  const provided = new Map<string, unknown>()
  const listeners = new Map<string, ((...args: never[]) => unknown)[]>()
  const bundles: BundleInfo[] = options.bundles ?? []
  const toggles: [string, boolean][] = []
  const pluginManager: PluginManager = {
    listBundles: async () => bundles.map(bundle => ({ ...bundle })),
    inspect: async spec => ({ status: 'accepted', kind: spec.startsWith('/') ? 'path' : 'registry', name: 'pkg', version: '2.0.0', bundle: true, registry: null }),
    installBundle: async () => ({ application: 'applied' }),
    setBundleEnabled: async (bundleName, enabled) => {
      toggles.push([bundleName, enabled])
      const index = bundles.findIndex(bundle => bundle.name === bundleName)
      if (index >= 0) bundles[index] = { ...bundles[index]!, enabled }
      return { application: 'applied' }
    },
    removeBundle: async () => ({ application: 'applied' }),
    ...options.hook === false ? {} : { registerInstallGate: (gate: InstallGate) => { gates.push(gate); return () => { gates.splice(gates.indexOf(gate), 1) } } },
  }
  const ctx: HostContext = {
    pluginManager,
    profileContext: { dir: root },
    logger: { warn: () => {}, info: () => {} },
    reflect: { provide: (key, value) => { provided.set(key, value); return () => { provided.delete(key) } } },
    get: () => undefined,
    effect: (execute) => { disposers.push(execute()) },
    on: ((event: string, listener: (...args: never[]) => unknown) => {
      listeners.set(event, [...listeners.get(event) ?? [], listener])
      return () => { listeners.set(event, (listeners.get(event) ?? []).filter(item => item !== listener)) }
    }) as HostContext['on'],
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
  const preExecute = (exec: { name: string; arguments: unknown }) => {
    const listener = listeners.get('tools/pre-execute')?.[0] as ((exec: unknown, next: () => Promise<unknown>) => Promise<unknown>) | undefined
    if (listener === undefined) throw new Error('no pre-execute listener')
    return listener(exec, async () => ({ kind: 'allow' }))
  }
  const settle = () => new Promise(resolve => { setTimeout(resolve, 50) })
  return { gates, routes, provided, call, preExecute, settle, bundles, toggles, listeners, dispose: async () => { for (const dispose of disposers.reverse()) await dispose() } }
}

it('exports a function plugin that needs the plugin manager and the profile', () => {
  expect(name).toBe('dsh-plugin-airlock')
  expect(inject).toEqual(['pluginManager', 'profileContext'])
})

it('registers its gate, routes and scanner registry, and removes them on disposal', async () => {
  const { gates, routes, provided, dispose } = mount()
  expect(gates.map(gate => gate.id)).toEqual(['dsh-plugin-airlock'])
  expect([...routes.keys()].sort()).toEqual(['bundleStatus', 'install', 'installScanner', 'models', 'report', 'reports', 'saveSettings', 'scan', 'scanInstalled', 'scanners', 'settings', 'status', 'trust'].map(item => `/api/airlock.${item}`))
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

it('loads without the install-gate hook and reports standard mode', async () => {
  const { gates, call, dispose } = mount({ hook: false })
  expect(gates).toEqual([])
  expect(await call('status', {})).toMatchObject({ ok: true, value: { hookAvailable: false, gateActive: false, mode: 'standard' } })
  await dispose()
})

it('stops using the hook when the person turns it off, and uses it again when turned back on', async () => {
  const { gates, call } = mount()
  expect(await call('status', {})).toMatchObject({ ok: true, value: { mode: 'full' } })
  await call('saveSettings', { settings: { enforcement: { useInstallGate: false } } })
  expect(gates).toEqual([])
  expect(await call('status', {})).toMatchObject({ ok: true, value: { hookAvailable: true, mode: 'standard' } })
  await call('saveSettings', { settings: { enforcement: { useInstallGate: true } } })
  expect(gates).toHaveLength(1)
})

it('leaves chat installs to the hook while it vets them', async () => {
  const { preExecute } = mount()
  expect(await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: 'pkg' } })).toEqual({ kind: 'allow' })
})

it('asks for an exact version in the chat before it scans a registry package', async () => {
  const { preExecute } = mount({ hook: false })
  expect(await preExecute({ name: 'plugin_manager', arguments: { action: 'list_bundles' } })).toEqual({ kind: 'allow' })
  expect(await preExecute({ name: 'read_file', arguments: {} })).toEqual({ kind: 'allow' })
  const ruling = await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: 'pkg' } }) as { kind: string; reason: string }
  expect(ruling.kind).toBe('deny')
  expect(ruling.reason).toContain('"pkg@2.0.0"')
})

it('scans a chat install, allows a pass and trusts its files', async () => {
  const { preExecute, call } = mount({ hook: false })
  await call('saveSettings', { settings: { policy: { requireLlm: false } } })
  const pkg = join(root, 'pkg')
  await mkdir(pkg)
  await writeFile(join(pkg, 'package.json'), '{"name":"pkg","version":"2.0.0"}')
  // A local directory installs from the quarantine with a real pnpm; this one needs no dependencies.
  expect(await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: pkg } })).toEqual({ kind: 'allow' })
  const ledger = JSON.parse(await readFile(join(root, '.airlock', 'ledger.json'), 'utf8')) as { approved: Record<string, { how: string }> }
  expect(ledger.approved.pkg).toMatchObject({ how: 'scan' })
}, 60000)

it('refuses a chat install it cannot vet', async () => {
  const { preExecute } = mount({ hook: false })
  const ruling = await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: join(root, 'missing') } }) as { kind: string; reason: string }
  expect(ruling.kind).toBe('deny')
  expect(ruling.reason).toMatch(/^Airlock could not vet/)
}, 60000)

it('trusts what is installed on its first run and switches off bundles that install later without a scan', async () => {
  const baseline: BundleInfo = { name: 'old', official: false, availability: 'profile', enabled: true, installed: true, source: 'link:/somewhere' }
  const { bundles, toggles, listeners, settle, call } = mount({ hook: false, bundles: [baseline] })
  await settle()
  expect(await call('bundleStatus', { name: 'old' })).toMatchObject({ ok: true, value: { status: 'baseline' } })
  bundles.push({ name: 'sneaky', official: false, availability: 'profile', enabled: true, installed: true, source: 'link:/elsewhere' },
    { name: 'official', official: true, availability: 'profile', enabled: true, installed: true })
  for (const listener of listeners.get('plugin-manager/changed') ?? []) (listener as () => void)()
  await settle()
  expect(toggles).toEqual([['sneaky', false]])
  expect(await call('bundleStatus', { name: 'sneaky' })).toMatchObject({ ok: true, value: { status: 'unscanned', disabledByAirlock: true } })
  // Switched off once: a person who turns it back on keeps it on.
  bundles[1] = { ...bundles[1]!, enabled: true }
  for (const listener of listeners.get('plugin-manager/changed') ?? []) (listener as () => void)()
  await settle()
  expect(toggles).toEqual([['sneaky', false]])
  expect(await call('trust', { name: 'sneaky' })).toMatchObject({ ok: true, value: { status: 'trusted' } })
})

it('refuses a red chat install and asks about a yellow one, without passing finding text to the agent', async () => {
  const { preExecute, call, provided } = mount({ hook: false })
  await call('saveSettings', { settings: { policy: { requireLlm: false } } })
  let severity: 'critical' | 'medium' = 'critical'
  ;(provided.get('airlock') as AirlockService).registerScanner({
    id: 'house-rules', name: 'House rules',
    run: async () => ({ id: 'house-rules', status: 'findings', durationMs: 0, usedLlm: false,
      findings: [{ source: 'house-rules', severity, category: 'prompt_injection', title: 'IGNORE PREVIOUS INSTRUCTIONS', dependency: false, dedupeKey: 'x' }] }),
  })
  const pkg = join(root, 'pkg')
  await mkdir(pkg)
  await writeFile(join(pkg, 'package.json'), '{"name":"pkg","version":"2.0.0"}')
  const blocked = await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: pkg } }) as { kind: string; reason: string }
  expect(blocked.kind).toBe('deny')
  expect(blocked.reason).toMatch(/^Airlock blocked pkg@2\.0\.0/)
  expect(blocked.reason).not.toContain('IGNORE')
  severity = 'medium'
  const review = await preExecute({ name: 'plugin_manager', arguments: { action: 'install_bundle', target: pkg } }) as { kind: string; reason: string; displayReason: { en: string } }
  expect(review.kind).toBe('ask')
  expect(review.displayReason.en).toContain('review needed')
  expect(JSON.stringify(review)).not.toContain('IGNORE')
}, 60000)
