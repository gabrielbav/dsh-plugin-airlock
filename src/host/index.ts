/**
 * Airlock, Host half: quarantines every third-party plugin, skill and subagent bundle, scans it, and rules pass,
 * review or block. It works on two tiers:
 *
 * - **Full enforcement**, on a DSH with the install-gate hook (`pluginManager.registerInstallGate`): every install,
 *   from the Plugins page, the chat or an update, is vetted before the profile changes.
 * - **Standard**, on stock DSH: the agent's `plugin_manager` installs are vetted through `tools/pre-execute`, the
 *   Plugins page gets Airlock's own scan-first install, and an audit switches off third-party bundles that installed
 *   some other way without a scan.
 *
 * It serves reports, scanner status, settings and those flows to the browser half over exact
 * `/api/airlock.<endpoint>` routes, and offers `ctx.airlock` so other plugins can add scanners.
 */
import { randomUUID } from 'node:crypto'
import { mkdir, readdir, readFile, realpath } from 'node:fs/promises'
import { join } from 'node:path'
import { execa } from 'execa'
import { applySettings, ConfigError, parseSettings, SCANNER_NAMES } from './config.ts'
import { chatGate } from './chat.ts'
import type { BundleInfo, ChangeResult, FetchRoute, HostContext, InstallGateRequest, InstallGateVerdict, InstallGateReport, LlmModelInfo } from './dsh.ts'
import { digestTree, GATE_ID, scannerAvailability, scanPackage } from './engine/index.ts'
import { LOCAL_SKIPPED_DIRS } from './engine/quarantine.ts'
import { anchorPathSpec, quarantineFetch } from './fetch.ts'
import { audit, audited, linked, readLedger, statusOf, writeLedger, type BundleStatus, type Ledger, type TrustSource } from './ledger.ts'
import { scannerEnv } from './engine/runner.ts'
import { customScanner, SCANNERS } from './engine/scanners.ts'
import { writePrivateFile } from './files.ts'
import { startLlmBridge } from './llm-bridge.ts'
import { upgradeReport } from './reports.ts'
import {
  BUILTIN_SCANNERS, type AirlockConfig, type AirlockScannerInfo, type AirlockService, type AirlockSettings,
  type BuiltinScannerId, type ResolvedScanner, type ScannerAdapter,
} from './types.ts'

export { Config } from './config.ts'
export type * from './types.ts'

/** Plugin name in the Loader. */
export const name = 'dsh-plugin-airlock'

/** The plugin manager owns installation; the profile locates settings and reports. */
export const inject = ['pluginManager', 'profileContext']

/** Route prefix under the connection's shared `/api` channel. */
const PREFIX = 'airlock.'

/** The fork branch that carries the install-gate hook, linked from the settings page. */
export const HOOK_URL = 'https://github.com/gabrielbav/deepseek-harness/tree/feat/install-gate'

/** How long a scan from Airlock's install dialog stays installable. */
const SCAN_TTL_MS = 30 * 60 * 1000

/** Lower-case scanner ids a plugin may register. */
const ADAPTER_ID = /^[a-z0-9][a-z0-9-]{0,39}$/

type Result = { ok: true; value: unknown } | { ok: false; error: { code: string; message: string; details: Record<string, never> } }

/** A request the browser sent with a payload Airlock refuses. */
class BadRequest extends Error {}

function payloadObject(payload: unknown): Record<string, unknown> {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) throw new BadRequest('payload must be an object')
  return payload as Record<string, unknown>
}

function stringField(payload: unknown, key: string): string {
  const value = payloadObject(payload)[key]
  if (typeof value !== 'string' || value === '') throw new BadRequest(`${key} must be a non-empty string`)
  return value
}

/**
 * Mount Airlock.
 * @param ctx Plugin context.
 * @param config The row's validated configuration.
 */
export function apply(ctx: HostContext, config: AirlockConfig): void {
  const root = join(ctx.profileContext.dir, '.airlock')
  const reportsDir = join(root, 'reports')
  const settingsPath = join(root, 'settings.json')
  const adapters = new Map<string, ScannerAdapter>()

  const readSettings = async (): Promise<AirlockSettings> => {
    let text: string
    try { text = await readFile(settingsPath, 'utf8') }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {}
      throw error
    }
    return parseSettings(JSON.parse(text))
  }

  const effective = async (): Promise<AirlockConfig> => applySettings(config, await readSettings())

  const resolveScanners = (current: AirlockConfig): ResolvedScanner[] => [
    ...BUILTIN_SCANNERS.map((id): ResolvedScanner => ({
      id, name: SCANNER_NAMES[id], origin: 'builtin', enabled: current.scanners[id].enabled, command: current.scanners[id].command, run: SCANNERS[id],
    })),
    ...current.custom.map((scanner): ResolvedScanner => ({
      id: scanner.id, name: scanner.name, origin: 'custom', enabled: scanner.enabled, command: scanner.command, run: customScanner(scanner),
    })),
    ...[...adapters.values()].filter(adapter => !current.custom.some(scanner => scanner.id === adapter.id)).map((adapter): ResolvedScanner => ({
      id: adapter.id, name: adapter.name, origin: 'plugin', enabled: true, command: adapter.command, run: ctx => adapter.run(ctx),
    })),
  ]

  const reportPath = (packageName: string): string => join(reportsDir, `${encodeURIComponent(packageName)}.json`)
  const ledgerPath = join(root, 'ledger.json')

  // Ledger writes run one at a time. Nothing inside this queue waits for the plugin manager, which holds its change
  // lock while it asks the install gate, and the gate itself writes to the ledger.
  let queue: Promise<unknown> = Promise.resolve()
  const serial = <T>(task: () => Promise<T>): Promise<T> => {
    const run = queue.then(task)
    queue = run.then(() => undefined, () => undefined)
    return run
  }
  let ledgerCache: Ledger | null | undefined
  const loadLedger = async (): Promise<Ledger | null> => {
    if (ledgerCache === undefined) ledgerCache = await readLedger(ledgerPath)
    return ledgerCache
  }
  const saveLedger = async (ledger: Ledger): Promise<void> => {
    await mkdir(root, { recursive: true, mode: 0o700 })
    await writeLedger(ledgerPath, ledger)
    ledgerCache = ledger
  }
  /** Trust one bundle's files. */
  const trust = (name: string, digest: string | null, how: TrustSource, version?: string): Promise<void> => serial(async () => {
    const current = await loadLedger() ?? { version: 1 as const, approved: {}, disabled: {} }
    await saveLedger({
      ...current,
      approved: { ...current.approved, [name]: { digest, how, ...version === undefined ? {} : { version }, at: new Date().toISOString() } },
    })
  })
  const trustReport = (report: InstallGateReport): Promise<void> => report.packageName === undefined
    ? Promise.resolve()
    : trust(report.packageName, report.digest, 'scan', report.version)

  /** The real directory of an installed profile dependency, or null when it has none. */
  const bundleDir = async (name: string): Promise<string | null> => {
    try { return await realpath(join(ctx.profileContext.dir, 'node_modules', name)) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
  }
  const digestOf = async (bundle: BundleInfo): Promise<string | null> => {
    if (linked(bundle)) return null
    const dir = await bundleDir(bundle.name)
    return dir === null ? null : digestTree(dir, LOCAL_SKIPPED_DIRS)
  }

  const vet = async (request: InstallGateRequest): Promise<InstallGateVerdict> => {
    const current = await effective()
    const llm = ctx.get('llm')
    // The judge runs only with a chosen model the profile can call; otherwise the report says the LLM did not run.
    const bridge = current.llm.enabled && current.llm.provider !== '' && current.llm.model !== '' && llm !== undefined
      ? await startLlmBridge(llm, { provider: current.llm.provider, model: current.llm.model }, request.signal, (message) => {
        ctx.logger.warn(`airlock: LLM judge ${current.llm.provider}/${current.llm.model}: ${message}`)
        request.log(`airlock: LLM judge: ${message}\n`, 'stderr')
      })
      : undefined
    let scanned
    try {
      scanned = await scanPackage({
        ...request, config: current, scanners: resolveScanners(current),
        ...bridge === undefined ? {} : { llm: { baseUrl: bridge.baseUrl, apiKey: bridge.apiKey, calls: model => bridge.calls(model) } },
      })
    } finally {
      await bridge?.close()
    }
    if (scanned.report.packageName !== undefined) {
      await mkdir(reportsDir, { recursive: true, mode: 0o700 })
      await writePrivateFile(reportPath(scanned.report.packageName), `${JSON.stringify(scanned.report, null, 2)}\n`)
    }
    return scanned
  }

  /** The install-gate hook's entry: the manager refuses blocks and asks for review itself, so only blocks go untrusted. */
  const hookVet = async (request: InstallGateRequest): Promise<InstallGateVerdict> => {
    const verdict = await vet(request)
    if (verdict.report.level !== 'block') await trustReport(verdict.report)
    return verdict
  }

  /**
   * Quarantine and scan a spec with Airlock's own fetch, for every flow the plugin manager does not drive.
   * @param trustUpTo The worst level whose digest is trusted right away; the rest are trusted on acknowledgement.
   */
  const scanSpec = async (spec: string, registry: string | null, signal: AbortSignal, trustUpTo: 'pass' | 'review'): Promise<InstallGateReport> => {
    const current = await effective()
    const log = (text: string, stream: 'stdout' | 'stderr'): void => { if (stream === 'stderr' && text.trim() !== '') ctx.logger.info(`airlock: ${text.trim()}`) }
    const anchored = anchorPathSpec(spec, ctx.profileContext.cwd ?? ctx.profileContext.dir)
    const verdict = await vet({
      spec: anchored, registry, signal, log,
      fetch: (dir, fetchSignal) => quarantineFetch(dir, fetchSignal, {
        invocation: ctx.profileContext.packageManager ?? { command: 'pnpm', args: [], env: {} },
        profileDir: ctx.profileContext.dir, cwd: ctx.profileContext.cwd ?? ctx.profileContext.dir, spec: anchored, registry,
        timeoutMs: current.fetchTimeoutMs, onOutput: log,
      }),
    })
    await verdict.dispose()
    const report = verdict.report
    if (report.level === 'pass' || (trustUpTo === 'review' && report.level === 'review')) await trustReport(report)
    return report
  }

  // Install-gate hook: used when the DSH has it and the person has not turned it off.
  const hookAvailable = typeof ctx.pluginManager.registerInstallGate === 'function'
  let unregisterGate: (() => void) | undefined
  const gateActive = (): boolean => unregisterGate !== undefined
  const reconcileGate = (current: AirlockConfig): void => {
    const want = hookAvailable && current.enforcement.useInstallGate
    if (want && unregisterGate === undefined) unregisterGate = ctx.pluginManager.registerInstallGate?.({ id: GATE_ID, vet: hookVet })
    if (!want && unregisterGate !== undefined) { unregisterGate(); unregisterGate = undefined }
  }

  let auditing: Promise<void> | undefined
  let auditAgain = false
  let disposed = false
  const runAudit = async (): Promise<void> => {
    const current = await effective()
    const bundles = await ctx.pluginManager.listBundles()
    const digests = new Map<string, string | null>()
    for (const bundle of bundles.filter(item => audited(item, name))) digests.set(bundle.name, await digestOf(bundle))
    const result = await serial(async () => {
      const outcome = await audit({
        bundles, ledger: await loadLedger(), digestOf: async bundle => digests.get(bundle.name) ?? null,
        disable: current.enforcement.unscanned === 'disable', self: name,
      })
      await saveLedger(outcome.ledger)
      return outcome
    })
    for (const bundle of result.bundles) {
      if (bundle.status === 'unscanned' || bundle.status === 'changed') {
        ctx.logger.warn(`airlock: ${bundle.name} installed without an Airlock scan (${bundle.status})${bundle.disable ? '; switched it off' : ''}`)
      }
      if (!bundle.disable || disposed) continue
      const change = await ctx.pluginManager.setBundleEnabled(bundle.name, false)
      if (change.application === 'failed') ctx.logger.warn(`airlock: could not switch off ${bundle.name}: ${change.error?.message ?? 'unknown error'}`)
    }
  }
  /** Run the audit, coalescing the change events that arrive while it runs. */
  const scheduleAudit = (): void => {
    if (disposed) return
    if (auditing !== undefined) { auditAgain = true; return }
    // Off the event's own call stack: the manager emits its change event while it still holds its change lock.
    auditing = new Promise<void>(done => { setTimeout(done, 0) }).then(runAudit).catch((error: unknown) => {
      ctx.logger.warn('airlock: audit failed', error)
    }).finally(() => {
      auditing = undefined
      if (auditAgain) { auditAgain = false; scheduleAudit() }
    })
  }

  const bundleState = async (bundleName: string): Promise<{
    status: BundleStatus | null; enabled: boolean; linked: boolean; disabledByAirlock: boolean
  }> => {
    const bundle = (await ctx.pluginManager.listBundles()).find(item => item.name === bundleName)
    if (bundle === undefined || !audited(bundle, name)) return { status: null, enabled: bundle?.enabled ?? false, linked: false, disabledByAirlock: false }
    const ledger = await serial(loadLedger)
    const status = ledger === null ? 'baseline' : statusOf(ledger.approved[bundleName], await digestOf(bundle))
    return { status, enabled: bundle.enabled, linked: linked(bundle), disabledByAirlock: !bundle.enabled && ledger?.disabled[bundleName] !== undefined }
  }

  /** Switch back on a bundle the audit switched off. */
  const restore = async (bundleName: string): Promise<ChangeResult | null> => {
    const state = await bundleState(bundleName)
    return state.disabledByAirlock ? ctx.pluginManager.setBundleEnabled(bundleName, true) : null
  }

  /** Scans from Airlock's install dialog, kept until installed or expired. */
  const scans = new Map<string, { installSpec: string; registry: string | null; report: InstallGateReport; at: number }>()

  const scanForInstall = async (spec: string, registry: string | undefined, signal: AbortSignal): Promise<{ scanId: string; report: InstallGateReport }> => {
    for (const [id, scan] of scans) if (Date.now() - scan.at > SCAN_TTL_MS) scans.delete(id)
    const inspection = await ctx.pluginManager.inspect(spec, registry === undefined ? undefined : { registry }, signal)
    if (inspection.status === 'refused') throw new BadRequest(inspection.reason)
    const report = await scanSpec(spec, registry ?? inspection.registry, signal, 'pass')
    // A registry install names the exact version scanned, so the files cannot change in between.
    const installSpec = inspection.kind === 'registry' && report.packageName !== undefined && report.version !== undefined
      ? `${report.packageName}@${report.version}`
      : anchorPathSpec(spec, ctx.profileContext.cwd ?? ctx.profileContext.dir)
    const scanId = randomUUID()
    scans.set(scanId, { installSpec, registry: registry ?? null, report, at: Date.now() })
    return { scanId, report }
  }

  /**
   * Install a scanned package switched off, check that the installed files are the scanned ones, then switch it on.
   * Files that differ are removed again.
   */
  const installScanned = async (scanId: string, acknowledged: string | undefined): Promise<{ result: ChangeResult }> => {
    const scan = scans.get(scanId)
    if (scan === undefined) throw new BadRequest('this scan expired; scan the package again')
    const { report } = scan
    if (report.level === 'block') throw new BadRequest('Airlock blocked this package')
    if (report.level === 'review' && acknowledged !== report.digest) throw new BadRequest('this package needs review; acknowledge the findings first')
    scans.delete(scanId)
    await trustReport(report)
    const installed = await ctx.pluginManager.installBundle(scan.installSpec, {
      enabled: false,
      ...scan.registry === null ? {} : { registry: scan.registry },
      ...report.packageName !== undefined && report.version !== undefined ? { expected: { name: report.packageName, version: report.version } } : {},
    })
    if (installed.application === 'failed' || installed.application === 'cancelled') return { result: installed }
    const bundleName = installed.bundle ?? report.packageName
    if (bundleName === undefined) return { result: installed }
    const dir = await bundleDir(bundleName)
    if (dir === null || await digestTree(dir, LOCAL_SKIPPED_DIRS) !== report.digest) {
      await ctx.pluginManager.removeBundle(bundleName)
      return { result: { application: 'failed', bundle: bundleName, error: { code: 'airlock/mismatch', message: 'The installed files are not the ones Airlock scanned, so the package was removed again.' } } }
    }
    return { result: await ctx.pluginManager.setBundleEnabled(bundleName, true) }
  }

  const status = async () => {
    const current = await effective()
    return {
      hookAvailable, gateActive: gateActive(), mode: gateActive() ? 'full' as const : 'standard' as const,
      useInstallGate: current.enforcement.useInstallGate, unscanned: current.enforcement.unscanned, hookUrl: HOOK_URL,
    }
  }

  const readReport = async (packageName: string): Promise<InstallGateReport | null> => {
    try { return upgradeReport(JSON.parse(await readFile(reportPath(packageName), 'utf8'))) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
      throw error
    }
  }

  const listReports = async (): Promise<InstallGateReport[]> => {
    let names: string[]
    try { names = await readdir(reportsDir) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw error
    }
    const reports = await Promise.all(names.filter(file => file.endsWith('.json'))
      .map(async file => upgradeReport(JSON.parse(await readFile(join(reportsDir, file), 'utf8')))))
    return reports.sort((a, b) => b.checkedAt.localeCompare(a.checkedAt))
  }

  const scannerInfo = async (): Promise<AirlockScannerInfo[]> => {
    const current = await effective()
    const scanners = resolveScanners(current)
    const available = await scannerAvailability(scanners, current.searchPaths)
    return scanners.map(scanner => ({
      id: scanner.id, name: scanner.name, origin: scanner.origin, enabled: scanner.enabled, command: scanner.command ?? null,
      executable: available.get(scanner.id) ?? null,
      installable: scanner.origin === 'builtin' && current.installCommands[scanner.id as BuiltinScannerId].length > 0,
    }))
  }

  /** Installations in flight by scanner id, so a double click runs one. */
  const installing = new Map<string, Promise<{ exitCode: number | null; output: string }>>()

  const installScanner = (id: string): Promise<{ exitCode: number | null; output: string }> => {
    if (!(BUILTIN_SCANNERS as readonly string[]).includes(id)) throw new BadRequest(`${id} is not a built-in scanner`)
    const running = installing.get(id)
    if (running !== undefined) return running
    const task = (async () => {
      const current = await effective()
      const [command, ...args] = current.installCommands[id as BuiltinScannerId]
      if (command === undefined) throw new BadRequest(`no install command is configured for ${id}`)
      const result = await execa(command, args, {
        env: scannerEnv(current.searchPaths, {}), extendEnv: false, reject: false, stdin: 'ignore', all: true,
        timeout: current.installTimeoutMs,
      })
      const output = typeof result.all === 'string' ? result.all : ''
      return { exitCode: result.exitCode ?? null, output: output.slice(-4000) }
    })().finally(() => { installing.delete(id) })
    installing.set(id, task)
    return task
  }

  /** The chat's model catalog: every provider's advertised models. */
  const listModels = async (): Promise<(LlmModelInfo & { providerName: string })[]> => {
    const llm = ctx.get('llm')
    if (llm === undefined) return []
    const lists = await Promise.all(llm.listProviders().map(async (provider) => {
      try { return (await llm.listModels(provider.id)).map(model => ({ ...model, providerName: provider.name })) }
      catch (error) { ctx.logger.warn(`airlock: could not list models of ${provider.id}`, error); return [] }
    }))
    return lists.flat()
  }

  const dispatch = async (endpoint: string, payload: unknown, signal: AbortSignal): Promise<unknown> => {
    switch (endpoint) {
      case 'status': return status()
      case 'scan': {
        const registry = payloadObject(payload).registry
        return scanForInstall(stringField(payload, 'spec').trim(), typeof registry === 'string' && registry !== '' ? registry : undefined, signal)
      }
      case 'install': {
        const acknowledged = payloadObject(payload).acknowledged
        return installScanned(stringField(payload, 'scanId'), typeof acknowledged === 'string' ? acknowledged : undefined)
      }
      case 'bundleStatus': return bundleState(stringField(payload, 'name'))
      case 'scanInstalled': {
        const bundleName = stringField(payload, 'name')
        const dir = await bundleDir(bundleName)
        if (dir === null) throw new BadRequest(`${bundleName} is not installed in this profile`)
        const report = await scanSpec(dir, null, signal, 'pass')
        if (report.level === 'pass') await restore(bundleName)
        return { report, state: await bundleState(bundleName) }
      }
      case 'trust': {
        const bundleName = stringField(payload, 'name')
        const bundle = (await ctx.pluginManager.listBundles()).find(item => item.name === bundleName)
        if (bundle === undefined || !audited(bundle, name)) throw new BadRequest(`${bundleName} is not a third-party bundle in this profile`)
        await trust(bundleName, await digestOf(bundle), 'user', bundle.version)
        await restore(bundleName)
        return bundleState(bundleName)
      }
      case 'models': return listModels()
      case 'report': return readReport(stringField(payload, 'name'))
      case 'reports': return listReports()
      case 'scanners': return scannerInfo()
      case 'settings': return { settings: await readSettings(), effective: await effective() }
      case 'saveSettings': {
        const settings = parseSettings(payloadObject(payload).settings)
        applySettings(config, settings)
        await mkdir(root, { recursive: true, mode: 0o700 })
        await writePrivateFile(settingsPath, `${JSON.stringify(settings, null, 2)}\n`)
        const next = await effective()
        reconcileGate(next)
        return { settings, effective: next }
      }
      case 'installScanner': return installScanner(stringField(payload, 'id'))
      default: throw new BadRequest(`unknown endpoint ${endpoint}`)
    }
  }

  const handle = async (endpoint: string, payload: unknown, signal: AbortSignal): Promise<Result> => {
    try { return { ok: true, value: await dispatch(endpoint, payload, signal) } }
    catch (error) {
      if (error instanceof BadRequest || error instanceof ConfigError) return { ok: false, error: { code: 'airlock/bad-request', message: error.message, details: {} } }
      ctx.logger.warn('airlock: request failed', error)
      return { ok: false, error: { code: 'airlock/failed', message: error instanceof Error ? error.message : String(error), details: {} } }
    }
  }

  // The gate is registered at once with the configured default, then follows the saved settings.
  reconcileGate(config)
  ctx.effect(() => () => { unregisterGate?.(); unregisterGate = undefined }, 'airlock: install gate')
  void effective().then(reconcileGate, (error: unknown) => { ctx.logger.warn('airlock: could not read settings', error) })
  if (!hookAvailable) ctx.logger.info('airlock: this DSH has no install-gate hook; vetting chat installs and auditing the rest (standard mode)')

  ctx.effect(() => ctx.on('tools/pre-execute', (exec, next) => chatGate(exec, next, {
    active: () => !gateActive(),
    inspect: (spec, registry, signal) => ctx.pluginManager.inspect(spec, registry === undefined ? undefined : { registry }, signal),
    scan: (spec, registry, signal) => scanSpec(spec, registry, signal, 'review'),
  })), 'airlock: chat gate')
  ctx.effect(() => ctx.on('plugin-manager/changed', () => { scheduleAudit() }), 'airlock: audit on change')
  ctx.effect(() => { scheduleAudit(); return () => { disposed = true } }, 'airlock: audit')

  const service: AirlockService = {
    registerScanner(adapter) {
      if (!ADAPTER_ID.test(adapter.id) || (BUILTIN_SCANNERS as readonly string[]).includes(adapter.id) || adapter.id === 'airlock') {
        throw new Error(`airlock: scanner id ${adapter.id} is invalid or reserved`)
      }
      if (adapters.has(adapter.id)) throw new Error(`airlock: scanner ${adapter.id} is already registered`)
      adapters.set(adapter.id, adapter)
      return () => { if (adapters.get(adapter.id) === adapter) adapters.delete(adapter.id) }
    },
  }
  ctx.effect(() => ctx.reflect.provide('airlock', service), 'airlock: scanner registry')

  ctx.inject(['connection'], (scope) => {
    for (const endpoint of ['report', 'reports', 'scanners', 'models', 'settings', 'saveSettings', 'installScanner', 'status', 'scan', 'install', 'bundleStatus', 'scanInstalled', 'trust']) {
      const method = `${PREFIX}${endpoint}`
      const route: FetchRoute = {
        path: `/api/${method}`, methods: ['POST'], requestBody: 'buffered',
        fetch: async (request) => {
          if (request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/json') {
            return new Response('content type must be application/json', { status: 415 })
          }
          let body: unknown
          try { body = await request.json() }
          catch (error) { void error; return new Response('body is not JSON', { status: 400 }) }
          const envelope = payloadObject(body)
          const rpcId = typeof envelope.rpcId === 'string' ? envelope.rpcId : 'invalid-request'
          const result = envelope.type !== 'client-request' || envelope.method !== method
            ? { ok: false, error: { code: 'gateway/bad-request', message: `expected a client-request for ${method}`, details: {} } }
            : await handle(endpoint, envelope.payload ?? {}, request.signal)
          return Response.json({ type: 'server-response', rpcId, result })
        },
      }
      scope.effect(() => scope.connection.fetch.register(route), `airlock: /api/${method}`)
    }
  })
}
