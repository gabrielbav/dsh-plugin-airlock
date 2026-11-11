/**
 * Airlock, Host half: registers an install gate with the DSH plugin manager that quarantines every third-party
 * plugin, skill and subagent bundle, scans it, and rules pass, review or block. It serves the reports, scanner status
 * and settings to the browser half over exact `/api/airlock.<endpoint>` routes, and offers `ctx.airlock` so other
 * plugins can add scanners.
 */
import { mkdir, readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { execa } from 'execa'
import { applySettings, ConfigError, parseSettings, SCANNER_NAMES } from './config.ts'
import type { FetchRoute, HostContext, InstallGateRequest, InstallGateVerdict, InstallGateReport } from './dsh.ts'
import { GATE_ID, scannerAvailability, scanPackage } from './engine/index.ts'
import { scannerEnv } from './engine/runner.ts'
import { customScanner, SCANNERS } from './engine/scanners.ts'
import { writePrivateFile } from './files.ts'
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

/** Lower-case scanner ids a plugin may register. */
const ADAPTER_ID = /^[a-z0-9][a-z0-9-]{0,39}$/

type Result = { ok: true; value: unknown } | { ok: false; error: { code: string; message: string } }

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

  const vet = async (request: InstallGateRequest): Promise<InstallGateVerdict> => {
    const current = await effective()
    const scanned = await scanPackage({ ...request, config: current, scanners: resolveScanners(current) })
    if (scanned.report.packageName !== undefined) {
      await mkdir(reportsDir, { recursive: true, mode: 0o700 })
      await writePrivateFile(reportPath(scanned.report.packageName), `${JSON.stringify(scanned.report, null, 2)}\n`)
    }
    return scanned
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

  const dispatch = async (endpoint: string, payload: unknown): Promise<unknown> => {
    switch (endpoint) {
      case 'report': return readReport(stringField(payload, 'name'))
      case 'reports': return listReports()
      case 'scanners': return scannerInfo()
      case 'settings': return { settings: await readSettings(), effective: await effective() }
      case 'saveSettings': {
        const settings = parseSettings(payloadObject(payload).settings)
        applySettings(config, settings)
        await mkdir(root, { recursive: true, mode: 0o700 })
        await writePrivateFile(settingsPath, `${JSON.stringify(settings, null, 2)}\n`)
        return { settings, effective: await effective() }
      }
      case 'installScanner': return installScanner(stringField(payload, 'id'))
      default: throw new BadRequest(`unknown endpoint ${endpoint}`)
    }
  }

  const handle = async (endpoint: string, payload: unknown): Promise<Result> => {
    try { return { ok: true, value: await dispatch(endpoint, payload) } }
    catch (error) {
      if (error instanceof BadRequest || error instanceof ConfigError) return { ok: false, error: { code: 'airlock/bad-request', message: error.message } }
      ctx.logger.warn('airlock: request failed', error)
      return { ok: false, error: { code: 'airlock/failed', message: error instanceof Error ? error.message : String(error) } }
    }
  }

  if (typeof ctx.pluginManager.registerInstallGate !== 'function') {
    throw new Error('dsh-plugin-airlock needs a DeepSeek Harness whose plugin manager supports install gates (registerInstallGate); update DSH')
  }
  ctx.effect(() => ctx.pluginManager.registerInstallGate({ id: GATE_ID, vet }), 'airlock: install gate')

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
    for (const endpoint of ['report', 'reports', 'scanners', 'settings', 'saveSettings', 'installScanner']) {
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
            ? { ok: false, error: { code: 'gateway/bad-request', message: `expected a client-request for ${method}` } }
            : await handle(endpoint, envelope.payload ?? {})
          return Response.json({ type: 'server-response', rpcId, result })
        },
      }
      scope.effect(() => scope.connection.fetch.register(route), `airlock: /api/${method}`)
    }
  })
}
