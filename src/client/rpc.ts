/** Calls to the Host half's `/api/airlock.<endpoint>` routes. */
import type { AirlockConfig, AirlockScannerInfo, AirlockSettings } from '../host/types.ts'
import type { ChangeResult } from '../host/dsh.ts'
import type { BundleStatus } from '../host/ledger.ts'
import type { ClientContext, InstallGateReport } from './dsh.ts'

/** Which tier Airlock runs on. */
export interface AirlockStatus {
  /** The DSH has the install-gate hook. */
  readonly hookAvailable: boolean
  /** Airlock vets installs through it right now. */
  readonly gateActive: boolean
  readonly mode: 'full' | 'standard'
  readonly useInstallGate: boolean
  readonly unscanned: 'disable' | 'flag'
  readonly hookUrl: string
}

/** What the audit says about one bundle; `status` is null for bundles Airlock does not audit. */
export interface BundleState {
  readonly status: BundleStatus | null
  readonly enabled: boolean
  readonly linked: boolean
  readonly disabledByAirlock: boolean
}

/** A Host answer the caller shows as an error message. */
export class AirlockRequestError extends Error {}

/** Typed Host endpoints. */
export interface AirlockApi {
  report(name: string): Promise<InstallGateReport | null>
  scanners(): Promise<AirlockScannerInfo[]>
  settings(): Promise<{ settings: AirlockSettings; effective: AirlockConfig }>
  saveSettings(settings: AirlockSettings): Promise<{ settings: AirlockSettings; effective: AirlockConfig }>
  installScanner(id: string): Promise<{ exitCode: number | null; output: string }>
  /** The chat's model catalog. */
  models(): Promise<{ provider: string; providerName: string; id: string; name: string }[]>
  reports(): Promise<InstallGateReport[]>
  status(): Promise<AirlockStatus>
  scan(spec: string, registry?: string): Promise<{ scanId: string; report: InstallGateReport }>
  install(scanId: string, acknowledged?: string): Promise<{ result: ChangeResult }>
  bundleStatus(name: string): Promise<BundleState>
  scanInstalled(name: string): Promise<{ report: InstallGateReport; state: BundleState }>
  trust(name: string): Promise<BundleState>
}

/**
 * Bind the endpoints to the page connection.
 * @param ctx Client context.
 * @returns The endpoint calls; each rejects with {@link AirlockRequestError} on a Host refusal.
 */
export function airlockApi(ctx: ClientContext): AirlockApi {
  const call = async <T>(endpoint: string, payload: unknown): Promise<T> => {
    const result = await ctx.connection.rpc.call('/api', `airlock.${endpoint}`, payload)
    if (!result.ok) throw new AirlockRequestError(result.error.message)
    return result.value as T
  }
  return {
    report: name => call('report', { name }),
    scanners: () => call('scanners', {}),
    settings: () => call('settings', {}),
    saveSettings: settings => call('saveSettings', { settings }),
    installScanner: id => call('installScanner', { id }),
    models: () => call('models', {}),
    reports: () => call('reports', {}),
    status: () => call('status', {}),
    scan: (spec, registry) => call('scan', { spec, ...registry === undefined ? {} : { registry } }),
    install: (scanId, acknowledged) => call('install', { scanId, ...acknowledged === undefined ? {} : { acknowledged } }),
    bundleStatus: name => call('bundleStatus', { name }),
    scanInstalled: name => call('scanInstalled', { name }),
    trust: name => call('trust', { name }),
  }
}
