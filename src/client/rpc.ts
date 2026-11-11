/** Calls to the Host half's `/api/airlock.<endpoint>` routes. */
import type { AirlockConfig, AirlockScannerInfo, AirlockSettings } from '../host/types.ts'
import type { ClientContext, SecurityReport } from './dsh.ts'

/** A Host answer the caller shows as an error message. */
export class AirlockRequestError extends Error {}

/** Typed Host endpoints. */
export interface AirlockApi {
  report(name: string): Promise<SecurityReport | null>
  scanners(): Promise<AirlockScannerInfo[]>
  settings(): Promise<{ settings: AirlockSettings; effective: AirlockConfig }>
  saveSettings(settings: AirlockSettings): Promise<{ settings: AirlockSettings; effective: AirlockConfig }>
  installScanner(id: string): Promise<{ exitCode: number | null; output: string }>
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
  }
}
