/**
 * Type-only copies of the DeepSeek Harness interfaces Airlock uses: the plugin manager's install gate
 * (`@deepseek-ai/dsh-plugin-manager/install-gate`) and the parts of the Cordis context the Host half touches. Nothing
 * here exists at runtime, so the package loads against any DSH release that provides the install gate.
 */

export type SecurityLevel = 'pass' | 'review' | 'block'
export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type SecurityScannerStatus = 'clean' | 'findings' | 'not-applicable' | 'disabled' | 'unavailable' | 'error'
export type SecurityReason =
  | 'finding-blocks' | 'score-below-block' | 'score-below-pass' | 'findings-need-review'
  | 'scanner-unavailable' | 'scanner-error' | 'llm-not-run'

export interface SecurityScannerRun {
  readonly id: string
  readonly status: SecurityScannerStatus
  readonly findings: number
  readonly detail?: string
  readonly durationMs: number
}

export interface SecurityFinding {
  readonly scanner: string
  readonly severity: SecuritySeverity
  readonly category: string
  readonly title: string
  readonly ruleId?: string
  readonly file?: string
  readonly line?: number
}

export interface SecurityReport {
  readonly digest: string
  readonly spec: string
  readonly packageName?: string
  readonly version?: string
  readonly score: number
  readonly level: SecurityLevel
  readonly reasons: readonly SecurityReason[]
  readonly scanners: readonly SecurityScannerRun[]
  readonly findings: readonly SecurityFinding[]
  readonly omittedFindings: number
  readonly inventory: { readonly skills: number; readonly prompts: number; readonly mcpTools: number; readonly dependencies: number }
  readonly scannedAt: string
}

export interface QuarantineFetchResult {
  readonly exitCode: number | null
  readonly output: string
  readonly packageDir?: string
}

export interface InstallGateRequest {
  readonly spec: string
  readonly registry: string | null
  readonly fetch: (dir: string, signal: AbortSignal) => Promise<QuarantineFetchResult>
  readonly log: (text: string, stream: 'stdout' | 'stderr') => void
  readonly signal: AbortSignal
}

export interface InstallGateVerdict {
  readonly report: SecurityReport
  readonly verifyInstalled: (dir: string) => Promise<boolean>
  readonly dispose: () => Promise<void>
}

export interface InstallGate {
  readonly id: string
  vet(request: InstallGateRequest): Promise<InstallGateVerdict>
}

/** One exact Fetch route on the Host connection. */
export interface FetchRoute {
  readonly path: string
  readonly methods: readonly string[]
  readonly requestBody: 'buffered'
  readonly fetch: (request: Request) => Promise<Response>
}

/** The Cordis context members the Host half uses. */
export interface HostContext {
  readonly pluginManager: { registerInstallGate(gate: InstallGate): () => void }
  readonly profileContext: { readonly dir: string }
  readonly logger: { warn(...args: unknown[]): void; info(...args: unknown[]): void }
  readonly reflect: { provide(name: string, value: unknown): () => void }
  effect(execute: () => () => void | Promise<void>, label?: string): void
  inject(names: readonly string[], callback: (ctx: HostContext & { readonly connection: { fetch: { register(route: FetchRoute): () => void } } }) => void): void
}
