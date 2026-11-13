/**
 * Type-only copies of the DeepSeek Harness interfaces Airlock uses: the plugin manager, its optional install-gate hook
 * (`@deepseek-ai/dsh-plugin-manager/install-gate`), the tool pre-execute event, and the parts of the Cordis context
 * the Host half touches. Nothing here exists at runtime, so the package loads against stock DSH and against a DSH
 * with the install-gate hook.
 */

export interface InstallGateText { readonly en: string; readonly [locale: string]: string }
export type InstallGateLevel = 'pass' | 'review' | 'block'
export type InstallGateSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type InstallGateCheckStatus = 'clean' | 'findings' | 'not-applicable' | 'disabled' | 'unavailable' | 'error'

export interface InstallGateCheck {
  readonly id: string
  readonly name?: string
  readonly status: InstallGateCheckStatus
  readonly findings: number
  readonly detail?: string
  readonly durationMs?: number
}

export interface InstallGateFinding {
  readonly source: string
  readonly severity: InstallGateSeverity
  readonly category: string
  readonly title: string
  readonly ruleId?: string
  readonly file?: string
  readonly line?: number
}

export interface InstallGateReport {
  readonly digest: string
  readonly spec: string
  readonly packageName?: string
  readonly version?: string
  readonly level: InstallGateLevel
  readonly score?: number
  readonly reasons: readonly InstallGateText[]
  readonly checks?: readonly InstallGateCheck[]
  readonly findings: readonly InstallGateFinding[]
  readonly omittedFindings: number
  readonly metrics?: Readonly<Record<string, number>>
  readonly gates: readonly string[]
  readonly checkedAt: string
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
  readonly report: InstallGateReport
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

/** One model the DSH model catalog offers, as the chat's model selector lists it. */
export interface LlmModelInfo {
  readonly provider: string
  readonly id: string
  readonly name: string
  readonly description?: string
}

/** One chunk of a DSH model stream; Airlock reads text and the terminal result only. */
export type LlmStreamChunk =
  | { readonly type: 'text-delta'; readonly text: string }
  | { readonly type: 'finish'; readonly reason: { readonly kind: string; readonly failure?: { readonly message?: string } } }
  | { readonly type: string }

/** The DSH model-call service (`@deepseek-ai/dsh-llm`), as far as Airlock uses it. */
export interface LlmService {
  listProviders(): readonly { readonly id: string; readonly name: string }[]
  listModels(provider: string): Promise<readonly LlmModelInfo[]>
  stream(options: {
    provider: string
    model: string
    system?: string
    messages: { role: 'user'; content: { type: 'text'; text: string }[] }[]
    maxTokens?: number
    temperature?: number
    signal?: AbortSignal
  }): AsyncIterable<LlmStreamChunk>
}

/** One bundle as `pluginManager.listBundles()` reports it, as far as Airlock reads it. */
export interface BundleInfo {
  readonly name: string
  readonly official: boolean
  readonly availability: 'installation' | 'profile' | 'missing'
  readonly version?: string
  readonly enabled: boolean
  readonly installed: boolean
  /** The installation spec of a profile dependency, such as `link:/abs/dir` or `name@1.2.3`. */
  readonly source?: string
}

/** The result of a plugin manager change, as far as Airlock reads it. */
export interface ChangeResult {
  readonly application: 'applied' | 'restart-required' | 'overridden' | 'failed' | 'cancelled'
  readonly bundle?: string
  readonly version?: string
  readonly error?: { readonly code?: string; readonly message?: string }
  readonly pendingBuilds?: readonly string[]
}

/** What `pluginManager.inspect` says about a spec before anything installs. */
export type SpecInspection =
  | {
    readonly status: 'accepted'
    readonly kind: 'registry' | 'path' | 'git' | 'tarball'
    readonly name?: string
    readonly version?: string
    readonly bundle: boolean | null
    readonly registry: string | null
  }
  | { readonly status: 'refused'; readonly problem: string; readonly reason: string }

/**
 * The DSH plugin manager (`@deepseek-ai/dsh-plugin-manager`). Everything but `registerInstallGate` ships with stock
 * DSH; the install-gate hook adds that one method.
 */
export interface PluginManager {
  registerInstallGate?(gate: InstallGate): () => void
  listBundles(): Promise<BundleInfo[]>
  inspect(spec: string, options?: { registry?: string }, signal?: AbortSignal): Promise<SpecInspection>
  installBundle(spec: string, options?: {
    enabled?: boolean
    registry?: string
    expected?: { readonly name: string; readonly version: string }
    approvedBuilds?: string[]
  }): Promise<ChangeResult>
  setBundleEnabled(name: string, enabled: boolean): Promise<ChangeResult>
  removeBundle(name: string): Promise<ChangeResult>
}

/** The pnpm a profile installs with, as `profileContext.packageManager` names it. */
export interface PnpmInvocation {
  readonly command: string
  readonly args: readonly string[]
  readonly env: Readonly<Record<string, string>>
}

/** One tool call as `tools/pre-execute` listeners see it. */
export interface ToolExecution {
  readonly name: string
  readonly arguments: unknown
  readonly signal?: AbortSignal
}

/** A `tools/pre-execute` ruling. */
export type PreToolDecision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string; displayReason?: InstallGateText }

/** The Cordis context members the Host half uses. */
export interface HostContext {
  readonly pluginManager: PluginManager
  readonly profileContext: { readonly dir: string; readonly cwd?: string; readonly packageManager?: PnpmInvocation }
  readonly logger: { warn(...args: unknown[]): void; info(...args: unknown[]): void }
  readonly reflect: { provide(name: string, value: unknown): () => void }
  /** Optional services; `llm` is the model-call service when the profile mounts it. */
  get(name: 'llm'): LlmService | undefined
  effect(execute: () => () => void | Promise<void>, label?: string): void
  /** Subscribe to a Cordis event; returns the disposer. */
  on(name: 'tools/pre-execute', listener: (exec: ToolExecution, next: () => Promise<PreToolDecision>) => Promise<PreToolDecision>): () => void
  on(name: 'plugin-manager/changed', listener: (change: { reason?: string }) => void): () => void
  inject(names: readonly string[], callback: (ctx: HostContext & { readonly connection: { fetch: { register(route: FetchRoute): () => void } } }) => void): void
}
