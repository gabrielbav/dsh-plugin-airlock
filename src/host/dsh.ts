/**
 * Type-only copies of the DeepSeek Harness interfaces Airlock uses: the plugin manager's install gate
 * (`@deepseek-ai/dsh-plugin-manager/install-gate`) and the parts of the Cordis context the Host half touches. Nothing
 * here exists at runtime, so the package loads against any DSH release that provides the install gate.
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

/** The Cordis context members the Host half uses. */
export interface HostContext {
  readonly pluginManager: { registerInstallGate(gate: InstallGate): () => void }
  readonly profileContext: { readonly dir: string }
  readonly logger: { warn(...args: unknown[]): void; info(...args: unknown[]): void }
  readonly reflect: { provide(name: string, value: unknown): () => void }
  /** Optional services; `llm` is the model-call service when the profile mounts it. */
  get(name: 'llm'): LlmService | undefined
  effect(execute: () => () => void | Promise<void>, label?: string): void
  inject(names: readonly string[], callback: (ctx: HostContext & { readonly connection: { fetch: { register(route: FetchRoute): () => void } } }) => void): void
}
