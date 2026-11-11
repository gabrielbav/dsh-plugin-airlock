/** Airlock configuration, settings and scanner extension types. */
import type { InstallGateFinding, InstallGateSeverity } from './dsh.ts'
import type { Inventory } from './engine/quarantine.ts'

/** The scanners Airlock ships adapters for. */
export const BUILTIN_SCANNERS = ['cisco-skill-scanner', 'skillscan', 'cisco-mcp-scanner', 'osv-scanner', 'trivy', 'gitleaks'] as const

/** One built-in scanner id. */
export type BuiltinScannerId = typeof BUILTIN_SCANNERS[number]

/** One scanner's switch and executable. */
export interface ScannerConfig {
  readonly enabled: boolean
  /** Executable name looked up on `searchPaths` then `PATH`, or an absolute path. */
  readonly command: string
}

/** What a custom SARIF scanner reads in the quarantine. */
export type CustomScannerTarget = 'package' | 'lockfile'

/**
 * A scanner added from settings: any tool that writes a SARIF 2.1 report. `args` may contain `{target}` (the
 * directory scanned) and `{output}` (a report file path); without `{output}` the report is read from stdout.
 */
export interface CustomScanner {
  /** Lower-case id, unique among scanners. */
  readonly id: string
  readonly name: string
  readonly enabled: boolean
  readonly command: string
  readonly args: readonly string[]
  readonly target: CustomScannerTarget
  /** Exit codes that still carry a report; anything else is an error. */
  readonly okExitCodes: readonly number[]
}

/** How findings become a score and a level. */
export interface AirlockPolicy {
  /** Scores at or above this pass when nothing else needs review. */
  readonly passScore: number
  /** A score below this, counting package-content findings only, blocks; dependency advisories block only at `dependencyBlockSeverity`. */
  readonly blockScore: number
  /** A package-content finding at or above this severity blocks. */
  readonly blockSeverity: InstallGateSeverity
  /** A dependency vulnerability at or above this severity blocks. */
  readonly dependencyBlockSeverity: InstallGateSeverity
  /** Any finding at or above this severity requires review. */
  readonly reviewSeverity: InstallGateSeverity
  /**
   * The highest severity a dependency advisory keeps when it can only affect availability (denial of service, memory or
   * CPU exhaustion) and cannot expose data or change behavior.
   */
  readonly availabilitySeverity: InstallGateSeverity
  readonly weights: Readonly<Record<InstallGateSeverity, number>>
  readonly dependencyWeight: number
  /** Without the LLM analyzers a package cannot pass; it is reviewed at best. */
  readonly requireLlm: boolean
}

/**
 * The LLM judge used by Cisco Skill Scanner and Cisco MCP Scanner: one model from the DSH model catalog, reached
 * through Airlock's local bridge, so no key or URL is configured here.
 */
export interface AirlockLlmConfig {
  readonly enabled: boolean
  /** DSH provider route, as the chat's model selector lists it. */
  readonly provider: string
  /** Model id within that provider. */
  readonly model: string
}

/** Effective configuration: Cordis config with the person's saved settings applied on top. */
export interface AirlockConfig {
  readonly scanners: Readonly<Record<BuiltinScannerId, ScannerConfig>>
  readonly custom: readonly CustomScanner[]
  /** Directories searched for scanner executables before `PATH`; `~` expands to the home directory. */
  readonly searchPaths: readonly string[]
  readonly scannerTimeoutMs: number
  readonly maxFindings: number
  readonly promptMinChars: number
  readonly maxJsonBytes: number
  readonly policy: AirlockPolicy
  readonly llm: AirlockLlmConfig
  /** The command the settings page runs to install each built-in scanner. */
  readonly installCommands: Readonly<Record<BuiltinScannerId, readonly string[]>>
  /** Bound on one scanner installation, in milliseconds. */
  readonly installTimeoutMs: number
}

/** What a person can change on the settings page; saved beside the profile and applied over the Cordis config. */
export interface AirlockSettings {
  readonly scanners?: Partial<Record<BuiltinScannerId, Partial<ScannerConfig>>>
  readonly custom?: readonly CustomScanner[]
  readonly policy?: Partial<Omit<AirlockPolicy, 'weights'>>
  readonly llm?: Partial<AirlockLlmConfig>
}

/** One scanner's raw outcome before scoring. */
export interface ScannerOutcome {
  readonly id: string
  readonly status: 'clean' | 'findings' | 'not-applicable' | 'disabled' | 'unavailable' | 'error'
  readonly findings: readonly ScannedFinding[]
  readonly detail?: string
  readonly durationMs: number
  /** Whether an LLM analyzer contributed to this outcome. */
  readonly usedLlm: boolean
}

/** A finding with the facts scoring needs. */
export interface ScannedFinding extends InstallGateFinding {
  /** Dependency vulnerabilities score and block on their own thresholds. */
  readonly dependency: boolean
  /** Equal keys from different scanners count once. */
  readonly dedupeKey: string
  /** Further keys naming the same issue, such as a vulnerability's CVE and GHSA aliases; any shared key counts once. */
  readonly aliasKeys?: readonly string[]
}

/** Everything one scanner reads. */
export interface ScanContext {
  /** The copied package files. */
  readonly subject: string
  /** Synthetic skills extracted from prompts. */
  readonly promptsRoot: string
  /** The quarantine pnpm project holding `pnpm-lock.yaml`. */
  readonly fetchDir: string
  /** Scratch directory for report files. */
  readonly outDir: string
  readonly inventory: Inventory
  readonly config: AirlockConfig
  readonly signal: AbortSignal
  /** The resolved executable of this scanner; empty for a scanner that names no command. */
  readonly executable: string
  /** The running LLM bridge, when the judge is on and its model is available. */
  readonly llm?: {
    readonly baseUrl: string
    readonly apiKey: string
    /** Model replies the bridge sent for one model name. */
    readonly calls: (model: string) => number
  }
}

/**
 * A scanner another plugin registers through `ctx.airlock.registerScanner`. `run` must fail closed: report `error`
 * for anything it does not recognize, never `clean`.
 */
export interface ScannerAdapter {
  /** Lower-case id, unique among scanners. */
  readonly id: string
  /** Display name. */
  readonly name: string
  /** Executable resolved before `run`; a missing one reports `unavailable`. Omit for scanners that run in-process. */
  readonly command?: string
  run(ctx: ScanContext): Promise<ScannerOutcome>
}

/** A scanner ready for one scan: its adapter, switch and command. */
export interface ResolvedScanner {
  readonly id: string
  readonly name: string
  readonly enabled: boolean
  readonly command: string | undefined
  readonly origin: 'builtin' | 'custom' | 'plugin'
  run(ctx: ScanContext): Promise<ScannerOutcome>
}

/** Scanner availability as the settings page shows it. */
export interface AirlockScannerInfo {
  readonly id: string
  readonly name: string
  readonly origin: ResolvedScanner['origin']
  readonly enabled: boolean
  readonly command: string | null
  /** Resolved executable, or null when missing, disabled, or in-process. */
  readonly executable: string | null
  /** Whether the settings page can install it. */
  readonly installable: boolean
}

/** The service other plugins reach as `ctx.airlock`. */
export interface AirlockService {
  /**
   * Add a scanner to every later scan.
   * @param adapter The scanner.
   * @returns The disposer that removes it; call it from the registering plugin's `ctx.effect`.
   */
  registerScanner(adapter: ScannerAdapter): () => void
}
