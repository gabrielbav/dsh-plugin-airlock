/**
 * The chat gate for a DSH without the install-gate hook: a `tools/pre-execute` listener that vets the agent's
 * `plugin_manager` `install_bundle` calls before the tool runs. A red package is refused, a yellow one asks the person
 * with the score, a green one runs. The agent only ever learns the score and the result, never finding text, which
 * can quote the scanned package.
 */
import type { InstallGateReport, InstallGateText, PreToolDecision, SpecInspection, ToolExecution } from './dsh.ts'

/** The tool and action the gate vets. */
export const TOOL = 'plugin_manager'
export const ACTION = 'install_bundle'

/** An exact semver version, the only registry form whose files cannot change between the scan and the install. */
const EXACT_VERSION = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/

/**
 * Whether a registry spec names one exact version: `name@1.2.3` or `@scope/name@1.2.3`.
 * @param spec Registry spec.
 * @returns True when the part after the name's `@` is an exact version.
 */
export function pinned(spec: string): boolean {
  const at = spec.lastIndexOf('@')
  return at > 0 && EXACT_VERSION.test(spec.slice(at + 1))
}

/** What the gate needs from the rest of Airlock. */
export interface ChatGateDeps {
  /** Whether the gate runs: false while the install-gate hook vets installs, so nothing is scanned twice. */
  readonly active: () => boolean
  readonly inspect: (spec: string, registry: string | undefined, signal: AbortSignal | undefined) => Promise<SpecInspection>
  /** Quarantine and scan a spec, save its report, and trust its digest unless it is blocked. */
  readonly scan: (spec: string, registry: string | null, signal: AbortSignal) => Promise<InstallGateReport>
}

function subject(report: InstallGateReport): string {
  const name = report.packageName ?? report.spec
  return report.version === undefined ? name : `${name}@${report.version}`
}

function score(report: InstallGateReport): string {
  return `${report.score ?? '—'}/100`
}

/** The approval card's text for a package that needs review. */
export function reviewText(report: InstallGateReport): InstallGateText {
  const what = subject(report)
  const value = score(report)
  return {
    en: `Airlock security score ${value} for ${what}: review needed. Open Plugins → Airlock → Recent scans to read the findings before you approve.`,
    pt: `Pontuação de segurança do Airlock ${value} para ${what}: revisão necessária. Abra Plugins → Airlock → Verificações recentes para ler os achados antes de aprovar.`,
    zh: `Airlock 为 ${what} 给出的安全评分为 ${value}：需要审查。批准前，请在“插件 → Airlock → 最近的扫描”中查看发现的问题。`,
  }
}

function deny(reason: string): PreToolDecision {
  return { kind: 'deny', reason }
}

function message(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).split('\n', 1)[0]?.slice(0, 300) ?? ''
}

/**
 * Rule on one tool call before it runs.
 * @param exec The pending call.
 * @param next The rest of the pre-execute chain.
 * @param deps Scan and inspection facilities.
 * @returns The ruling; any failure to vet refuses the call.
 */
export async function chatGate(exec: ToolExecution, next: () => Promise<PreToolDecision>, deps: ChatGateDeps): Promise<PreToolDecision> {
  if (exec.name !== TOOL || !deps.active()) return next()
  const args = typeof exec.arguments === 'object' && exec.arguments !== null ? exec.arguments as Record<string, unknown> : {}
  if (args.action !== ACTION) return next()
  const target = args.target
  // Without a target the tool refuses the call itself; nothing can install.
  if (typeof target !== 'string' || target.trim() === '') return next()
  const registry = typeof args.registry === 'string' && args.registry !== '' ? args.registry : undefined
  try {
    const inspection = await deps.inspect(target, registry, exec.signal)
    if (inspection.status === 'refused') return deny(`Airlock could not check ${target} before installing it: ${inspection.reason.slice(0, 300)}`)
    if (inspection.kind === 'registry' && !pinned(target)) {
      if (inspection.name === undefined || inspection.version === undefined) {
        return deny(`Airlock vets one exact version. Call install_bundle again with target "<package>@<exact version>".`)
      }
      return deny(`Airlock vets one exact version, so the scanned files are the ones that install. Call install_bundle again with target "${inspection.name}@${inspection.version}".`)
    }
    const report = await deps.scan(target, registry ?? inspection.registry, exec.signal ?? new AbortController().signal)
    if (report.level === 'block') {
      return deny(`Airlock blocked ${subject(report)}: security score ${score(report)}, high risk. Nothing was installed. Do not retry this package. Tell the user that Airlock blocked it and that the full report is under Plugins → Airlock → Recent scans.`)
    }
    if (report.level === 'review') {
      // Later listeners still rule; a stricter ruling than asking wins.
      const rest = await next()
      if (rest.kind !== 'allow') return rest
      return { kind: 'ask', reason: `Airlock security score ${score(report)} for ${subject(report)}: review needed`, displayReason: reviewText(report) }
    }
    return next()
  } catch (error) {
    return deny(`Airlock could not vet ${target}, so it was not installed: ${message(error)}`)
  }
}
