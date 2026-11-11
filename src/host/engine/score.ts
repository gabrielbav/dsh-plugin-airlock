/** Turn scanner outcomes into a security score, a level, and the reasons for it. */
import type { InstallGateLevel, InstallGateSeverity } from '../dsh.ts'
import type { AirlockReason } from '../reasons.ts'
import type { AirlockPolicy, ScannedFinding, ScannerOutcome } from '../types.ts'

/** Severities from most to least severe. */
export const SEVERITIES: readonly InstallGateSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

/**
 * Whether `severity` is at least as severe as `threshold`.
 * @param severity Observed severity.
 * @param threshold Threshold severity.
 * @returns True when it reaches the threshold.
 */
export function atLeast(severity: InstallGateSeverity, threshold: InstallGateSeverity): boolean {
  return SEVERITIES.indexOf(severity) <= SEVERITIES.indexOf(threshold)
}

/** The ruling on a set of scanner outcomes. */
export interface Ruling {
  readonly score: number
  readonly level: InstallGateLevel
  readonly reasons: AirlockReason[]
  /** Deduplicated findings, most severe first. */
  readonly findings: ScannedFinding[]
}

/**
 * Score outcomes. The level follows the worst finding, not the average: one finding at the block severity blocks
 * whatever the other scanners report. A scanner that is unavailable or failed, or missing LLM analysis when the policy
 * requires it, caps the level at `review`.
 * @param outcomes Every scanner's outcome.
 * @param policy Thresholds and weights.
 * @returns Score, level and reasons.
 */
export function rule(outcomes: readonly ScannerOutcome[], policy: AirlockPolicy): Ruling {
  const seen = new Set<string>()
  const findings: ScannedFinding[] = []
  for (const finding of outcomes.flatMap(outcome => outcome.findings)) {
    if (seen.has(finding.dedupeKey)) continue
    seen.add(finding.dedupeKey)
    findings.push(finding)
  }
  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))
  const deduction = findings.reduce((sum, finding) => sum + policy.weights[finding.severity] * (finding.dependency ? policy.dependencyWeight : 1), 0)
  const score = Math.max(0, Math.round(100 - deduction))
  // Dependency advisories lower the shown score and ask for review, but block only at their own severity threshold.
  const contentScore = Math.max(0, Math.round(100 - findings.filter(finding => !finding.dependency).reduce((sum, finding) => sum + policy.weights[finding.severity], 0)))
  const reasons: AirlockReason[] = []
  const blocks = findings.some(finding => atLeast(finding.severity, finding.dependency ? policy.dependencyBlockSeverity : policy.blockSeverity))
  if (blocks) reasons.push('finding-blocks')
  if (contentScore < policy.blockScore) reasons.push('score-below-block')
  if (score < policy.passScore) reasons.push('score-below-pass')
  if (findings.some(finding => atLeast(finding.severity, policy.reviewSeverity))) reasons.push('findings-need-review')
  if (outcomes.some(outcome => outcome.status === 'unavailable')) reasons.push('scanner-unavailable')
  if (outcomes.some(outcome => outcome.status === 'error')) reasons.push('scanner-error')
  if (policy.requireLlm && !outcomes.some(outcome => outcome.usedLlm)) reasons.push('llm-not-run')
  const level: InstallGateLevel = blocks || contentScore < policy.blockScore ? 'block' : reasons.length > 0 ? 'review' : 'pass'
  return { score, level, reasons, findings }
}
