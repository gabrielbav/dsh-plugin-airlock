/**
 * The security score card: score dial, level, reasons, scanner statuses, findings by severity, and the
 * acknowledgement a `review` installation needs. Finding text is untrusted scanner output and renders as plain text.
 */
import { useId, useState, type ReactNode } from 'react'
import { Button, Checkbox, Tag, type TagTone } from '@deepseek-ai/dsh-client-ui-primitives'
import type { InstallGateFinding, InstallGateLevel, InstallGateReport, InstallGateSeverity, InstallGateText, Translate } from './dsh.ts'
import type { AirlockKey } from './locales.ts'

/** Translate seat of the `airlock` namespace. */
export type AirlockT = Translate<AirlockKey>

/** Findings shown before the list unfolds. */
const FOLDED_FINDINGS = 5

const LEVEL_KEYS = { pass: 'levelPass', review: 'levelReview', block: 'levelBlock' } as const satisfies Record<InstallGateLevel, string>

const LEVEL_TONES = { pass: 'success', review: 'warning', block: 'danger' } as const satisfies Record<InstallGateLevel, TagTone>

const SEVERITY_TONES = {
  critical: 'danger', high: 'danger', medium: 'warning', low: 'neutral', info: 'quiet',
} as const satisfies Record<InstallGateSeverity, TagTone>

/**
 * The tag tone of a security level.
 * @param level - the report's level.
 * @returns green, amber or red tone.
 */
export function levelTone(level: InstallGateLevel): TagTone {
  return LEVEL_TONES[level]
}

/** Scanner ids with a dictionary name; others show their id. */
const NAMED_SCANNERS = new Set(['cisco-skill-scanner', 'skillscan', 'cisco-mcp-scanner', 'osv-scanner', 'trivy', 'gitleaks', 'airlock'])

/**
 * A scanner's display name.
 * @param t - translate seat.
 * @param id - scanner id.
 * @returns the product name for a built-in scanner, else the id.
 */
export function scannerLabel(t: AirlockT, id: string, name?: string): string {
  return NAMED_SCANNERS.has(id) ? t(`scanner.${id}` as AirlockKey) : name ?? id
}

/** Impact categories Airlock assigns to dependency advisories. */
const IMPACTS = new Set(['denial-of-service', 'data-exposure', 'integrity', 'vulnerability'])

type AreaResult = 'ok' | 'found' | 'na' | 'error' | 'incomplete'

/** One security area of the summary: its checks and the findings that belong to it. */
interface Area {
  readonly id: 'instructions' | 'mcp' | 'dependencies' | 'secrets' | 'config'
  readonly checks: readonly string[]
  readonly owns: (finding: InstallGateFinding) => boolean
  readonly applicable: (metrics: Readonly<Record<string, number>>) => boolean
}

const AREAS: readonly Area[] = [
  { id: 'instructions', checks: ['cisco-skill-scanner', 'skillscan'], owns: f => f.source === 'cisco-skill-scanner' || f.source === 'skillscan',
    applicable: m => (m.skills ?? 0) + (m.prompts ?? 0) > 0 },
  { id: 'mcp', checks: ['cisco-mcp-scanner'], owns: f => f.source === 'cisco-mcp-scanner', applicable: m => (m.mcpTools ?? 0) > 0 },
  { id: 'dependencies', checks: ['osv-scanner', 'trivy'], owns: f => IMPACTS.has(f.category), applicable: () => true },
  { id: 'secrets', checks: ['gitleaks', 'trivy'], owns: f => f.category === 'secret', applicable: () => true },
  { id: 'config', checks: [], owns: f => f.source === 'airlock', applicable: () => true },
]

const RESULT_TONES = { ok: 'success', found: 'warning', na: 'quiet', error: 'danger', incomplete: 'danger' } as const satisfies Record<AreaResult, TagTone>

/** The plain-language summary of what Airlock checked, by security area. */
function CheckSummary({ report, t }: { readonly report: InstallGateReport; readonly t: AirlockT }): ReactNode {
  const metrics = report.metrics ?? {}
  const checks = report.checks ?? []
  const covered = new Set(AREAS.flatMap(area => area.checks))
  const vars = {
    skills: String(metrics.skills ?? 0), prompts: String(metrics.prompts ?? 0), tools: String(metrics.mcpTools ?? 0),
    packages: String(metrics.dependencies ?? 0),
  }
  const rows = AREAS.map((area) => {
    const own = checks.filter(check => area.checks.includes(check.id))
    const findings = report.findings.filter(area.owns)
    const result: AreaResult = own.some(check => check.status === 'error') ? 'error'
      : own.some(check => check.status === 'unavailable') ? 'incomplete'
        : !area.applicable(metrics) ? 'na'
          : findings.length > 0 ? 'found' : 'ok'
    const dos = findings.filter(finding => finding.category === 'denial-of-service').length
    const detail = result === 'na' ? t(`na.${area.id}` as AirlockKey)
      : result === 'ok' ? t(`detail.${area.id}.none` as AirlockKey, vars)
        : area.id === 'dependencies' && result === 'found'
          ? t('detail.dependencies.found', { ...vars, count: String(findings.length), security: String(findings.length - dos), dos: String(dos) })
          : null
    return { area, result, detail, count: findings.length }
  })
  const others = checks.filter(check => !covered.has(check.id))
  return (
    <div className="airlock-block">
      <h4 className="airlock-block-title">{t('checkedTitle')}</h4>
      <ul className="airlock-areas">
        {rows.map(({ area, result, detail, count }) => (
          <li key={area.id} className="airlock-area" data-result={result}>
            <span className="airlock-area-head">
              <span className="airlock-area-name">{t(`area.${area.id}`)}</span>
              <Tag tone={RESULT_TONES[result]}>{t(`result.${result}`, { count: String(count) })}</Tag>
            </span>
            {detail === null ? null : <span className="airlock-area-detail">{detail}</span>}
          </li>
        ))}
        {others.length === 0 ? null : (
          <li className="airlock-area">
            <span className="airlock-area-head"><span className="airlock-area-name">{t('area.other')}</span></span>
            <span className="airlock-area-detail">{others.map(check => `${check.name ?? check.id}: ${t(`status.${check.status}`, { count: String(check.findings) })}`).join(' · ')}</span>
          </li>
        )}
      </ul>
    </div>
  )
}

/** The score dial: a ring filled to the score, colored by level. */
function ScoreDial({ score, level }: { readonly score: number; readonly level: InstallGateLevel }): ReactNode {
  const radius = 26
  const circumference = 2 * Math.PI * radius
  return (
    <span className="airlock-dial" data-level={level} aria-hidden="true">
      <svg width="64" height="64" viewBox="0 0 64 64">
        <circle className="airlock-dial-track" cx="32" cy="32" r={radius} />
        <circle className="airlock-dial-value" cx="32" cy="32" r={radius}
          strokeDasharray={circumference} strokeDashoffset={circumference * (1 - score / 100)} />
      </svg>
      <span className="airlock-dial-score">{score}</span>
    </span>
  )
}

/**
 * Render a report.
 * @param props.report - the gate's report.
 * @param props.outcome - `review` waits for acknowledgement, `blocked` was refused, `installed` finished.
 * @param props.acknowledge - repeat the installation with the report acknowledged; present only for `review`.
 * @param props.acknowledgeLabel - the acknowledgement button's label, when it does something other than install.
 * @param props.t - translate seat.
 * @param props.resolve - localized-text resolver.
 * @returns the card.
 */
export function SecurityScore({ report, outcome, acknowledge, acknowledgeLabel, summaryText, t, resolve }: {
  readonly report: InstallGateReport
  readonly outcome: 'review' | 'blocked' | 'installed'
  readonly acknowledge?: (() => void) | undefined
  /** The acknowledgement button's label; "Install anyway" when absent. */
  readonly acknowledgeLabel?: string | undefined
  /** The sentence under the title, when the outcome's own wording does not fit. */
  readonly summaryText?: string | undefined
  readonly t: AirlockT
  /** Pick the person's locale from a gate's localized text. */
  readonly resolve: (text: InstallGateText) => string
}): ReactNode {
  const titleId = useId()
  const score = report.score ?? 0
  const metrics = report.metrics ?? {}
  const [accepted, setAccepted] = useState(false)
  const [unfolded, setUnfolded] = useState(false)
  const summary = outcome === 'blocked' ? 'outcomeBlock'
    : outcome === 'review' ? 'outcomeReview'
      : report.level === 'pass' ? 'outcomePass' : 'outcomeReviewInstalled'
  const findings = unfolded ? report.findings : report.findings.slice(0, FOLDED_FINDINGS)
  const total = report.findings.length + report.omittedFindings
  return (
    <section className="airlock-card" data-level={report.level} role="group" aria-labelledby={titleId} data-airlock-score={score}>
      <header className="airlock-head">
        <ScoreDial score={score} level={report.level} />
        <div className="airlock-head-text">
          <h3 id={titleId} className="airlock-title">{t('title')}</h3>
          <Tag tone={LEVEL_TONES[report.level]}>{t(LEVEL_KEYS[report.level])}</Tag>
        </div>
      </header>
      <p className="airlock-summary" role={outcome === 'blocked' ? 'alert' : undefined}>{summaryText ?? t(summary)}</p>
      <p className="airlock-meta">{t('inventory', {
        skills: String(metrics.skills ?? 0), prompts: String(metrics.prompts ?? 0),
        mcpTools: String(metrics.mcpTools ?? 0), dependencies: String(metrics.dependencies ?? 0),
      })}</p>
      <CheckSummary report={report} t={t} />
      {report.reasons.length === 0 ? null : (
        <div className="airlock-block">
          <h4 className="airlock-block-title">{t('reasonsTitle')}</h4>
          <ul className="airlock-reasons">
            {report.reasons.map((reason, index) => <li key={index}>{resolve(reason)}</li>)}
          </ul>
        </div>
      )}
      <div className="airlock-block">
        <h4 className="airlock-block-title">{t('scannersTitle')}</h4>
        <ul className="airlock-scanners">
          {(report.checks ?? []).map(scanner => (
            <li key={scanner.id} className="airlock-scanner" data-status={scanner.status} title={scanner.detail}>
              <span className="airlock-scanner-name">{scannerLabel(t, scanner.id, scanner.name)}</span>
              <span className="airlock-scanner-status">{t(`status.${scanner.status}`, { count: String(scanner.findings) })}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="airlock-block">
        <h4 className="airlock-block-title">{t('findingsTitle')}</h4>
        {report.findings.length === 0
          ? <p className="airlock-meta">{t('findingsNone')}</p>
          : (
            <ul className="airlock-findings">
              {findings.map((finding, index) => (
                <li key={`${finding.source}:${index}`} className="airlock-finding">
                  <Tag tone={SEVERITY_TONES[finding.severity]}>{t(`severity.${finding.severity}`)}</Tag>
                  <span className="airlock-finding-body">
                    <span className="airlock-finding-title">
                      {IMPACTS.has(finding.category) ? <span className="airlock-impact" data-impact={finding.category}>{t(`impact.${finding.category}` as AirlockKey)}</span> : null}
                      {finding.title}
                    </span>
                    <span className="airlock-finding-where">
                      {scannerLabel(t, finding.source)}
                      {finding.file === undefined ? null : <> · <code>{finding.file}{finding.line === undefined ? '' : `:${finding.line}`}</code></>}
                      {finding.ruleId === undefined ? null : <> · <code>{finding.ruleId}</code></>}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        {report.findings.length > FOLDED_FINDINGS
          ? (
            <button type="button" className="airlock-fold" aria-expanded={unfolded} onClick={() => { setUnfolded(!unfolded) }}>
              {unfolded ? t('findingsShowFewer') : t('findingsShowAll', { count: String(report.findings.length) })}
            </button>
          )
          : null}
        {report.omittedFindings > 0 && total > report.findings.length
          ? <p className="airlock-meta">{t('findingsMore', { count: String(report.omittedFindings) })}</p>
          : null}
      </div>
      {outcome === 'review' && acknowledge !== undefined
        ? (
          <div className="airlock-acknowledge">
            <Checkbox checked={accepted} onChange={setAccepted} label={t('acknowledge')} />
            <Button variant="primary" className="airlock-wide" disabled={!accepted} onClick={acknowledge}>{acknowledgeLabel ?? t('installAnyway')}</Button>
          </div>
        )
        : null}
    </section>
  )
}
