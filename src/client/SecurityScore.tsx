/**
 * The security score card: score dial, level, reasons, scanner statuses, findings by severity, and the
 * acknowledgement a `review` installation needs. Finding text is untrusted scanner output and renders as plain text.
 */
import { useId, useState, type ReactNode } from 'react'
import { Button, Checkbox, Tag, type TagTone } from '@deepseek-ai/dsh-client-ui-primitives'
import type { SecurityLevel, SecurityReport, SecuritySeverity, Translate } from './dsh.ts'
import type { AirlockKey } from './locales.ts'

/** Translate seat of the `airlock` namespace. */
export type AirlockT = Translate<AirlockKey>

/** Findings shown before the list unfolds. */
const FOLDED_FINDINGS = 5

const LEVEL_KEYS = { pass: 'levelPass', review: 'levelReview', block: 'levelBlock' } as const satisfies Record<SecurityLevel, string>

const LEVEL_TONES = { pass: 'success', review: 'warning', block: 'danger' } as const satisfies Record<SecurityLevel, TagTone>

const SEVERITY_TONES = {
  critical: 'danger', high: 'danger', medium: 'warning', low: 'neutral', info: 'quiet',
} as const satisfies Record<SecuritySeverity, TagTone>

/**
 * The tag tone of a security level.
 * @param level - the report's level.
 * @returns green, amber or red tone.
 */
export function levelTone(level: SecurityLevel): TagTone {
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
export function scannerLabel(t: AirlockT, id: string): string {
  return NAMED_SCANNERS.has(id) ? t(`scanner.${id}` as AirlockKey) : id
}

/** The score dial: a ring filled to the score, colored by level. */
function ScoreDial({ score, level }: { readonly score: number; readonly level: SecurityLevel }): ReactNode {
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
 * @param props.t - translate seat.
 * @returns the card.
 */
export function SecurityScore({ report, outcome, acknowledge, t }: {
  readonly report: SecurityReport
  readonly outcome: 'review' | 'blocked' | 'installed'
  readonly acknowledge?: (() => void) | undefined
  readonly t: AirlockT
}): ReactNode {
  const titleId = useId()
  const [accepted, setAccepted] = useState(false)
  const [unfolded, setUnfolded] = useState(false)
  const summary = outcome === 'blocked' ? 'outcomeBlock'
    : outcome === 'review' ? 'outcomeReview'
      : report.level === 'pass' ? 'outcomePass' : 'outcomeReviewInstalled'
  const findings = unfolded ? report.findings : report.findings.slice(0, FOLDED_FINDINGS)
  const total = report.findings.length + report.omittedFindings
  return (
    <section className="airlock-card" data-level={report.level} role="group" aria-labelledby={titleId} data-airlock-score={report.score}>
      <header className="airlock-head">
        <ScoreDial score={report.score} level={report.level} />
        <div className="airlock-head-text">
          <h3 id={titleId} className="airlock-title">{t('title')}</h3>
          <Tag tone={LEVEL_TONES[report.level]}>{t(LEVEL_KEYS[report.level])}</Tag>
        </div>
      </header>
      <p className="airlock-summary" role={outcome === 'blocked' ? 'alert' : undefined}>{t(summary)}</p>
      <p className="airlock-meta">{t('inventory', {
        skills: String(report.inventory.skills), prompts: String(report.inventory.prompts),
        mcpTools: String(report.inventory.mcpTools), dependencies: String(report.inventory.dependencies),
      })}</p>
      {report.reasons.length === 0 ? null : (
        <div className="airlock-block">
          <h4 className="airlock-block-title">{t('reasonsTitle')}</h4>
          <ul className="airlock-reasons">
            {report.reasons.map(reason => <li key={reason}>{t(`reason.${reason}`)}</li>)}
          </ul>
        </div>
      )}
      <div className="airlock-block">
        <h4 className="airlock-block-title">{t('scannersTitle')}</h4>
        <ul className="airlock-scanners">
          {report.scanners.map(scanner => (
            <li key={scanner.id} className="airlock-scanner" data-status={scanner.status} title={scanner.detail}>
              <span className="airlock-scanner-name">{scannerLabel(t, scanner.id)}</span>
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
                <li key={`${finding.scanner}:${index}`} className="airlock-finding">
                  <Tag tone={SEVERITY_TONES[finding.severity]}>{t(`severity.${finding.severity}`)}</Tag>
                  <span className="airlock-finding-body">
                    <span className="airlock-finding-title">{finding.title}</span>
                    <span className="airlock-finding-where">
                      {scannerLabel(t, finding.scanner)}
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
            <Button variant="primary" className="airlock-wide" disabled={!accepted} onClick={acknowledge}>{t('installAnyway')}</Button>
          </div>
        )
        : null}
    </section>
  )
}
