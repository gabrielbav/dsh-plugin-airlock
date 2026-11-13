/**
 * Airlock's sections on a bundle's Plugins page: the stored report, and for a third-party bundle that installed
 * without an Airlock scan, a notice with **Scan now** and **Trust without scanning**.
 */
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Button, Tag } from '@deepseek-ai/dsh-client-ui-primitives'
import type { InstallGateReport, InstallGateText, PluginsSubject } from './dsh.ts'
import type { AirlockApi, BundleState } from './rpc.ts'
import { levelTone, SecurityScore, type AirlockT } from './SecurityScore.tsx'

/** Bundles whose state changed on this page, so the badge and the section read it again together. */
const changed = new EventTarget()
const announce = (name: string): void => { changed.dispatchEvent(new CustomEvent('change', { detail: name })) }

/** A bundle Airlock has not vetted in its current form. */
function untrusted(state: BundleState | null): boolean {
  return state?.status === 'unscanned' || state?.status === 'changed'
}

/** Load a bundle subject's stored report and audit state. */
function useBundle(subject: PluginsSubject, api: AirlockApi): {
  report: InstallGateReport | null; state: BundleState | null; reload: () => void
  set: (report: InstallGateReport | null, state: BundleState | null) => void
} {
  const pkg = subject.kind === 'bundle' ? subject.pkg.name : undefined
  const [value, setValue] = useState<{ pkg?: string; report: InstallGateReport | null; state: BundleState | null }>({ report: null, state: null })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (pkg === undefined) return undefined
    let live = true
    Promise.all([api.report(pkg).catch(() => null), api.bundleStatus(pkg).catch(() => null)]).then(([report, state]) => {
      if (live) setValue({ pkg, report, state })
    }, () => {})
    return () => { live = false }
  }, [pkg, api, tick])
  const reload = useCallback(() => { setTick(current => current + 1) }, [])
  useEffect(() => {
    const listener = (event: Event): void => { if ((event as CustomEvent<string>).detail === pkg) reload() }
    changed.addEventListener('change', listener)
    return () => { changed.removeEventListener('change', listener) }
  }, [pkg, reload])
  const set = useCallback((report: InstallGateReport | null, state: BundleState | null) => { setValue({ ...pkg === undefined ? {} : { pkg }, report, state }) }, [pkg])
  return value.pkg === pkg ? { report: value.report, state: value.state, reload, set } : { report: null, state: null, reload, set }
}

/**
 * The tag beside a bundle's title.
 * @returns the score, a "Not scanned" warning, or nothing.
 */
export function BundleBadge({ subject, api, t }: { readonly subject: PluginsSubject; readonly api: AirlockApi; readonly t: AirlockT }): ReactNode {
  const { report, state } = useBundle(subject, api)
  if (untrusted(state)) return <Tag tone="warning">{t(state?.status === 'changed' ? 'auditChangedBadge' : 'auditUnscannedBadge')}</Tag>
  return report === null ? null : <Tag tone={levelTone(report.level)}>{t('badge', { score: String(report.score ?? '—') })}</Tag>
}

/**
 * The section under a bundle's own content.
 * @returns the audit notice and the report, or nothing for bundles Airlock has nothing to say about.
 */
export function BundleSection({ subject, api, t, resolve }: {
  readonly subject: PluginsSubject
  readonly api: AirlockApi
  readonly t: AirlockT
  readonly resolve: (text: InstallGateText) => string
}): ReactNode {
  const { report, state, set } = useBundle(subject, api)
  const [busy, setBusy] = useState<'scan' | 'trust' | null>(null)
  const [error, setError] = useState<string | null>(null)
  // A scan from this page that still needs the person's decision.
  const [pending, setPending] = useState<InstallGateReport | null>(null)
  const name = subject.kind === 'bundle' ? subject.pkg.name : undefined
  if (name === undefined) return null

  const scan = async (): Promise<void> => {
    setBusy('scan'); setError(null)
    try {
      const scanned = await api.scanInstalled(name)
      set(scanned.report, scanned.state)
      setPending(untrusted(scanned.state) ? scanned.report : null)
      announce(name)
    } catch (failure) { setError(failure instanceof Error ? failure.message : String(failure)) }
    finally { setBusy(null) }
  }
  const trust = async (): Promise<void> => {
    setBusy('trust'); setError(null)
    try { set(report, await api.trust(name)); setPending(null); announce(name) }
    catch (failure) { setError(failure instanceof Error ? failure.message : String(failure)) }
    finally { setBusy(null) }
  }

  const notice = untrusted(state)
    ? (
      <section className="airlock-card" data-level="review" role="group" data-airlock-audit={state?.status}>
        <h3 className="airlock-title">{t(state?.status === 'changed' ? 'auditChangedTitle' : 'auditUnscannedTitle')}</h3>
        <p className="airlock-summary">
          {t(state?.status === 'changed' ? 'auditChangedText' : 'auditUnscannedText')}
          {' '}
          {state?.disabledByAirlock === true ? t('auditDisabled') : state?.enabled === true ? t('auditStillOn') : ''}
        </p>
        <div className="airlock-save">
          <Button size="sm" variant="primary" disabled={busy !== null} onClick={() => { void scan() }}>{busy === 'scan' ? t('scanningShort') : t('auditScanNow')}</Button>
          {pending === null
            ? <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => { void trust() }}>{t('auditTrust')}</Button>
            : null}
        </div>
        {busy === 'scan' ? <p className="airlock-meta" role="status">{t('scanning')}</p> : null}
        {error === null ? null : <p className="airlock-meta airlock-error" role="alert">{error}</p>}
      </section>
    )
    : null

  const shown = pending ?? report
  return (
    <>
      {notice}
      {shown === null ? null : (
        <SecurityScore report={shown}
          outcome={pending === null ? 'installed' : pending.level === 'block' ? 'blocked' : 'review'}
          acknowledge={pending?.level === 'review' ? () => { void trust() } : undefined}
          acknowledgeLabel={t('auditAcceptAndEnable')}
          summaryText={pending === null ? undefined : t(pending.level === 'block' ? 'auditBlockedText' : 'auditReviewText')}
          t={t} resolve={resolve} />
      )}
    </>
  )
}
