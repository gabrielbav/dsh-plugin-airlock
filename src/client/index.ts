/**
 * Airlock, browser half: the security score in the install dialog (`plugins.install.gate`), a score tag and the
 * full report on scanned bundles' pages, and the settings page on Airlock's own bundle page.
 */
import { createElement, useEffect, useState, type ReactNode } from 'react'
import { Tag } from '@deepseek-ai/dsh-client-ui-primitives'
import type { ClientContext, ConfigViewProps, DetailProps, InstallGateText, InstallGateProps, PluginsSubject, InstallGateReport } from './dsh.ts'
import { de, en, es, fr, ja, pt, ru, zh } from './locales.ts'
import { airlockApi, type AirlockApi } from './rpc.ts'
import { levelTone, SecurityScore, type AirlockT } from './SecurityScore.tsx'
import { Settings } from './Settings.tsx'
import { STYLES } from './styles.ts'

/** Services the contribution uses; `connection` carries the Host routes. */
export const inject = ['slots', 'locale', 'connection']

/** Dictionary namespace. */
const NS = 'airlock'

/** The package name, which keys this bundle's own config page. */
const PACKAGE = 'dsh-plugin-airlock'

/** Load the stored report of a bundle subject; null for other subjects or before it arrives. */
function useReport(subject: PluginsSubject, api: AirlockApi): InstallGateReport | null {
  const [report, setReport] = useState<InstallGateReport | null>(null)
  const pkg = subject.kind === 'bundle' ? subject.pkg.name : undefined
  useEffect(() => {
    if (pkg === undefined) return undefined
    let live = true
    api.report(pkg).then((value) => { if (live) setReport(value) }, () => { if (live) setReport(null) })
    return () => { live = false }
  }, [pkg, api])
  return pkg === undefined ? null : report
}

/**
 * Register the dictionaries, styles and slot entries.
 * @param ctx - client plugin context.
 */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { en, zh, ja, es, fr, de, ru, pt }), 'airlock: locale')
  ctx.effect(() => {
    const style = document.createElement('style')
    style.dataset.plugin = PACKAGE
    style.textContent = STYLES
    document.head.appendChild(style)
    return () => { style.remove() }
  }, 'airlock: styles')
  const api = airlockApi(ctx)
  const resolve = (text: InstallGateText): string => ctx.locale.resolveText(text)
  ctx.slots.inject('plugins.install.gate', () => ctx.slots.register({ name: 'plugins.install.gate', id: 'airlock', locale: NS },
    (props: InstallGateProps & { t: AirlockT }): ReactNode => createElement(SecurityScore, { ...props, resolve })))
  ctx.slots.inject('plugins.detail.badge', () => ctx.slots.register({ name: 'plugins.detail.badge', id: 'airlock', locale: NS },
    ({ subject, t }: DetailProps & { t: AirlockT }): ReactNode => {
      const report = useReport(subject, api)
      return report === null ? null : createElement(Tag, { tone: levelTone(report.level) }, t('badge', { score: String(report.score ?? '—') }))
    }))
  ctx.slots.inject('plugins.detail.section', () => ctx.slots.register({ name: 'plugins.detail.section', id: 'airlock', locale: NS },
    ({ subject, t }: DetailProps & { t: AirlockT }): ReactNode => {
      const report = useReport(subject, api)
      return report === null ? null : createElement(SecurityScore, { report, outcome: 'installed', t, resolve })
    }))
  ctx.slots.inject('plugins.bundle.config', () => ctx.slots.register({ name: 'plugins.bundle.config', key: PACKAGE, locale: NS },
    ({ view, t }: ConfigViewProps & { t: AirlockT }): ReactNode => createElement(Settings, { view, api, t })))
}
