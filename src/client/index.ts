/**
 * Airlock, browser half: the security score in the install dialog (`plugins.install.gate`, with the install-gate
 * hook), Airlock's own scan-first install in the Add plugin menu (without it), a score or "Not scanned" tag and the
 * report on bundles' pages, and the settings page on Airlock's own bundle page.
 */
import { createElement, type ReactNode } from 'react'
import { BundleBadge, BundleSection } from './BundleAudit.tsx'
import type { ClientContext, ConfigViewProps, DetailProps, InstallGateText, InstallGateProps } from './dsh.ts'
import { InstallDialog, InstallMenuItem } from './InstallDialog.tsx'
import { de, en, es, fr, ja, pt, ru, zh } from './locales.ts'
import { airlockApi } from './rpc.ts'
import { SecurityScore, type AirlockT } from './SecurityScore.tsx'
import { Settings } from './Settings.tsx'
import { STYLES } from './styles.ts'

/** Services the contribution uses; `connection` carries the Host routes. */
export const inject = ['slots', 'locale', 'connection']

/** Dictionary namespace. */
const NS = 'airlock'

/** The package name, which keys this bundle's own config page. */
const PACKAGE = 'dsh-plugin-airlock'

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
    ({ subject, t }: DetailProps & { t: AirlockT }): ReactNode => createElement(BundleBadge, { subject, api, t })))
  ctx.slots.inject('plugins.detail.section', () => ctx.slots.register({ name: 'plugins.detail.section', id: 'airlock', locale: NS },
    ({ subject, t }: DetailProps & { t: AirlockT }): ReactNode => createElement(BundleSection, { subject, api, t, resolve })))
  ctx.slots.inject('plugins.add.actions', () => ctx.slots.register({ name: 'plugins.add.actions', id: 'airlock-install', locale: NS },
    ({ onDismiss, t }: { onDismiss: () => void; t: AirlockT }): ReactNode => createElement(InstallMenuItem, { onDismiss, api, t })))
  ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'airlock-install', locale: NS },
    ({ t }: { t: AirlockT }): ReactNode => createElement(InstallDialog, { api, t, resolve })))
  ctx.slots.inject('plugins.bundle.config', () => ctx.slots.register({ name: 'plugins.bundle.config', key: PACKAGE, locale: NS },
    ({ view, t }: ConfigViewProps & { t: AirlockT }): ReactNode => createElement(Settings, { view, api, t, resolve })))
}
