/** Type-only copies of the DSH browser interfaces the client half uses. */
import type { ComponentType } from 'react'
import type { InstallGateReport } from '../host/dsh.ts'

export type { InstallGateFinding, InstallGateLevel, InstallGateReport, InstallGateSeverity, InstallGateText } from '../host/dsh.ts'

/** A translate function bound to one locale namespace. */
export type Translate<K extends string = string> = (key: K, params?: Readonly<Record<string, string>>) => string

/** One RPC answer on the connection. */
export type RpcResult<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string } }

/** The subject of a Plugins detail page. */
export type PluginsSubject =
  | { kind: 'bundle'; pkg: { name: string } }
  | { kind: 'row'; pkg: { name: string }; row: unknown }
  | { kind: 'item'; id: string }

/** Owner props of `plugins.install.gate`. */
export interface InstallGateProps {
  readonly report: InstallGateReport
  readonly outcome: 'review' | 'blocked' | 'installed'
  readonly acknowledge?: () => void
}

/** Owner props of `plugins.detail.badge` and `plugins.detail.section`. */
export interface DetailProps { readonly subject: PluginsSubject }

/** Owner props of `plugins.bundle.config`. */
export interface ConfigViewProps { readonly view: 'summary' | 'page' }

/** The browser Cordis context members the client half uses. */
export interface ClientContext {
  readonly slots: {
    inject(name: string, register: () => () => void): void
    register<P>(options: { name: string; id?: string; key?: string; locale?: string }, component: ComponentType<P>): () => void
  }
  readonly locale: {
    register(namespace: string, dictionaries: Readonly<Record<string, Readonly<Record<string, string>>>>): () => void
    /** The person's locale's entry of a localized text, falling back to English. */
    resolveText(text: { readonly en: string; readonly [locale: string]: string }): string
  }
  readonly connection: { readonly rpc: { call(channel: string, method: string, payload: unknown, signal?: AbortSignal): Promise<RpcResult<unknown>> } }
  effect(execute: () => () => void, label?: string): void
}
