/** Type-only copies of the DSH browser interfaces the client half uses. */
import type { ComponentType } from 'react'
import type { SecurityReport } from '../host/dsh.ts'

export type { SecurityFinding, SecurityLevel, SecurityReason, SecurityReport, SecuritySeverity } from '../host/dsh.ts'

/** A translate function bound to one locale namespace. */
export type Translate<K extends string = string> = (key: K, params?: Readonly<Record<string, string>>) => string

/** One RPC answer on the connection. */
export type RpcResult<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string } }

/** The subject of a Plugins detail page. */
export type PluginsSubject =
  | { kind: 'bundle'; pkg: { name: string } }
  | { kind: 'row'; pkg: { name: string }; row: unknown }
  | { kind: 'item'; id: string }

/** Owner props of `plugins.install.security`. */
export interface InstallSecurityProps {
  readonly report: SecurityReport
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
  readonly locale: { register(namespace: string, dictionaries: Readonly<Record<string, Readonly<Record<string, string>>>>): () => void }
  readonly connection: { readonly rpc: { call(channel: string, method: string, payload: unknown, signal?: AbortSignal): Promise<RpcResult<unknown>> } }
  effect(execute: () => () => void, label?: string): void
}
