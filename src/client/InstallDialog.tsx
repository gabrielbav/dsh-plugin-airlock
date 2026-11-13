/**
 * Airlock's own scan-first install for a DSH without the install-gate hook: a row in the Plugins page's Add plugin
 * menu opens a dialog that scans a spec in quarantine, shows the score, and installs only what passed or what the
 * person reviewed. The Host installs it switched off, checks the installed files against the scan, then switches it
 * on. The dialog lives in `shell.overlay`, so it outlives the menu that opened it.
 */
import { useState, useSyncExternalStore, type ReactNode } from 'react'
import { Button, IconShieldOutlineRegular, MenuItemButton, Modal } from '@deepseek-ai/dsh-client-ui-primitives'
import type { InstallGateReport, InstallGateText } from './dsh.ts'
import type { AirlockApi, AirlockStatus } from './rpc.ts'
import { SecurityScore, type AirlockT } from './SecurityScore.tsx'

/** Whether the dialog is open; shared by the menu row and the overlay. */
let open = false
const listeners = new Set<() => void>()
const setOpen = (next: boolean): void => { open = next; for (const listener of listeners) listener() }
const subscribe = (listener: () => void): (() => void) => { listeners.add(listener); return () => { listeners.delete(listener) } }

/** The tier Airlock runs on, read once per page load and refreshed when settings are saved. */
let status: AirlockStatus | null = null
let statusRequest: Promise<void> | undefined
const statusListeners = new Set<() => void>()
/**
 * Read the Host's tier again.
 * @param api - Host endpoints.
 */
export function refreshStatus(api: AirlockApi): Promise<void> {
  statusRequest = api.status().then((value) => { status = value }, () => { status = null })
    .finally(() => { for (const listener of statusListeners) listener() })
  return statusRequest
}
function useStatus(api: AirlockApi): AirlockStatus | null {
  return useSyncExternalStore((listener) => {
    statusListeners.add(listener)
    if (statusRequest === undefined) void refreshStatus(api)
    return () => { statusListeners.delete(listener) }
  }, () => status)
}

/**
 * The Add plugin menu row. Hidden while the install-gate hook vets the page's own install button.
 * @param props.onDismiss - close the menu.
 * @param props.api - Host endpoints.
 * @param props.t - translate seat.
 * @returns the row, or null in full enforcement.
 */
export function InstallMenuItem({ onDismiss, api, t }: { readonly onDismiss: () => void; readonly api: AirlockApi; readonly t: AirlockT }): ReactNode {
  const current = useStatus(api)
  if (current === null || current.gateActive) return null
  return (
    <MenuItemButton icon={<IconShieldOutlineRegular size={14} />} onSelect={() => { onDismiss(); setOpen(true) }}>
      <span className="airlock-menu-copy">
        <span>{t('installMenu')}</span>
        <span className="airlock-menu-description">{t('installMenuDescription')}</span>
      </span>
    </MenuItemButton>
  )
}

type Step =
  | { kind: 'form'; error?: string }
  | { kind: 'scanning' }
  | { kind: 'scanned'; scanId: string; report: InstallGateReport }
  | { kind: 'installing'; report: InstallGateReport }
  | { kind: 'done'; report: InstallGateReport; name: string }
  | { kind: 'failed'; report: InstallGateReport; message: string }

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * The dialog, mounted in `shell.overlay`.
 * @param props.api - Host endpoints.
 * @param props.t - translate seat.
 * @param props.resolve - localized-text resolver.
 * @returns the dialog while it is open.
 */
export function InstallDialog({ api, t, resolve }: { readonly api: AirlockApi; readonly t: AirlockT; readonly resolve: (text: InstallGateText) => string }): ReactNode {
  const isOpen = useSyncExternalStore(subscribe, () => open)
  if (!isOpen) return null
  return <DialogBody api={api} t={t} resolve={resolve} />
}

function DialogBody({ api, t, resolve }: { readonly api: AirlockApi; readonly t: AirlockT; readonly resolve: (text: InstallGateText) => string }): ReactNode {
  const [spec, setSpec] = useState('')
  const [registry, setRegistry] = useState('')
  const [step, setStep] = useState<Step>({ kind: 'form' })
  const busy = step.kind === 'scanning' || step.kind === 'installing'
  const close = (): void => { if (!busy) setOpen(false) }

  const scan = async (): Promise<void> => {
    if (spec.trim() === '') return
    setStep({ kind: 'scanning' })
    try {
      const { scanId, report } = await api.scan(spec.trim(), registry.trim() === '' ? undefined : registry.trim())
      setStep({ kind: 'scanned', scanId, report })
    } catch (error) {
      setStep({ kind: 'form', error: t('scanFailed', { reason: message(error) }) })
    }
  }

  const install = async (scanId: string, report: InstallGateReport): Promise<void> => {
    setStep({ kind: 'installing', report })
    try {
      const { result } = await api.install(scanId, report.level === 'review' ? report.digest : undefined)
      if (result.application === 'failed' || result.application === 'cancelled') {
        const builds = result.pendingBuilds === undefined || result.pendingBuilds.length === 0 ? '' : ` ${t('installBuilds', { names: result.pendingBuilds.join(', ') })}`
        setStep({ kind: 'failed', report, message: `${result.error?.message ?? t('installCancelled')}${builds}` })
      } else {
        setStep({ kind: 'done', report, name: result.bundle ?? report.packageName ?? spec })
      }
    } catch (error) {
      setStep({ kind: 'failed', report, message: message(error) })
    }
  }

  let body: ReactNode
  let footer: ReactNode
  if (step.kind === 'form' || step.kind === 'scanning') {
    body = (
      <div className="airlock-dialog-form">
        <p className="airlock-meta">{t('installDialogHint')}</p>
        <label className="airlock-field">
          <span>{t('installSpec')}</span>
          <input type="text" data-modal-autofocus="" value={spec} disabled={busy} placeholder="name@1.2.3 · github:owner/repo · /path/to/dir"
            onChange={event => { setSpec(event.currentTarget.value) }}
            onKeyDown={(event) => { if (event.key === 'Enter') void scan() }} />
        </label>
        <label className="airlock-field">
          <span>{t('installRegistry')}</span>
          <input type="text" value={registry} disabled={busy} placeholder="https://registry.npmjs.org/" onChange={event => { setRegistry(event.currentTarget.value) }} />
        </label>
        {step.kind === 'scanning' ? <p className="airlock-meta" role="status">{t('scanning')}</p> : null}
        {step.kind === 'form' && step.error !== undefined ? <p className="airlock-meta airlock-error" role="alert">{step.error}</p> : null}
      </div>
    )
    footer = (
      <>
        <Button variant="outline" disabled={busy} onClick={close}>{t('cancel')}</Button>
        <Button variant="primary" disabled={busy || spec.trim() === ''} onClick={() => { void scan() }}>{busy ? t('scanningShort') : t('scan')}</Button>
      </>
    )
  } else {
    const report = step.report
    const outcome = step.kind === 'scanned' ? (report.level === 'block' ? 'blocked' : report.level === 'review' ? 'review' : 'installed') : 'installed'
    body = (
      <div className="airlock-dialog-form">
        {step.kind === 'scanned' && report.level === 'pass' ? <p className="airlock-meta" role="status">{t('scanPassed')}</p> : null}
        {step.kind === 'installing' ? <p className="airlock-meta" role="status">{t('installing')}</p> : null}
        {step.kind === 'done' ? <p className="airlock-meta" role="status">{t('installDone', { name: step.name })}</p> : null}
        {step.kind === 'failed' ? <p className="airlock-meta airlock-error" role="alert">{t('installFailed', { reason: step.message })}</p> : null}
        <SecurityScore report={report} outcome={outcome} t={t} resolve={resolve}
          acknowledge={step.kind === 'scanned' && report.level === 'review' ? () => { void install(step.scanId, report) } : undefined} />
      </div>
    )
    footer = (
      <>
        <Button variant="outline" disabled={busy} onClick={close}>{step.kind === 'done' ? t('close') : t('cancel')}</Button>
        {step.kind === 'scanned' && report.level === 'pass'
          ? <Button variant="primary" onClick={() => { void install(step.scanId, report) }}>{t('install')}</Button>
          : null}
        {step.kind === 'failed' || (step.kind === 'scanned' && report.level === 'block')
          ? <Button variant="primary" onClick={() => { setStep({ kind: 'form' }) }}>{t('scanAnother')}</Button>
          : null}
      </>
    )
  }

  return (
    <Modal open title={t('installDialogTitle')} closeLabel={t('close')} onClose={close} footer={footer} className="airlock-modal" contentClassName="airlock-dialog">
      {body}
    </Modal>
  )
}
