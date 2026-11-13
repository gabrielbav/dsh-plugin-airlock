/**
 * Airlock's settings page on its Plugins bundle page: scanner status with install buttons and switches, custom SARIF
 * scanners, the ruling policy, and the LLM judge. Settings save beside the profile and apply from the next scan.
 */
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Button, Switch, Tag } from '@deepseek-ai/dsh-client-ui-primitives'
import type { AirlockConfig, AirlockScannerInfo, AirlockSettings, BuiltinScannerId, CustomScanner } from '../host/types.ts'
import type { InstallGateReport, InstallGateSeverity, InstallGateText } from './dsh.ts'
import { refreshStatus } from './InstallDialog.tsx'
import type { AirlockApi, AirlockStatus } from './rpc.ts'
import { levelTone, SecurityScore, type AirlockT } from './SecurityScore.tsx'

const SEVERITIES: readonly InstallGateSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

type Model = Awaited<ReturnType<AirlockApi['models']>>[number]

type Loaded = {
  settings: AirlockSettings; effective: AirlockConfig; scanners: AirlockScannerInfo[]; models: Model[]
  status: AirlockStatus; reports: InstallGateReport[]
}

/** A blank custom scanner row. */
function blankScanner(index: number): CustomScanner {
  return { id: `custom-${index}`, name: `Custom scanner ${index}`, enabled: true, command: '', args: ['{target}'], target: 'package', okExitCodes: [0, 1] }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Render the settings page, or its one-line summary.
 * @param props.view - `summary` for the Plugins list, `page` for the bundle page.
 * @param props.api - Host endpoints.
 * @param props.t - translate seat.
 * @returns the page.
 */
export function Settings({ view, api, t, resolve }: {
  readonly view: 'summary' | 'page'
  readonly api: AirlockApi
  readonly t: AirlockT
  readonly resolve: (text: InstallGateText) => string
}): ReactNode {
  const [loaded, setLoaded] = useState<Loaded | null>(null)
  const [draft, setDraft] = useState<AirlockSettings>({})
  const [status, setStatus] = useState<{ kind: 'error' | 'saved'; text: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [installing, setInstalling] = useState<Readonly<Record<string, string>>>({})
  const [openReport, setOpenReport] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      const [{ settings, effective }, scanners, models, status, reports] = await Promise.all([
        api.settings(), api.scanners(), api.models(), api.status(), api.reports().catch(() => []),
      ])
      setLoaded({ settings, effective, scanners, models, status, reports })
      setDraft(settings)
    } catch (error) {
      setStatus({ kind: 'error', text: t('loadFailed', { reason: message(error) }) })
    }
  }, [api, t])
  useEffect(() => { void load() }, [load])

  if (loaded === null) return status === null ? null : <p className="airlock-meta" role="alert">{status.text}</p>
  const effective = loaded.effective
  const enabledCount = loaded.scanners.filter(scanner => scanner.enabled).length
  const missing = loaded.scanners.filter(scanner => scanner.enabled && scanner.command !== null && scanner.executable === null).length
  const summary = `${t(loaded.status.mode === 'full' ? 'modeFull' : 'modeStandard')} · ${t('settingsSummary', { enabled: String(enabledCount), total: String(loaded.scanners.length), missing: String(missing) })}`
  if (view === 'summary') return summary

  const policy = { ...effective.policy, ...draft.policy }
  const llm = { ...effective.llm, ...draft.llm }
  const custom = draft.custom ?? effective.custom
  const scannerEnabled = (id: string): boolean => draft.scanners?.[id as BuiltinScannerId]?.enabled ?? effective.scanners[id as BuiltinScannerId]?.enabled ?? true
  const setScanner = (id: BuiltinScannerId, enabled: boolean): void => {
    setDraft({ ...draft, scanners: { ...draft.scanners, [id]: { ...draft.scanners?.[id], enabled } } })
  }
  const setCustom = (next: readonly CustomScanner[]): void => { setDraft({ ...draft, custom: next }) }
  const editCustom = (index: number, patch: Partial<CustomScanner>): void => {
    setCustom(custom.map((scanner, at) => at === index ? { ...scanner, ...patch } : scanner))
  }
  const setPolicy = (patch: NonNullable<AirlockSettings['policy']>): void => { setDraft({ ...draft, policy: { ...draft.policy, ...patch } }) }
  const setLlm = (patch: NonNullable<AirlockSettings['llm']>): void => { setDraft({ ...draft, llm: { ...draft.llm, ...patch } }) }
  const enforcement = { ...effective.enforcement, ...draft.enforcement }
  const setEnforcement = (patch: NonNullable<AirlockSettings['enforcement']>): void => { setDraft({ ...draft, enforcement: { ...draft.enforcement, ...patch } }) }
  const tier = loaded.status

  const save = async (): Promise<void> => {
    setSaving(true)
    setStatus(null)
    try {
      const { settings, effective: next } = await api.saveSettings(draft)
      await refreshStatus(api)
      setLoaded({ ...loaded, settings, effective: next, scanners: await api.scanners(), status: await api.status() })
      setDraft(settings)
      setStatus({ kind: 'saved', text: t('saved') })
    } catch (error) {
      setStatus({ kind: 'error', text: t('saveFailed', { reason: message(error) }) })
    } finally {
      setSaving(false)
    }
  }

  const install = async (id: string): Promise<void> => {
    setInstalling({ ...installing, [id]: t('scannerInstalling') })
    let note: string
    try {
      const result = await api.installScanner(id)
      note = result.exitCode === 0 ? t('scannerInstallDone') : t('scannerInstallFailed', { code: String(result.exitCode ?? 'signal') })
    } catch (error) {
      note = message(error)
    }
    setInstalling(current => ({ ...current, [id]: note }))
    setLoaded(current => current)
    try { setLoaded({ ...loaded, scanners: await api.scanners() }) }
    catch (error) { setStatus({ kind: 'error', text: t('loadFailed', { reason: message(error) }) }) }
  }

  const switchRow = (checked: boolean, onChange: (next: boolean) => void, label: string): ReactNode => (
    <div className="airlock-switch-row">
      <span>{label}</span>
      <Switch checked={checked} onChange={onChange} label={label} />
    </div>
  )
  const severitySelect = (value: InstallGateSeverity, onChange: (next: InstallGateSeverity) => void, label: string): ReactNode => (
    <label className="airlock-field">
      <span>{label}</span>
      <select value={value} onChange={event => { onChange(event.currentTarget.value as InstallGateSeverity) }}>
        {SEVERITIES.map(level => <option key={level} value={level}>{t(`severity.${level}`)}</option>)}
      </select>
    </label>
  )
  const numberField = (value: number, onChange: (next: number) => void, label: string): ReactNode => (
    <label className="airlock-field">
      <span>{label}</span>
      <input type="number" min={0} max={100} value={value} onChange={event => { onChange(Number(event.currentTarget.value)) }} />
    </label>
  )
  const textField = (value: string, onChange: (next: string) => void, label: string): ReactNode => (
    <label className="airlock-field">
      <span>{label}</span>
      <input type="text" value={value} onChange={event => { onChange(event.currentTarget.value) }} />
    </label>
  )

  return (
    <div className="airlock-settings" data-airlock-settings="">
      <p className="airlock-meta">{summary}</p>

      <section className="airlock-block">
        <h4 className="airlock-block-title">{t('scannersHeading')}</h4>
        <ul className="airlock-scanner-rows">
          {loaded.scanners.map(scanner => (
            <li key={scanner.id} className="airlock-scanner-row" data-scanner={scanner.id}>
              <div className="airlock-scanner-main">
                <strong>{scanner.name}</strong>
                {scanner.origin === 'custom' ? <Tag tone="info">{t('scannerOriginCustom')}</Tag> : null}
                {scanner.origin === 'plugin' ? <Tag tone="info">{t('scannerOriginPlugin')}</Tag> : null}
                <span className="airlock-meta">
                  {!scanner.enabled ? t('scannerOff')
                    : scanner.executable !== null ? t('scannerInstalled', { path: scanner.executable })
                      : scanner.command === null ? '' : t('scannerMissing')}
                </span>
                {installing[scanner.id] === undefined ? null : <span className="airlock-meta">{installing[scanner.id]}</span>}
              </div>
              <div className="airlock-scanner-actions">
                {scanner.installable && scanner.executable === null
                  ? <Button size="sm" variant="outline" disabled={installing[scanner.id] === t('scannerInstalling')} onClick={() => { void install(scanner.id) }}>{t('scannerInstall')}</Button>
                  : null}
                {scanner.origin === 'builtin'
                  ? <Switch checked={scannerEnabled(scanner.id)} onChange={next => { setScanner(scanner.id as BuiltinScannerId, next) }} label={t('scannerEnable', { name: scanner.name })} />
                  : null}
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="airlock-block">
        <h4 className="airlock-block-title">{t('customHeading')}</h4>
        <p className="airlock-meta">{t('customHint')}</p>
        {custom.map((scanner, index) => (
          <div key={index} className="airlock-custom" data-custom-scanner={scanner.id}>
            <div className="airlock-grid">
              {textField(scanner.id, value => { editCustom(index, { id: value }) }, t('customId'))}
              {textField(scanner.name, value => { editCustom(index, { name: value }) }, t('customName'))}
              {textField(scanner.command, value => { editCustom(index, { command: value }) }, t('customCommand'))}
              <label className="airlock-field">
                <span>{t('customTarget')}</span>
                <select value={scanner.target} onChange={event => { editCustom(index, { target: event.currentTarget.value === 'lockfile' ? 'lockfile' : 'package' }) }}>
                  <option value="package">{t('targetPackage')}</option>
                  <option value="lockfile">{t('targetLockfile')}</option>
                </select>
              </label>
            </div>
            <label className="airlock-field">
              <span>{t('customArgs')}</span>
              <textarea rows={3} value={scanner.args.join('\n')} onChange={event => { editCustom(index, { args: event.currentTarget.value.split('\n').filter(line => line !== '') }) }} />
            </label>
            <div className="airlock-scanner-actions">
              <Switch checked={scanner.enabled} onChange={next => { editCustom(index, { enabled: next }) }} label={t('scannerEnable', { name: scanner.name })} />
              <Button size="sm" variant="outline" onClick={() => { setCustom(custom.filter((_, at) => at !== index)) }}>{t('customRemove')}</Button>
            </div>
          </div>
        ))}
        <Button size="sm" variant="outline" onClick={() => { setCustom([...custom, blankScanner(custom.length + 1)]) }}>{t('customAdd')}</Button>
      </section>

      <section className="airlock-block">
        <h4 className="airlock-block-title">{t('policyHeading')}</h4>
        <div className="airlock-grid">
          {numberField(policy.passScore, value => { setPolicy({ passScore: value }) }, t('passScore'))}
          {numberField(policy.blockScore, value => { setPolicy({ blockScore: value }) }, t('blockScore'))}
          {severitySelect(policy.blockSeverity, value => { setPolicy({ blockSeverity: value }) }, t('blockSeverity'))}
          {severitySelect(policy.dependencyBlockSeverity, value => { setPolicy({ dependencyBlockSeverity: value }) }, t('dependencyBlockSeverity'))}
          {severitySelect(policy.reviewSeverity, value => { setPolicy({ reviewSeverity: value }) }, t('reviewSeverity'))}
          {severitySelect(policy.availabilitySeverity, value => { setPolicy({ availabilitySeverity: value }) }, t('availabilitySeverity'))}
        </div>
        {switchRow(policy.requireLlm, next => { setPolicy({ requireLlm: next }) }, t('requireLlm'))}
      </section>

      <section className="airlock-block">
        <h4 className="airlock-block-title">{t('llmHeading')}</h4>
        {switchRow(llm.enabled, next => { setLlm({ enabled: next }) }, t('llmEnabled'))}
        {loaded.models.length === 0
          ? <p className="airlock-meta" role="status">{t('llmModelsEmpty')}</p>
          : (
            <label className="airlock-field">
              <span>{t('llmModel')}</span>
              <select data-airlock-model="" value={llm.model === '' ? '' : `${llm.provider}\u0000${llm.model}`}
                onChange={(event) => {
                  const [provider = '', model = ''] = event.currentTarget.value.split('\u0000')
                  setLlm({ provider, model, ...model === '' ? {} : { enabled: true } })
                }}>
                <option value="">{t('llmModelNone')}</option>
                {[...new Set(loaded.models.map(model => model.provider))].map(provider => (
                  <optgroup key={provider} label={loaded.models.find(model => model.provider === provider)?.providerName ?? provider}>
                    {loaded.models.filter(model => model.provider === provider).map(model => (
                      <option key={model.id} value={`${model.provider}\u0000${model.id}`}>{model.name}</option>
                    ))}
                  </optgroup>
                ))}
              </select>
            </label>
          )}
        {llm.enabled && llm.model === '' ? <p className="airlock-meta" role="alert">{t('llmModelRequired')}</p> : null}
        <p className="airlock-meta">{t('llmHint')}</p>
      </section>

      <section className="airlock-block" data-airlock-mode={tier.mode}>
        <h4 className="airlock-block-title">{t('enforcementHeading')}</h4>
        <div className="airlock-switch-row">
          <span>{t(tier.mode === 'full' ? 'modeFull' : 'modeStandard')}</span>
          <Tag tone={tier.mode === 'full' ? 'success' : 'info'}>{t(tier.hookAvailable ? 'hookPresent' : 'hookMissing')}</Tag>
        </div>
        <p className="airlock-meta">{t(tier.mode === 'full' ? 'enforcementFull' : tier.hookAvailable ? 'enforcementHookOff' : 'enforcementStandard')}</p>
        {tier.mode === 'standard'
          ? (
            <ul className="airlock-reasons">
              <li>{t('coverageChat')}</li>
              <li>{t('coverageMenu')}</li>
              <li>{t('coverageAudit')}</li>
            </ul>
          )
          : null}
        {tier.hookAvailable
          ? switchRow(enforcement.useInstallGate, next => { setEnforcement({ useInstallGate: next }) }, t('useInstallGate'))
          : <p className="airlock-meta">{t('hookUpgrade')} <a href={tier.hookUrl} target="_blank" rel="noreferrer">{t('hookLink')}</a></p>}
        <label className="airlock-field">
          <span>{t('unscannedLabel')}</span>
          <select value={enforcement.unscanned} onChange={(event) => { setEnforcement({ unscanned: event.currentTarget.value === 'flag' ? 'flag' : 'disable' }) }}>
            <option value="disable">{t('unscannedDisable')}</option>
            <option value="flag">{t('unscannedFlag')}</option>
          </select>
        </label>
        {tier.hookAvailable ? <p className="airlock-meta">{t('enforcementHint')}</p> : null}
      </section>

      <section className="airlock-block">
        <h4 className="airlock-block-title">{t('recentHeading')}</h4>
        {loaded.reports.length === 0 ? <p className="airlock-meta">{t('recentNone')}</p> : (
          <ul className="airlock-scanner-rows">
            {loaded.reports.slice(0, 20).map((report) => {
              const key = `${report.packageName ?? report.spec}@${report.version ?? ''}`
              return (
                <li key={key} className="airlock-recent" data-recent={report.packageName}>
                  <button type="button" className="airlock-recent-head" aria-expanded={openReport === key} onClick={() => { setOpenReport(openReport === key ? null : key) }}>
                    <strong>{report.packageName ?? report.spec}{report.version === undefined ? '' : `@${report.version}`}</strong>
                    <Tag tone={levelTone(report.level)}>{t('badge', { score: String(report.score ?? '—') })}</Tag>
                    <span className="airlock-meta">{t('scannedAt', { time: new Date(report.checkedAt).toLocaleString() })}</span>
                  </button>
                  {openReport === key
                    ? <SecurityScore report={report} outcome="installed" summaryText={t('recentSummary')} t={t} resolve={resolve} />
                    : null}
                </li>
              )
            })}
          </ul>
        )}
      </section>

      <div className="airlock-save">
        <Button variant="primary" disabled={saving} onClick={() => { void save() }}>{saving ? t('saving') : t('save')}</Button>
        <Button variant="outline" disabled={saving} onClick={() => { setDraft(loaded.settings); setStatus(null) }}>{t('reset')}</Button>
        {status === null ? null : <p className="airlock-meta" role={status.kind === 'error' ? 'alert' : 'status'}>{status.text}</p>}
      </div>
    </div>
  )
}
