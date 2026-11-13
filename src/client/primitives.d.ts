/**
 * Type declarations for the DSH UI primitives the browser half uses. The module itself is provided at runtime by
 * the DSH page's module table, so the package never bundles it.
 */
declare module '@deepseek-ai/dsh-client-ui-primitives' {
  import type { ButtonHTMLAttributes, ForwardRefExoticComponent, ReactNode, RefAttributes } from 'react'
  export type TagTone = 'outline' | 'solid' | 'neutral' | 'quiet' | 'success' | 'info' | 'warning' | 'danger'
  export function Tag(props: { tone?: TagTone; className?: string | undefined; children?: ReactNode }): ReactNode
  export const Button: ForwardRefExoticComponent<{
    variant?: 'primary' | 'ghost' | 'outline' | 'toolbar'
    size?: 'md' | 'sm'
    icon?: ReactNode
    className?: string | undefined
    children?: ReactNode
  } & ButtonHTMLAttributes<HTMLButtonElement> & RefAttributes<HTMLButtonElement>>
  export function Checkbox(props: { checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean; className?: string | undefined }): ReactNode
  export function IconShieldOutlineRegular(props: { size?: number }): ReactNode
  export function MenuItemButton(props: { icon?: ReactNode; disabled?: boolean; onSelect: () => void; children?: ReactNode }): ReactNode
  export function Modal(props: {
    open: boolean
    onClose: () => void
    title: string
    closeLabel: string
    tone?: 'warning'
    description?: string
    children?: ReactNode
    footer?: ReactNode
    className?: string
    contentClassName?: string
  }): ReactNode
  export function Switch(props: { checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean; className?: string | undefined }): ReactNode
}
