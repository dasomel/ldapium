import { useId, useState, type ComponentProps } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { useT } from '@/context/LanguageContext'

/**
 * A password field with a reveal toggle.
 *
 * Every password field in this app wants the same toggle, and it was being
 * hand-rolled per field — the same absolutely-positioned button, the same
 * pr-9 to keep the text clear of it, the same Eye/EyeOff swap. Three copies
 * had already accumulated across two files, which is how the affordance ends
 * up subtly different in one place after a style tweak.
 *
 * The toggle is a plain <button type="button"> rather than the shared Button
 * primitive on purpose: Button carries padding, height and variant styling
 * meant for standalone controls, all of which has to be unwound to sit inside
 * a field. Anything the caller does need to vary is forwarded to the Input.
 *
 * Visibility is uncontrolled by default. Pass visible/onVisibleChange when
 * several fields must reveal together — a "new password" and its confirmation
 * are compared by eye, so revealing one while the other stays masked defeats
 * the point.
 */
export function PasswordInput({
  className,
  visible: controlledVisible,
  onVisibleChange,
  ...props
}: ComponentProps<typeof Input> & {
  visible?: boolean
  onVisibleChange?: (visible: boolean) => void
}) {
  const [uncontrolledVisible, setUncontrolledVisible] = useState(false)
  const visible = controlledVisible ?? uncontrolledVisible
  const setVisible = (next: boolean) => {
    if (onVisibleChange) onVisibleChange(next)
    else setUncontrolledVisible(next)
  }
  const t = useT()
  const generatedId = useId()
  const id = props.id ?? generatedId

  return (
    <div className="relative">
      <Input
        {...props}
        id={id}
        type={visible ? 'text' : 'password'}
        className={`pr-9 ${className ?? ''}`}
      />
      <button
        type="button"
        onClick={() => setVisible(!visible)}
        title={visible ? t('common.hidePassword') : t('common.showPassword')}
        aria-label={visible ? t('common.hidePassword') : t('common.showPassword')}
        aria-controls={id}
        className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded-console p-1.5 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
      </button>
    </div>
  )
}
