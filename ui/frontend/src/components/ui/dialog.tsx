import { createContext, useContext, useRef, useState } from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { cn } from '@/lib/utils'

const ReturnFocus = createContext<React.RefObject<HTMLElement | null> | null>(null)

export function Dialog({ open, defaultOpen, onOpenChange, children, ...props }: React.ComponentProps<typeof DialogPrimitive.Root>) {
  const [internalOpen, setInternalOpen] = useState(defaultOpen ?? false)
  const active = open ?? internalOpen
  const previous = useRef<HTMLElement | null>(null)
  const wasOpen = useRef(false)
  // D25: native autoFocus may run before Radix's mount event. Capture the
  // invoking control before content mounts so controlled dialogs restore focus.
  if (active && !wasOpen.current) previous.current = document.activeElement as HTMLElement
  wasOpen.current = active
  return <ReturnFocus.Provider value={previous}><DialogPrimitive.Root {...props} open={active} onOpenChange={(value) => {
    if (value) previous.current = document.activeElement as HTMLElement
    setInternalOpen(value); onOpenChange?.(value)
  }}>{children}</DialogPrimitive.Root></ReturnFocus.Provider>
}
export const DialogTrigger = DialogPrimitive.Trigger

export function DialogContent({
  className,
  children,
  onOpenAutoFocus,
  onCloseAutoFocus,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content>) {
  const t = useT()
  const fallbackFocus = useRef<HTMLElement | null>(null)
  const previousFocus = useContext(ReturnFocus) ?? fallbackFocus
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px] data-[state=open]:animate-console-in" />
      <DialogPrimitive.Content
        onOpenAutoFocus={(event) => { if (!previousFocus.current) previousFocus.current = document.activeElement as HTMLElement; onOpenAutoFocus?.(event) }}
        onCloseAutoFocus={(event) => {
          onCloseAutoFocus?.(event)
          if (!event.defaultPrevented && previousFocus.current?.isConnected) { event.preventDefault(); previousFocus.current.focus() }
        }}
        className={cn(
          'fixed left-1/2 top-1/2 z-50 w-[calc(100%-1.5rem)] max-w-md max-h-[calc(100dvh-1.5rem)] overflow-y-auto -translate-x-1/2 -translate-y-1/2',
          'rounded-console border border-border-strong bg-surface-raised shadow-panel',
          'animate-console-in focus:outline-none',
          className,
        )}
        {...props}
      >
        {children}
        <DialogPrimitive.Close className="absolute right-3 top-3 rounded-console p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
          <X className="size-4" />
          <span className="sr-only">{t('common.close')}</span>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}

export function DialogHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('border-b border-border px-5 py-4', className)} {...props} />
}

export function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return <DialogPrimitive.Title className={cn('text-sm font-semibold tracking-tight', className)} {...props} />
}

export function DialogDescription({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      className={cn('mt-1 text-[13px] text-muted-foreground', className)}
      {...props}
    />
  )
}

export function DialogBody({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-5 py-4', className)} {...props} />
}

export function DialogFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex justify-end gap-2 border-t border-border px-5 py-3.5', className)}
      {...props}
    />
  )
}
