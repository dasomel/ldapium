import type { HTMLAttributes } from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[11px] leading-4',
  {
    variants: {
      variant: {
        neutral: 'border-border-strong bg-muted text-muted-foreground',
        accent: 'border-accent/30 bg-accent-muted text-accent',
        success: 'border-success/30 bg-success/10 text-success',
        danger: 'border-danger/30 bg-danger/10 text-danger',
      },
    },
    defaultVariants: { variant: 'neutral' },
  },
)

export function Badge({
  className,
  variant,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
