import type { ReactNode } from 'react'
import { Info } from 'lucide-react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { LDAP_GLOSSARY } from '@/lib/ldapGlossary'
import { cn } from '@/lib/utils'

interface GlossaryTermProps {
  /** The raw LDAP token to look up (attribute name or objectClass value),
   * matched case-insensitively against LDAP_GLOSSARY. */
  term: string
  children: ReactNode
  className?: string
}

/** Wraps a raw LDAP value or label with an inline hint explaining what it
 * means, for admins unfamiliar with LDAP. The value itself is never
 * altered, translated, or hidden — only annotated next to where it
 * already appears. Renders children unchanged, with no icon or tooltip,
 * when term has no glossary entry: an unexplained value is left alone
 * rather than given a guessed-at definition. */
export function GlossaryTerm({ term, children, className }: GlossaryTermProps) {
  const explanation = LDAP_GLOSSARY[term.toLowerCase()]
  if (!explanation) return <>{children}</>

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn(
            'inline-flex items-center gap-1 rounded-console underline decoration-dotted decoration-muted-foreground/60 underline-offset-2',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            className,
          )}
        >
          {children}
          <Info className="size-3 shrink-0 text-muted-foreground" />
        </button>
      </TooltipTrigger>
      <TooltipContent>{explanation}</TooltipContent>
    </Tooltip>
  )
}
