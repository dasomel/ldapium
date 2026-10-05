import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useT } from '@/context/LanguageContext'
import { Button } from '@/components/ui/button'

export function CopyButton({ text }: { text: string }) {
  const t = useT()
  const [done, setDone] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    } catch {
      // Clipboard can be blocked (insecure origin); the text stays selectable.
    }
  }
  return (
    <Button type="button" variant="outline" size="sm" onClick={copy} aria-label={t('apiDocs.copy')}>
      {done ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      <span aria-live="polite">{done ? t('apiDocs.copied') : t('apiDocs.copy')}</span>
    </Button>
  )
}

export function CodeBlock({ code, label }: { code: string; label: string }) {
  return (
    <div className="rounded-console border border-border bg-muted">
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
        <span className="text-[12px] text-muted-foreground">{label}</span>
        <CopyButton text={code} />
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[12px] leading-5" tabIndex={0}><code>{code}</code></pre>
    </div>
  )
}
