import { PanelLeft } from 'lucide-react'
import { useLanguage } from '@/context/LanguageContext'

export function StatusHud() {
  const { t } = useLanguage()

  return (
    <footer className="flex min-h-9 shrink-0 items-center justify-between gap-4 border-t border-border bg-surface px-3 font-mono text-[11px] text-muted-foreground">
      <div className="flex min-w-0 items-center gap-1.5 overflow-hidden whitespace-nowrap">
        <PanelLeft className="size-3 shrink-0" aria-hidden="true" />
        <span>{t('hud.openSidebar')}</span>
        <span aria-hidden="true">·</span>
        <span>{t('hud.commands')}</span>
        <span aria-hidden="true">·</span>
        <span>{t('hud.help')}</span>
        <span aria-hidden="true">·</span>
        <span>{t('hud.nextTab')}</span>
      </div>
      <span className="shrink-0 text-foreground">GPT-5.6 Terra</span>
    </footer>
  )
}
