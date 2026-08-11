import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import en, { type DictKey } from '@/lib/i18n/en'
import ko from '@/lib/i18n/ko'

export type Language = 'en' | 'ko'

const dictionaries: Record<Language, Record<DictKey, string>> = { en, ko }

function detectDefaultLanguage(): Language {
  if (typeof navigator === 'undefined') return 'en'
  return navigator.language.toLowerCase().startsWith('ko') ? 'ko' : 'en'
}

function readInitialLanguage(): Language {
  const stored = typeof localStorage !== 'undefined' ? localStorage.getItem('language') : null
  return stored === 'en' || stored === 'ko' ? stored : detectDefaultLanguage()
}

interface LanguageState {
  language: Language
  setLanguage: (lang: Language) => void
  /** Looks up key in the current language. {name} placeholders in the
   * value are replaced from params. Falls back to English, then to the
   * raw key, so a lookup bug shows up as a visibly wrong string rather
   * than a blank one — this should never actually trigger, since ko.ts
   * is typed to have every key en.ts has. */
  t: (key: DictKey, params?: Record<string, string | number>) => string
}

const LanguageContext = createContext<LanguageState | null>(null)

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>(readInitialLanguage)

  useEffect(() => {
    localStorage.setItem('language', language)
    document.documentElement.lang = language
  }, [language])

  function t(key: DictKey, params?: Record<string, string | number>): string {
    let str = dictionaries[language][key] ?? en[key] ?? key
    if (params) {
      for (const [name, value] of Object.entries(params)) {
        str = str.replaceAll(`{${name}}`, String(value))
      }
    }
    return str
  }

  return <LanguageContext.Provider value={{ language, setLanguage, t }}>{children}</LanguageContext.Provider>
}

export function useLanguage() {
  const ctx = useContext(LanguageContext)
  if (!ctx) throw new Error('useLanguage must be used within LanguageProvider')
  return ctx
}

/** Convenience for components that only need the translate function, not
 * the current language or the setter. */
export function useT() {
  return useLanguage().t
}
