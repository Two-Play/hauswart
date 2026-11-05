import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const STORAGE_KEY = 'hauswart-language';

type Messages = Record<string, unknown>;

// Every feature has its own file per language, merged here by section.
const files = import.meta.glob<Messages>('./locales/*/*.json', { eager: true, import: 'default' });

function merge(target: Messages, source: Messages) {
  for (const [key, value] of Object.entries(source)) {
    if (typeof value === 'object' && value !== null) {
      target[key] = target[key] ?? {};
      merge(target[key] as Messages, value as Messages);
    } else {
      target[key] = value;
    }
  }
}

function load(language: string): Messages {
  const messages: Messages = {};
  for (const [path, content] of Object.entries(files)) {
    if (path.includes(`/${language}/`)) merge(messages, content);
  }
  return messages;
}

export const LANGUAGES = ['en', 'de'] as const;

// Storage can be blocked, for example in a private window.
function storedLanguage(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function initialLanguage(): string {
  const stored = storedLanguage();
  if (stored && (LANGUAGES as readonly string[]).includes(stored)) return stored;
  return navigator.language.toLowerCase().startsWith('de') ? 'de' : 'en';
}

export function setLanguage(language: string) {
  i18n.changeLanguage(language);
  document.documentElement.lang = language;
  try {
    localStorage.setItem(STORAGE_KEY, language);
  } catch {
    // The choice then only lasts for this visit.
  }
}

i18n.use(initReactI18next).init({
  resources: { en: { translation: load('en') }, de: { translation: load('de') } },
  lng: initialLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false }, // React already escapes
});
document.documentElement.lang = i18n.language;

export default i18n;
