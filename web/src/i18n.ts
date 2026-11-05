import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import de from './locales/de.json';
import en from './locales/en.json';

const STORAGE_KEY = 'hauswart-language';

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
  resources: { en: { translation: en }, de: { translation: de } },
  lng: initialLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false }, // React already escapes
});
document.documentElement.lang = i18n.language;

export default i18n;
