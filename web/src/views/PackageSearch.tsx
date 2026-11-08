import { Badge, Group, Stack, TagsInput, Text, type TagsInputProps } from '@mantine/core';
import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '../api';

export type SearchKind = 'package' | 'flatpak';

/** Whose packages a search looks at: one device, the devices of a group, or all. */
export interface SearchScope {
  device?: string;
  group?: number;
}

interface Entry {
  name: string;
  title?: string;
  summary?: string;
  installed?: boolean;
}

// A form deep inside a group sets the scope once, instead of handing it down.
export const SearchScopeContext = createContext<SearchScope>({});

const MIN_QUERY = 2;
const DEBOUNCE_MS = 250;

function searchPath(kind: SearchKind, q: string, scope: SearchScope) {
  const params = new URLSearchParams({ kind, q });
  if (scope.device) params.set('device', scope.device);
  if (scope.group !== undefined) params.set('group', String(scope.group));
  return `/api/catalog/search?${params}`;
}

/** useSearch asks the server while someone types, and drops answers that came too late. */
function useSearch(kind: SearchKind, query: string, scope: SearchScope) {
  const [entries, setEntries] = useState<Entry[]>([]);
  const latest = useRef(0);
  const q = query.trim();
  const tooShort = q.length < MIN_QUERY;
  const { device, group } = scope;

  useEffect(() => {
    if (tooShort) return;
    const ticket = ++latest.current;
    const timer = setTimeout(async () => {
      try {
        const found = await api<Entry[]>('GET', searchPath(kind, q, { device, group }));
        if (ticket === latest.current) setEntries(found);
      } catch {
        // A search is a help, not a step: without it, the name is typed by hand.
        if (ticket === latest.current) setEntries([]);
      }
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [kind, q, tooShort, device, group]);

  return tooShort ? [] : entries;
}

type Props = Omit<TagsInputProps, 'data' | 'searchValue' | 'onSearchChange' | 'renderOption' | 'filter'> & {
  kind: SearchKind;
  value: string[];
  onChange: (value: string[]) => void;
  /** Overrides the scope of the surrounding form. */
  scope?: SearchScope;
};

/**
 * PackageSearch is a TagsInput that suggests package names or Flatpak IDs.
 * Anything can still be typed, for a package that no catalog knows yet.
 */
export function PackageSearch({ kind, value, onChange, scope, ...rest }: Props) {
  const { t } = useTranslation();
  const inherited = useContext(SearchScopeContext);
  const [query, setQuery] = useState('');
  const entries = useSearch(kind, query, scope ?? inherited);
  const byName = new Map(entries.map((entry) => [entry.name, entry]));

  return (
    <TagsInput
      {...rest}
      value={value}
      onChange={onChange}
      searchValue={query}
      onSearchChange={setQuery}
      data={entries.filter((entry) => !value.includes(entry.name)).map((entry) => entry.name)}
      // The server has searched already, also in titles that are not shown here.
      filter={({ options }) => options}
      limit={20}
      // Package names have no spaces, so a space starts the next one.
      splitChars={[',', ' ']}
      acceptValueOnBlur
      clearable
      placeholder={rest.placeholder ?? t('search.placeholder')}
      renderOption={({ option }) => {
        const entry = byName.get(option.value);
        return (
          <Group gap="xs" wrap="nowrap" justify="space-between" w="100%">
            <Stack gap={0}>
              <Text size="sm">{entry?.title ?? option.value}</Text>
              {entry?.title && (
                <Text size="xs" c="dimmed" ff="monospace">
                  {option.value}
                </Text>
              )}
              {entry?.summary && (
                <Text size="xs" c="dimmed" lineClamp={1}>
                  {entry.summary}
                </Text>
              )}
            </Stack>
            {entry?.installed && (
              <Badge size="xs" variant="light" color="teal">
                {t('search.installed')}
              </Badge>
            )}
          </Group>
        );
      }}
    />
  );
}
