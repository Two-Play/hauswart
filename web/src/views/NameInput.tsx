import { Autocomplete, type AutocompleteProps } from '@mantine/core';
import { createContext, useContext } from 'react';
import type { Device } from '../api';

/** Linux accounts and groups that devices reported, for suggestions. */
export interface KnownNames {
  users: string[];
  groups: string[];
}

// A form deep inside a group sets the names once, instead of handing them down.
export const KnownNamesContext = createContext<KnownNames>({ users: [], groups: [] });

/** knownNames collects the accounts and their groups from device reports. */
export function knownNames(devices: Device[]): KnownNames {
  const users = new Set<string>();
  const groups = new Set<string>();
  for (const device of devices) {
    for (const account of device.report?.accounts ?? []) {
      users.add(account.name);
      account.groups.forEach((group) => groups.add(group));
    }
  }
  const sorted = (set: Set<string>) => [...set].sort((a, b) => a.localeCompare(b));
  return { users: sorted(users), groups: sorted(groups) };
}

type Props = Omit<AutocompleteProps, 'data' | 'onChange'> & {
  /** Which names to suggest. */
  of: keyof KnownNames;
  value: string;
  onChange: (value: string) => void;
  /** Overrides the names of the surrounding form. */
  names?: KnownNames;
};

/**
 * NameInput suggests user or group names that devices reported. Any name can
 * still be typed, for an account that does not exist yet.
 */
export function NameInput({ of, names, value, onChange, ...rest }: Props) {
  const inherited = useContext(KnownNamesContext);
  return <Autocomplete {...rest} data={(names ?? inherited)[of]} value={value} onChange={onChange} limit={20} />;
}
