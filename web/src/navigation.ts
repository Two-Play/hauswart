import { createContext, useContext } from 'react';

/** Navigation lets one view open another, for example with a device chosen. */
export interface Navigation {
  open: (view: string, device?: string) => void;
  /** The device the actions page starts with, if a view chose one. */
  device?: string;
}

export const NavigationContext = createContext<Navigation>({ open: () => {} });

export const useNavigation = () => useContext(NavigationContext);
