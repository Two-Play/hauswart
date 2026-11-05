import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import './i18n';

import { createTheme, MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';

const theme = createTheme({ primaryColor: 'teal', defaultRadius: 'md' });

// The server allows only style tags carrying this per-request nonce, which
// keeps 'unsafe-inline' out of the Content Security Policy.
const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content ?? '';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto" getStyleNonce={() => nonce}>
      <Notifications />
      <App />
    </MantineProvider>
  </StrictMode>,
);
