import { createBrowserRouter, redirect } from 'react-router';
import { RootLayout } from './components/RootLayout';
import { Login } from './pages/Login';
import ThreatScanConsole from './pages/ThreatScanConsole';
import { ScanHistory } from './pages/ScanHistory';
import { ThreatAnalytics } from './pages/ThreatAnalytics';
import { SystemStatus } from './pages/SystemStatus';
import { ExplainabilityDetails } from './pages/ExplainabilityDetails';
import { GoogleSetup } from './pages/GoogleSetup';
import { AccountDetails } from './pages/AccountDetails';

function checkAuth(): boolean {
  if (typeof window === 'undefined') return false;
  const sessionData = localStorage.getItem('phishguard_session');
  if (!sessionData) return false;
  try {
    const session = JSON.parse(sessionData);
    return session.expiresAt > Date.now();
  } catch {
    return false;
  }
}

function protectedLoader() {
  if (!checkAuth()) {
    return redirect('/login');
  }
  return null;
}

function loginLoader() {
  if (checkAuth()) {
    return redirect('/account-details');
  }
  return null;
}

export const router = createBrowserRouter([
  {
    path: '/login',
    Component: Login,
    loader: loginLoader,
  },
  {
    path: '/auth/google-setup',
    Component: GoogleSetup,
    loader: loginLoader,
  },
  {
    path: '/',
    Component: RootLayout,
    loader: protectedLoader,
    children: [
      { index: true, loader: () => redirect('/account-details') },
      { path: 'account-details', Component: AccountDetails },
      { path: 'scan', Component: ThreatScanConsole },
      { path: 'history', Component: ScanHistory },
      { path: 'history/explainability/:scanId', Component: ExplainabilityDetails },
      { path: 'analytics', Component: ThreatAnalytics },
      { path: 'system', Component: SystemStatus },
      { path: '*', loader: () => redirect('/account-details') },
    ],
  },
  {
    path: '*',
    loader: () => redirect('/login'),
  },
]);
