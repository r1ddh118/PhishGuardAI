import { Outlet, NavLink, useLocation } from 'react-router';
import { 
  Shield, 
  History, 
  BarChart3, 
  Settings, 
  Radio,
  Lock,
  LogOut,
  User
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { getCurrentUser, logout } from '../lib/auth';
import { useNavigate } from 'react-router';
import { Button } from './ui/button';
import { toast } from 'sonner';

export function RootLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [isOnline, setIsOnline] = useState(navigator.onLine);
  const user = getCurrentUser();

  useEffect(() => {
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully');
    navigate('/login');
  };

  const navItems = [
    { path: '/scan', label: 'Threat Scan', icon: Shield },
    { path: '/history', label: 'Scan History', icon: History },
    { path: '/analytics', label: 'Analytics', icon: BarChart3 },
    { path: '/system', label: 'System', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-background text-foreground">
      {/* Sidebar Navigation */}
      <aside className="w-64 bg-card border-r border-border flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary rounded flex items-center justify-center">
              <Lock className="w-6 h-6 text-primary-foreground" />
            </div>
            <div>
              <h1 className="font-semibold text-sm">PhishGuard AI</h1>
              <p className="text-xs text-muted-foreground">Security Console</p>
            </div>
          </div>
        </div>

        {/* User Info */}
        {user && (
          <div className="px-6 py-4 border-b border-border bg-muted/30">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center">
                <User className="w-4 h-4 text-primary" />
              </div>
              <div className="flex-1 min-w-0">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => navigate('/account-details')}
                  className="h-auto p-0 text-sm font-medium text-foreground hover:text-foreground truncate"
                >
                  {user.username}
                </Button>
                <p className="text-xs text-muted-foreground uppercase">{user.role}</p>
              </div>
            </div>
          </div>
        )}

        {/* Status Indicator */}
        <div className="px-6 py-4 border-b border-border">
          <div className="flex items-center gap-2 text-xs">
            <Radio className={`w-3 h-3 ${isOnline ? 'text-chart-5' : 'text-chart-3'}`} />
            <span className={isOnline ? 'text-chart-5' : 'text-chart-3'}>
              {isOnline ? 'ONLINE' : 'OFFLINE MODE'}
            </span>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <ul className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              
              return (
                <li key={item.path}>
                  <NavLink
                    to={item.path}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                      isActive
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    <span className="text-sm font-medium">{item.label}</span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-border space-y-3">
          <div className="text-xs text-muted-foreground">
            <p>Model: v2.3.1</p>
            <p>Last Sync: 2026-02-08</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleLogout}
            className="w-full justify-start"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
