import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Lock, User, KeyRound, Shield, Mail } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { authenticate, authenticateWithGoogle, signupWithPassword } from '../lib/auth';
import { toast } from 'sonner';

type AuthMode = 'login' | 'signup';

export function Login() {
  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (authMode === 'login') {
      if (!usernameOrEmail || !password) {
        toast.error('Please enter username/email and password');
        return;
      }

      setIsLoading(true);

      try {
        const user = await authenticate({ usernameOrEmail, password });

        if (user) {
          toast.success(`Welcome, ${user.username}`);
          navigate('/account-details');
        } else {
          toast.error('Invalid credentials');
        }
      } catch {
        toast.error('Authentication failed');
      } finally {
        setIsLoading(false);
      }

      return;
    }

    if (!username || !email || !password) {
      toast.error('Please fill username, email and password');
      return;
    }

    setIsLoading(true);
    try {
      const user = await signupWithPassword({ username, email, password });
      toast.success(`Account created for ${user.email}`);
      navigate('/account-details');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Signup failed';
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleAuth = async () => {
    const googleEmail = window.prompt('Enter your Google email for secure sign-in');
    if (!googleEmail) return;

    setIsLoading(true);
    try {
      const user = await authenticateWithGoogle(googleEmail);
      toast.success(`Signed in with Google as ${user.email}`);
      navigate('/account-details');
    } catch (error) {
      if (error instanceof Error && error.message === 'ACCOUNT_NOT_FOUND') {
        toast.info('No existing account found. Please complete setup.');
        navigate(`/auth/google-setup?email=${encodeURIComponent(googleEmail.trim().toLowerCase())}`);
      } else {
        toast.error('Google authentication failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-slate-900 via-slate-800 to-navy-900 text-slate-100">
      <header className="w-full py-6 px-12 border-b border-slate-700">
        <h1 className="text-3xl font-medium tracking-wide text-slate-100">PhishGuard AI</h1>
        <p className="text-slate-400 text-sm">Enterprise Security Dashboard</p>
      </header>

      <main className="flex-1 flex items-center justify-center px-12">
        <div className="w-full max-w-5xl grid grid-cols-2 gap-12 items-center">
          <div className="space-y-6">
            <h2 className="text-4xl font-semibold text-slate-100">Welcome to PhishGuard AI</h2>
            <p className="text-slate-400 text-lg leading-relaxed">
              Protect your organization with advanced phishing detection and security analytics. Log in to access your security operations console.
            </p>
          </div>

          <div className="bg-slate-800 border border-slate-700 rounded-md shadow-lg p-8">
            <div className="grid grid-cols-2 border-b border-slate-700 mb-6">
              <button
                type="button"
                onClick={() => setAuthMode('login')}
                className={`py-3 text-base font-medium transition-all duration-200 ${
                  authMode === 'login' ? 'text-slate-100 border-b-2 border-slate-400' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => setAuthMode('signup')}
                className={`py-3 text-base font-medium transition-all duration-200 ${
                  authMode === 'signup' ? 'text-slate-100 border-b-2 border-slate-400' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                Sign Up
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
              {authMode === 'login' ? (
                <div>
                  <label className="block text-base mb-2 text-slate-300">Operator ID / Email</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                    <Input
                      type="text"
                      value={usernameOrEmail}
                      onChange={(e) => setUsernameOrEmail(e.target.value)}
                      placeholder="Enter operator ID or email"
                      className="pl-10 bg-slate-900 border-slate-600 h-11 text-slate-100 placeholder:text-slate-500 focus:ring-2 focus:ring-slate-500"
                      disabled={isLoading}
                      autoComplete="username"
                    />
                  </div>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-base mb-2 text-slate-300">Username</label>
                    <div className="relative">
                      <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                      <Input
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="Choose username"
                        className="pl-10 bg-slate-900 border-slate-600 h-11 text-slate-100 placeholder:text-slate-500 focus:ring-2 focus:ring-slate-500"
                        disabled={isLoading}
                      />
                    </div>
                  </div>
                  <div>
                    <label className="block text-base mb-2 text-slate-300">Email</label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                      <Input
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="name@company.com"
                        className="pl-10 bg-slate-900 border-slate-600 h-11 text-slate-100 placeholder:text-slate-500 focus:ring-2 focus:ring-slate-500"
                        disabled={isLoading}
                        autoComplete="email"
                      />
                    </div>
                  </div>
                </>
              )}

              <div>
                <label className="block text-base mb-2 text-slate-300">{authMode === 'login' ? 'Access Code' : 'Password'}</label>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={authMode === 'login' ? 'Enter access code' : 'Create password'}
                    className="pl-10 bg-slate-900 border-slate-600 h-11 text-slate-100 placeholder:text-slate-500 focus:ring-2 focus:ring-slate-500"
                    disabled={isLoading}
                    autoComplete={authMode === 'login' ? 'current-password' : 'new-password'}
                  />
                </div>
              </div>

              <Button type="submit" className="w-full h-11 bg-slate-700 text-slate-100 hover:bg-slate-600 transition-all duration-200" disabled={isLoading}>
                {isLoading ? 'Processing...' : authMode === 'login' ? 'Access Console' : 'Create Account'}
              </Button>

              <div className="flex items-center gap-3 text-slate-500 text-xs uppercase tracking-wide">
                <div className="h-px flex-1 bg-slate-700" />
                <span>Or</span>
                <div className="h-px flex-1 bg-slate-700" />
              </div>

              <Button
                type="button"
                onClick={handleGoogleAuth}
                className="w-full h-11 bg-slate-600 text-slate-100 hover:bg-slate-500 transition-all duration-200"
                disabled={isLoading}
              >
                Sign in with Google
              </Button>
            </form>
          </div>
        </div>
      </main>
    </div>
  );
}
