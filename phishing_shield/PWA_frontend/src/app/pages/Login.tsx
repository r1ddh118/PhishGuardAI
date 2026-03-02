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
    <div className="min-h-screen flex items-center justify-center bg-[#02040a] p-4 text-zinc-100">
      <div className="w-full max-w-xl">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-lg border border-zinc-700 mb-4">
            <Lock className="w-8 h-8 text-zinc-100" />
          </div>
          <h1 className="text-5xl font-semibold mb-2 tracking-tight">PhishGuard AI</h1>
          <p className="text-zinc-400 text-lg">Security Operations Console</p>
          <div className="mt-3 inline-flex items-center gap-2 text-xs text-zinc-400 uppercase tracking-wider">
            <Shield className="w-3 h-3" />
            <span>Offline Mode • Secure</span>
          </div>
        </div>

        <div className="bg-transparent border border-zinc-700 rounded-xl p-0 shadow-2xl overflow-hidden">
          <div className="grid grid-cols-2 border-b border-zinc-700">
            <button
              type="button"
              onClick={() => setAuthMode('login')}
              className={`py-4 text-lg font-medium transition-colors ${
                authMode === 'login' ? 'text-zinc-50 border-b-2 border-zinc-300' : 'text-zinc-500'
              }`}
            >
              Login
            </button>
            <button
              type="button"
              onClick={() => setAuthMode('signup')}
              className={`py-4 text-lg font-medium transition-colors ${
                authMode === 'signup' ? 'text-zinc-50 border-b-2 border-zinc-300' : 'text-zinc-500'
              }`}
            >
              Sign Up
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5 p-8">
            {authMode === 'login' ? (
              <div>
                <label className="block text-lg mb-2 text-zinc-200">Operator ID / Email</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                  <Input
                    type="text"
                    value={usernameOrEmail}
                    onChange={(e) => setUsernameOrEmail(e.target.value)}
                    placeholder="Enter operator ID or email"
                    className="pl-10 bg-transparent border-zinc-600 h-12 text-zinc-100 placeholder:text-zinc-500"
                    disabled={isLoading}
                    autoComplete="username"
                  />
                </div>
              </div>
            ) : (
              <>
                <div>
                  <label className="block text-lg mb-2 text-zinc-200">Username</label>
                  <div className="relative">
                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                    <Input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Choose username"
                      className="pl-10 bg-transparent border-zinc-600 h-12 text-zinc-100 placeholder:text-zinc-500"
                      disabled={isLoading}
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-lg mb-2 text-zinc-200">Email</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                    <Input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="name@company.com"
                      className="pl-10 bg-transparent border-zinc-600 h-12 text-zinc-100 placeholder:text-zinc-500"
                      disabled={isLoading}
                      autoComplete="email"
                    />
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-lg mb-2 text-zinc-200">{authMode === 'login' ? 'Access Code' : 'Password'}</label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={authMode === 'login' ? 'Enter access code' : 'Create password'}
                  className="pl-10 bg-transparent border-zinc-600 h-12 text-zinc-100 placeholder:text-zinc-500"
                  disabled={isLoading}
                  autoComplete={authMode === 'login' ? 'current-password' : 'new-password'}
                />
              </div>
            </div>

            <Button type="submit" className="w-full h-12 bg-zinc-100 text-zinc-900 hover:bg-zinc-200" disabled={isLoading}>
              {isLoading ? 'Processing...' : authMode === 'login' ? 'Access Console' : 'Create Account'}
            </Button>

            <div className="flex items-center gap-3 text-zinc-500 text-xs uppercase tracking-wider">
              <div className="h-px flex-1 bg-zinc-700" />
              <span>Or</span>
              <div className="h-px flex-1 bg-zinc-700" />
            </div>

            <Button
              type="button"
              variant="outline"
              className="w-full h-12 border-zinc-600 text-zinc-100 hover:bg-zinc-900"
              disabled={isLoading}
              onClick={handleGoogleAuth}
            >
              Continue with Google
            </Button>
          </form>
        </div>

        <div className="mt-6 text-center text-sm text-zinc-500">
          <p>Critical Infrastructure Security System</p>
          <p className="mt-1">Unauthorized access is prohibited</p>
        </div>
      </div>
    </div>
  );
}
