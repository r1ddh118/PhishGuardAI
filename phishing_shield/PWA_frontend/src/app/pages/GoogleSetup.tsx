import { FormEvent, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { KeyRound, Mail, User } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { completeGoogleSignup } from '../lib/auth';
import { toast } from 'sonner';

export function GoogleSetup() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const prefilledEmail = useMemo(() => searchParams.get('email')?.trim().toLowerCase() ?? '', [searchParams]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();

    if (!prefilledEmail) {
      toast.error('Missing Google email. Please retry sign-in.');
      navigate('/login');
      return;
    }

    if (!username || !password) {
      toast.error('Please provide username and password');
      return;
    }

    setIsLoading(true);
    try {
      await completeGoogleSignup({ username, email: prefilledEmail, password });
      toast.success('Google account linked and secured.');
      navigate('/account-details');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Setup failed';
      toast.error(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#02040a] p-4 text-zinc-100">
      <div className="w-full max-w-md border border-zinc-700 rounded-xl p-8 bg-transparent">
        <h1 className="text-2xl font-semibold mb-1">Complete Account Setup</h1>
        <p className="text-sm text-zinc-400 mb-6">Create your username and local password to finish Google onboarding.</p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm mb-2">Google Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
              <Input value={prefilledEmail} className="pl-10 bg-transparent border-zinc-600 h-11" disabled />
            </div>
          </div>

          <div>
            <label className="block text-sm mb-2">Username</label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Choose username"
                className="pl-10 bg-transparent border-zinc-600 h-11"
                disabled={isLoading}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm mb-2">Password</label>
            <div className="relative">
              <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Create a password"
                className="pl-10 bg-transparent border-zinc-600 h-11"
                disabled={isLoading}
              />
            </div>
          </div>

          <Button type="submit" className="w-full h-11 bg-zinc-100 text-zinc-900 hover:bg-zinc-200" disabled={isLoading}>
            {isLoading ? 'Saving...' : 'Finish Setup'}
          </Button>
        </form>
      </div>
    </div>
  );
}
