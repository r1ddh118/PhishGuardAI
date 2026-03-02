import { getCurrentUser } from '../lib/auth';

function maskId(userId: string): string {
  if (userId.length <= 8) return userId;
  return `${userId.slice(0, 4)}...${userId.slice(-4)}`;
}

export function AccountDetails() {
  const user = getCurrentUser();

  if (!user) {
    return (
      <div className="p-8 text-foreground">
        <h1 className="text-3xl font-semibold mb-2">Account Details</h1>
        <p className="text-muted-foreground">No user found.</p>
      </div>
    );
  }

  return (
    <div className="p-8 text-foreground">
      <h1 className="text-3xl font-semibold mb-2">Account Details</h1>
      <p className="text-muted-foreground mb-6">Manage your signed-in profile and security details.</p>

      <div className="rounded-lg border border-border bg-card p-6 space-y-4 max-w-2xl">
        <div className="grid gap-1">
          <p className="text-sm text-muted-foreground">Username</p>
          <p className="text-base font-medium text-foreground">{user.username}</p>
        </div>

        <div className="grid gap-1">
          <p className="text-sm text-muted-foreground">Email Address</p>
          <p className="text-base text-foreground">{user.email}</p>
        </div>

        <div className="grid sm:grid-cols-2 gap-4">
          <div className="grid gap-1">
            <p className="text-sm text-muted-foreground">Auth Provider</p>
            <p className="text-base text-foreground capitalize">{user.authProvider}</p>
          </div>
          <div className="grid gap-1">
            <p className="text-sm text-muted-foreground">Role</p>
            <p className="text-base text-foreground capitalize">{user.role}</p>
          </div>
        </div>

        <div className="grid sm:grid-cols-2 gap-4">
          <div className="grid gap-1">
            <p className="text-sm text-muted-foreground">Facility ID</p>
            <p className="text-base text-foreground">{user.facilityId}</p>
          </div>
          <div className="grid gap-1">
            <p className="text-sm text-muted-foreground">Session User ID</p>
            <p className="text-base text-foreground">{maskId(user.id)}</p>
          </div>
        </div>

        <div className="pt-2 border-t border-border">
          <p className="text-xs text-muted-foreground">
            Last login: {user.lastLogin.toLocaleString()}
          </p>
        </div>
      </div>
    </div>
  );
}
