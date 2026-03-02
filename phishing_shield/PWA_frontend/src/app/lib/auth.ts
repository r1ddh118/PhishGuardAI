import { openDB } from 'idb';

// Offline-first authentication for critical infrastructure
// In production, this would integrate with facility's authentication system

interface User {
  id: string;
  username: string;
  email: string;
  role: 'operator' | 'analyst' | 'admin';
  authProvider: 'local' | 'google';
  facilityId: string;
  lastLogin: Date;
}

interface Credentials {
  usernameOrEmail: string;
  password: string;
}

interface SignupData {
  username: string;
  email: string;
  password: string;
}

interface StoredUser {
  id: string;
  username: string;
  email: string;
  role: User['role'];
  authProvider: User['authProvider'];
  passwordHash: string | null;
  facilityId: string;
  createdAt: string;
}

const SESSION_KEY = 'phishguard_session';
const SESSION_TIMEOUT = 8 * 60 * 60 * 1000; // 8 hours for shift work
const DB_NAME = 'phishguard_auth';
const USERS_STORE = 'users';

const dbPromise = openDB(DB_NAME, 1, {
  upgrade(db) {
    if (!db.objectStoreNames.contains(USERS_STORE)) {
      const store = db.createObjectStore(USERS_STORE, { keyPath: 'id' });
      store.createIndex('username', 'username', { unique: true });
      store.createIndex('email', 'email', { unique: true });
    }
  },
});

async function hashPassword(password: string): Promise<string> {
  const data = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function ensureUserStoreReady(): Promise<void> {
  await dbPromise;
}

function createSession(user: StoredUser): User {
  const session: User = {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    authProvider: user.authProvider,
    facilityId: user.facilityId,
    lastLogin: new Date(),
  };

  localStorage.setItem(SESSION_KEY, JSON.stringify({
    ...session,
    expiresAt: Date.now() + SESSION_TIMEOUT,
  }));

  return session;
}

export async function authenticate(credentials: Credentials): Promise<User | null> {
  await ensureUserStoreReady();
  await new Promise(resolve => setTimeout(resolve, 500));

  const db = await dbPromise;
  const byUsername = await db.getFromIndex(USERS_STORE, 'username', credentials.usernameOrEmail.trim());
  const byEmail = await db.getFromIndex(USERS_STORE, 'email', credentials.usernameOrEmail.trim().toLowerCase());
  const user = (byUsername ?? byEmail) as StoredUser | undefined;

  if (!user || !user.passwordHash) {
    return null;
  }

  const passwordHash = await hashPassword(credentials.password);
  if (passwordHash !== user.passwordHash) {
    return null;
  }

  return createSession(user);
}

export async function signupWithPassword(signupData: SignupData): Promise<User> {
  await ensureUserStoreReady();

  const db = await dbPromise;
  const username = signupData.username.trim();
  const email = signupData.email.trim().toLowerCase();

  if (!username || !email || !signupData.password) {
    throw new Error('Please fill username, email and password');
  }

  if (await db.getFromIndex(USERS_STORE, 'username', username)) {
    throw new Error('Username already exists');
  }

  if (await db.getFromIndex(USERS_STORE, 'email', email)) {
    throw new Error('Email already exists');
  }

  const user: StoredUser = {
    id: crypto.randomUUID(),
    username,
    email,
    role: 'operator',
    authProvider: 'local',
    passwordHash: await hashPassword(signupData.password),
    facilityId: 'FACILITY-001',
    createdAt: new Date().toISOString(),
  };

  await db.add(USERS_STORE, user);

  return createSession(user);
}

export async function authenticateWithGoogle(googleEmail: string): Promise<User> {
  await ensureUserStoreReady();

  const db = await dbPromise;
  const email = googleEmail.trim().toLowerCase();
  const existingUser = await db.getFromIndex(USERS_STORE, 'email', email) as StoredUser | undefined;

  if (!existingUser) {
    throw new Error('ACCOUNT_NOT_FOUND');
  }

  return createSession(existingUser);
}

export async function completeGoogleSignup(signupData: SignupData): Promise<User> {
  await ensureUserStoreReady();

  const db = await dbPromise;
  const username = signupData.username.trim();
  const email = signupData.email.trim().toLowerCase();

  if (!username || !email || !signupData.password) {
    throw new Error('Please fill username, email and password');
  }

  if (await db.getFromIndex(USERS_STORE, 'username', username)) {
    throw new Error('Username already exists');
  }

  if (await db.getFromIndex(USERS_STORE, 'email', email)) {
    throw new Error('Email already exists');
  }

  const newUser: StoredUser = {
    id: crypto.randomUUID(),
    username,
    email,
    role: 'operator',
    authProvider: 'google',
    passwordHash: await hashPassword(signupData.password),
    facilityId: 'FACILITY-001',
    createdAt: new Date().toISOString(),
  };

  await db.add(USERS_STORE, newUser);

  return createSession(newUser);
}

export function getCurrentUser(): User | null {
  const sessionData = localStorage.getItem(SESSION_KEY);
  if (!sessionData) return null;

  try {
    const session = JSON.parse(sessionData);

    if (session.expiresAt < Date.now()) {
      logout();
      return null;
    }

    return {
      id: session.id,
      username: session.username,
      email: session.email,
      role: session.role,
      authProvider: session.authProvider,
      facilityId: session.facilityId,
      lastLogin: new Date(session.lastLogin),
    };
  } catch {
    return null;
  }
}

export function logout(): void {
  localStorage.removeItem(SESSION_KEY);
}

export function isAuthenticated(): boolean {
  return getCurrentUser() !== null;
}
