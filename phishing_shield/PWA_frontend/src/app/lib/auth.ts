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

function getCrypto(): Crypto | null {
  return typeof globalThis !== 'undefined' && 'crypto' in globalThis ? globalThis.crypto : null;
}

function fallbackHash(input: string): string {
  let hash = 5381;
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  }

  return (hash >>> 0).toString(16).padStart(8, '0');
}

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
  const cryptoApi = getCrypto();

  if (cryptoApi?.subtle?.digest) {
    const data = new TextEncoder().encode(password);
    const digest = await cryptoApi.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  return fallbackHash(password);
}

async function ensureUserStoreReady(): Promise<void> {
  await dbPromise;
}

function generateUserId(): string {
  const cryptoApi = getCrypto();

  if (typeof cryptoApi?.randomUUID === 'function') {
    return cryptoApi.randomUUID();
  }

  if (!cryptoApi?.getRandomValues) {
    return `user-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
  }

  const bytes = cryptoApi.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
    id: generateUserId(),
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
    id: generateUserId(),
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
