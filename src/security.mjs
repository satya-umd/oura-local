import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const KEY_FILE = path.join(DATA_DIR, '.secret_key');

function loadOrCreateMasterKey() {
  const envSecret = process.env.LAURA_SECRET_KEY?.trim();
  if (envSecret && envSecret.length >= 16) {
    return crypto.createHash('sha256').update(envSecret).digest();
  }
  if (fs.existsSync(KEY_FILE)) {
    const raw = fs.readFileSync(KEY_FILE, 'utf8').trim();
    if (raw.length >= 32) {
      return crypto.createHash('sha256').update(raw).digest();
    }
  }
  const generated = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(KEY_FILE, generated, { mode: 0o600 });
  return crypto.createHash('sha256').update(generated).digest();
}

const MASTER_KEY = loadOrCreateMasterKey();

/**
 * Encrypts sensitive strings (Oura PAT / OAuth2 tokens) at rest using AES-256-GCM.
 */
export function encryptSecret(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

/**
 * Decrypts AES-256-GCM encrypted strings stored in SQLite.
 */
export function decryptSecret(payload) {
  if (!payload) return null;
  try {
    const parts = String(payload).split('.');
    if (parts.length !== 3) return null;
    const [ivB64, tagB64, dataB64] = parts;
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const encrypted = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

/**
 * Hashes a user password with scrypt and a random 16-byte salt.
 */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

/**
 * Verifies a password against a stored scrypt hash using timingSafeEqual.
 */
export function verifyPassword(password, storedHash) {
  if (!password || !storedHash) return false;
  const parts = String(storedHash).split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, expectedHex] = parts;
  const derived = crypto.scryptSync(String(password), salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

/**
 * Generates a high-entropy 32-byte session token and its SHA-256 hash.
 */
export function generateSessionToken() {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = hashToken(token);
  return { token, tokenHash };
}

export function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

/**
 * Signs an OAuth2 state payload with HMAC-SHA256 to prevent CSRF.
 */
export function signOAuthState(data) {
  const payload = Buffer.from(JSON.stringify({ ...data, exp: Date.now() + 15 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', MASTER_KEY).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

export function verifyOAuthState(stateToken) {
  if (!stateToken || typeof stateToken !== 'string') return null;
  const [payload, sig] = stateToken.split('.');
  if (!payload || !sig) return null;
  const expectedSig = crypto.createHmac('sha256', MASTER_KEY).update(payload).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (parsed.exp && Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * In-memory rate limiter for authentication endpoints.
 */
const loginAttempts = new Map();

export function checkRateLimit(key, maxAttempts = 10, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1 };
  }
  if (entry.count >= maxAttempts) {
    const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, retryAfterSec };
  }
  entry.count += 1;
  return { allowed: true, remaining: maxAttempts - entry.count };
}

export function resetRateLimit(key) {
  loginAttempts.delete(key);
}

/**
 * Standard security headers for self-hosted web/PWA responses.
 */
export function applySecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self';"
  );
}
