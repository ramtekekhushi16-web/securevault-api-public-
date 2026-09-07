import crypto from 'crypto';
const ALGO = 'aes-256-gcm';
const KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'master-key', 'salt', 32);
export function encrypt(text: string) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  let enc = cipher.update(text, 'utf8', 'hex'); enc += cipher.final('hex');
  return { encrypted: enc, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') };
}
export function decrypt(enc: string, ivHex: string, tagHex: string) {
  const decipher = crypto.createDecipheriv(ALGO, KEY, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  let dec = decipher.update(enc, 'hex', 'utf8'); dec += decipher.final('utf8'); return dec;
}