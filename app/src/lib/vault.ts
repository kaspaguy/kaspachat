// Local storage of everything secret. The encryption is the open protocol library's (protocol/src/vault.ts): one
// AES-256-GCM blob under a scrypt key from the device passcode. This file only stores that blob in IndexedDB.
// Forgetting the passcode only costs this device's copy: the recovery phrase rebuilds the identity.
import { openVault, sealVault, vaultKey, type SealedVault } from '../../../protocol/src/index.ts';

const DB = 'kaspachat';
const STORE = 'vault';

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbGet(k: string): Promise<any> {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE).objectStore(STORE).get(k);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}
async function idbPut(k: string, v: unknown): Promise<void> {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, 'readwrite');
    t.objectStore(STORE).put(v, k);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}
async function idbDel(k: string): Promise<void> {
  const db = await idb();
  return new Promise((resolve) => {
    const t = db.transaction(STORE, 'readwrite');
    t.objectStore(STORE).delete(k);
    t.oncomplete = () => resolve();
  });
}

export class Vault<T> {
  // `slot` is the IndexedDB key; the app has one vault ('main'), the stack test one per user.
  constructor(private slot = 'main') {}
  private key: Uint8Array | null = null;
  private salt: Uint8Array | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  data: T | null = null;

  static exists = async () => !!(await idbGet('main'));
  static wipe = () => idbDel('main');

  async create(pass: string, data: T) {
    this.salt = crypto.getRandomValues(new Uint8Array(16));
    this.key = vaultKey(pass, this.salt);
    this.data = data;
    await this.flush();
  }
  async unlock(pass: string): Promise<boolean> {
    const rec: SealedVault | undefined = await idbGet(this.slot);
    if (rec?.v !== 2) return false;
    try {
      const key = vaultKey(pass, rec.salt);
      this.data = openVault<T>(key, rec);
      this.key = key;
      this.salt = rec.salt;
      return true;
    } catch {
      return false;
    }
  }
  // A new passcode for the same data (new salt, new key), written at once.
  async rekey(pass: string) {
    this.salt = crypto.getRandomValues(new Uint8Array(16));
    this.key = vaultKey(pass, this.salt);
    await this.flush();
  }
  save() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.flush(), 400);
  }
  async flush() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.key || !this.data) return;
    await idbPut(this.slot, sealVault(this.key, this.salt!, this.data));
  }
  lock() {
    this.key = null;
    this.data = null;
  }
}
