// Tiny in-memory TTL cache with bounded size (FIFO eviction). Shared by every
// route so the Map + TTL + eviction pattern lives in one place.

interface Entry {
  data:      Record<string, unknown>;
  expiresAt: number;
}

export interface TtlCache {
  get(key: string): Record<string, unknown> | null;
  set(key: string, data: Record<string, unknown>): void;
}

export function createTtlCache(ttlMs: number, maxEntries = 1000): TtlCache {
  const cache = new Map<string, Entry>();
  return {
    get(key) {
      const entry = cache.get(key);
      if (!entry) return null;
      if (Date.now() > entry.expiresAt) { cache.delete(key); return null; }
      return entry.data;
    },
    set(key, data) {
      cache.set(key, { data, expiresAt: Date.now() + ttlMs });
      // Prevent unbounded memory growth — evict oldest if over the cap.
      if (cache.size > maxEntries) {
        const firstKey = cache.keys().next().value;
        if (firstKey) cache.delete(firstKey);
      }
    },
  };
}
