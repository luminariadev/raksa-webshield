export interface RateLimiterOptions {
  windowMs?: number;
  maxRequests?: number;
  maxTrackedKeys?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetMs: number;
  retryAfterSeconds: number;
}

interface BucketEntry {
  count: number;
  resetAt: number;
}

export interface MemoryRateLimiter {
  check(key: string): RateLimitResult;
  reset(): void;
  size(): number;
}

export function createMemoryRateLimiter(
  options: RateLimiterOptions = {},
): MemoryRateLimiter {
  const windowMs = Math.max(100, Math.floor(options.windowMs ?? 60_000));
  const limit = Math.max(1, Math.floor(options.maxRequests ?? 120));
  const maxKeys = Math.max(16, Math.floor(options.maxTrackedKeys ?? 10_000));
  const buckets = new Map<string, BucketEntry>();

  return {
    check(rawKey: string): RateLimitResult {
      const key = rawKey || "global";
      const now = Date.now();
      let entry = buckets.get(key);

      if (entry !== undefined) {
        // Promote key in insertion-order LRU map.
        buckets.delete(key);
        if (now >= entry.resetAt) {
          entry = { count: 0, resetAt: now + windowMs };
        }
      } else {
        if (buckets.size >= maxKeys) {
          const oldest = buckets.keys().next().value;
          if (oldest !== undefined) {
            buckets.delete(oldest);
          }
        }
        entry = { count: 0, resetAt: now + windowMs };
      }

      entry.count += 1;
      buckets.set(key, entry);

      const allowed = entry.count <= limit;
      const remaining = Math.max(0, limit - entry.count);
      const resetMs = Math.max(0, entry.resetAt - now);
      const retryAfterSeconds = allowed ? 0 : Math.max(1, Math.ceil(resetMs / 1000));

      return {
        allowed,
        remaining,
        limit,
        resetMs,
        retryAfterSeconds,
      };
    },
    reset(): void {
      buckets.clear();
    },
    size(): number {
      return buckets.size;
    },
  };
}
