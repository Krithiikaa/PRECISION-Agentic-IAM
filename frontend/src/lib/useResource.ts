import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export type ResourceState<T> = {
  data: T | null;
  error: ApiError | Error | null;
  loading: boolean;
  /** 401 = sign in; 403 = signed in, role not permitted. Never inferred. */
  denied: 401 | 403 | null;
  reload: () => void;
  updatedAt: Date | null;
};

/**
 * Load one server resource, optionally refreshing it.
 *
 * The console never decides what a user may see: it asks, and renders the
 * server's answer -- including a refusal, which is shown as a permission
 * state rather than an error. `key` changes (e.g. the signed-in identity)
 * trigger a reload, so signing in re-asks the server.
 */
export function useResource<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  intervalMs = 0,
): ResourceState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const fetchRef = useRef(fetcher);
  fetchRef.current = fetcher;

  const load = useCallback(async () => {
    try {
      const result = await fetchRef.current();
      setData(result);
      setError(null);
      setUpdatedAt(new Date());
    } catch (e) {
      setError(e as Error);
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
    if (!intervalMs) return;
    const timer = setInterval(() => {
      if (document.visibilityState === "visible") load();
    }, intervalMs);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, intervalMs, ...deps]);

  const denied = error instanceof ApiError && (error.status === 401 || error.status === 403)
    ? (error.status as 401 | 403) : null;
  return { data, error, loading, denied, reload: load, updatedAt };
}
