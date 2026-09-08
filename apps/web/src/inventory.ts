import type { Identity } from "./types";

export interface IdentityPage {
  items: Identity[];
  total: number;
  limit: number;
  offset: number;
}

export const INVENTORY_PAGE_SIZE = 50;

// Cancellation also guards readers that finish after their signal was aborted.
export function requestIdentityPage(
  read: (path: string, signal: AbortSignal) => Promise<IdentityPage>,
  query: string,
  offset: number,
  success: (page: IdentityPage) => void,
  failure: (error: unknown) => void
) {
  const controller = new AbortController();
  const parameters = new URLSearchParams({ q: query.trim(), limit: String(INVENTORY_PAGE_SIZE), offset: String(offset) });
  void read(`/v1/identities/inventory?${parameters}`, controller.signal)
    .then((page) => { if (!controller.signal.aborted) success(page); })
    .catch((error: unknown) => { if (!controller.signal.aborted) failure(error); });
  return () => controller.abort();
}
