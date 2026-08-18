import type { User } from "oidc-client-ts";

const baseUrl = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
  }
}

export async function apiGet<T>(user: User, path: string): Promise<T> {
  return apiRequest<T>(user, path, "GET");
}

export async function apiPost<T>(user: User, path: string): Promise<T> {
  return apiRequest<T>(user, path, "POST");
}

export async function apiText(user: User, path: string): Promise<string> {
  const response = await authenticatedFetch(user, path, "GET");
  return response.text();
}

async function apiRequest<T>(user: User, path: string, method: "GET" | "POST"): Promise<T> {
  const response = await authenticatedFetch(user, path, method);
  return response.json() as Promise<T>;
}

async function authenticatedFetch(user: User, path: string, method: "GET" | "POST") {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: { Authorization: `${user.token_type} ${user.access_token}` }
  });
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: string };
      message = body.detail ?? message;
    } catch {
      // Preserve the status-based message when the API does not return JSON.
    }
    throw new ApiError(response.status, message);
  }
  return response;
}
