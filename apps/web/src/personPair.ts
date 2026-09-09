import type { Identity } from "./types";

export const isPersonAnchor = (identity: Identity) => identity.active && identity.identity_type === "human" && identity.source === "keycloak";
export const isPersonAccount = (identity: Identity) => identity.active && identity.identity_type === "human" && ["keycloak", "azure_entra"].includes(identity.source);

export function personPairIssue(anchor?: Identity, account?: Identity): string {
  if (!anchor || !account) return "Select both accounts to inspect the exact pair.";
  if (!isPersonAnchor(anchor)) return "The person anchor must be an active human Keycloak account.";
  if (!isPersonAccount(account)) return "Select an active human Keycloak or Entra account.";
  if (anchor.id === account.id) return "The provider account must differ from the person anchor.";
  return "";
}
