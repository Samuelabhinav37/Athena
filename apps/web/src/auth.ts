import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

const redirectUri = `${window.location.origin}/auth/callback`;

export const userManager = new UserManager({
  authority: import.meta.env.VITE_OIDC_AUTHORITY ?? "http://localhost:8080/realms/athena",
  client_id: import.meta.env.VITE_OIDC_CLIENT_ID ?? "athena-web",
  redirect_uri: redirectUri,
  post_logout_redirect_uri: window.location.origin,
  response_type: "code",
  scope: "openid profile email",
  automaticSilentRenew: false,
  userStore: new WebStorageStateStore({ store: window.sessionStorage })
});

export async function completeSignin(): Promise<User> {
  const user = await userManager.signinRedirectCallback();
  window.history.replaceState({}, document.title, "/");
  return user;
}
