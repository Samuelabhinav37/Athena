import { useState } from "react";
import type { User } from "oidc-client-ts";
import type { Identity } from "./types";
import { IdentityInventory } from "./IdentityInventory";
import { PersonLinkPanel } from "./PersonLinkPanel";
import { isPersonAccount, isPersonAnchor, personPairIssue } from "./personPair";

export function ManualPersonPair({ user }: { user: User }) {
  const [anchor, setAnchor] = useState<Identity>();
  const [account, setAccount] = useState<Identity>();
  const issue = personPairIssue(anchor, account);
  return <section className="panel" aria-label="Manual person-account selection">
    <h3>Select accounts using independent evidence</h3>
    <p>Contact details do not need to match. Choose a Keycloak person anchor and a separate provider account. Unsupported or inactive records are disabled; inventory counts still include them.</p>
    <div className="identity-layout">
      <IdentityInventory user={user} label="Person anchor" selectedId={anchor?.id ?? ""} onSelect={setAnchor} isSelectable={isPersonAnchor} />
      <IdentityInventory user={user} label="Provider account" selectedId={account?.id ?? ""} onSelect={setAccount} isSelectable={(item) => isPersonAccount(item) && item.id !== anchor?.id} />
    </div>
    <p>Person anchor: {anchor ? `${anchor.display_name} · ${anchor.source} · ${anchor.username} · ${anchor.id}` : "Not selected"}</p>
    <p>Provider account: {account ? `${account.display_name} · ${account.source} · ${account.username} · ${account.id}` : "Not selected"}</p>
    {issue ? <p role="status">{issue}</p> : anchor && account && <PersonLinkPanel key={`${anchor.id}:${account.id}`} user={user} anchorId={anchor.id} accountId={account.id} />}
  </section>;
}
