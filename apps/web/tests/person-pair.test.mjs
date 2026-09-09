import assert from "node:assert/strict";
import test from "node:test";
import { personPairIssue } from "../src/personPair.ts";

const anchor = { id: "anchor", source: "keycloak", identity_type: "human", active: true, email: "a@example.test" };
const account = { id: "account", source: "azure_entra", identity_type: "human", active: true, email: "different@example.test" };

test("manual pairing permits different contact hints but requires distinct accounts", () => {
  assert.equal(personPairIssue(anchor, account), "");
  assert.match(personPairIssue(anchor, anchor), /differ/);
});
test("missing or unsupported anchors cannot open stewardship", () => {
  assert.match(personPairIssue(undefined, account), /Select both/);
  assert.match(personPairIssue(account, anchor), /Keycloak/);
});
test("inactive and workload accounts are excluded from person pairing", () => {
  assert.match(personPairIssue(anchor, { ...account, active: false }), /active human/);
  assert.match(personPairIssue(anchor, { ...account, identity_type: "workload" }), /active human/);
  assert.match(personPairIssue(anchor, { ...account, source: "github" }), /Keycloak or Entra/);
});
