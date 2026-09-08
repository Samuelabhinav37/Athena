import assert from "node:assert/strict";
import test from "node:test";
import { freshness, loadAssessment, orderReviews, reviewProgress } from "../src/assessment.ts";

test("missing, invalid, and future observations never count as recent", () => {
  const now = Date.parse("2026-09-06T12:00:00Z");
  for (const observed of [undefined, "invalid", "2026-09-07T12:00:00Z"]) {
    assert.equal(freshness(observed, now), "unknown");
  }
  assert.equal(freshness("2026-09-06T11:00:00Z", now), "recent");
  assert.equal(freshness("2026-09-04T12:00:00Z", now), "stale");
});

test("opening a case does not complete assignment or a review", () => {
  assert.deepEqual(reviewProgress([{ status: "open", owner: "alice", resolution: null }]), { assigned: false, completed: false });
  assert.deepEqual(reviewProgress([{ status: "in_review", owner: "alice", resolution: null }]), { assigned: true, completed: false });
  assert.deepEqual(reviewProgress([{ status: "resolved", owner: "alice", resolution: "retain" }]), { assigned: true, completed: true });
});

test("active work is ordered by deadline without mutating the API results", () => {
  const items = [
    { id: "closed", status: "resolved", due_at: "2026-09-01" },
    { id: "later", status: "open", due_at: "2026-09-10" },
    { id: "urgent", status: "in_review", due_at: "2026-09-02" }
  ];
  assert.deepEqual(orderReviews(items).map((item) => item.id), ["urgent", "later", "closed"]);
  assert.equal(items[0].id, "closed");
});

function reader(failingPath, status = 503) {
  return async (path) => {
    if (path === failingPath) throw Object.assign(new Error("Unavailable"), { status });
    if (path === "/v1/auth/me") return { username: "alice", roles: ["athena-viewer"] };
    if (path === "/v1/identities") return [{ id: "alice" }];
    if (path === "/v1/executions") throw new Error("Viewer must not request administrator data");
    return [];
  };
}

test("optional protection failure preserves core evidence with a visible warning", async () => {
  const result = await loadAssessment(reader("/v1/security/events"));
  assert.equal(result.identities[0].id, "alice");
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0], /Protection events unavailable/);
});

test("core evidence failure and expired sessions cannot masquerade as an empty healthy workspace", async () => {
  await assert.rejects(loadAssessment(reader("/v1/identities")), /Unavailable/);
  await assert.rejects(loadAssessment(reader("/v1/security/events", 401)), /Unavailable/);
});
