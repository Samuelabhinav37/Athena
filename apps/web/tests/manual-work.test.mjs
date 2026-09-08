import assert from "node:assert/strict";
import test from "node:test";
import { manualWork } from "../src/assessment.ts";

const event = (action, revision, extra = {}) => ({ action, evidence_snapshot: { revision, ...extra } });

test("manual completion never appears verified without a later verification result", () => {
  const events = [event("fulfillment_assigned", 4, { due_at: "2026-09-10T00:00:00Z" })];
  assert.equal(manualWork({ events }, Date.parse("2026-09-11")).status, "overdue");
  events.push(event("operator_completed", 5));
  assert.equal(manualWork({ events }).status, "awaiting_verification");
  events.push(event("verification_recorded", 6, { outcome: "still_present" }));
  assert.equal(manualWork({ events }).status, "still_present");
  events.push(event("verification_recorded", 7, { outcome: "verified" }));
  assert.equal(manualWork({ events }).status, "verified");
});

test("reassigned work supersedes an earlier completion and retains original event order", () => {
  const events = [event("operator_completed", 5), event("fulfillment_assigned", 4), event("verification_recorded", 6, { outcome: "still_present" }), event("fulfillment_assigned", 7, { due_at: "2026-09-20T00:00:00Z" })];
  assert.equal(manualWork({ events }, Date.parse("2026-09-10")).status, "pending");
  assert.equal(events[0].action, "operator_completed");
});

test("a fresh verification request supersedes the previous outcome", () => {
  const events = [event("fulfillment_assigned", 4), event("operator_completed", 5), event("verification_recorded", 6, { outcome: "still_present" }), event("verification_requested", 7)];
  assert.equal(manualWork({ events }).status, "awaiting_verification");
  events.push(event("verification_recorded", 8, { outcome: "verified" }));
  assert.equal(manualWork({ events }).status, "verified");
});
