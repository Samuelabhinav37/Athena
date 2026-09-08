import assert from "node:assert/strict";
import test from "node:test";
import { requestIdentityPage } from "../src/inventory.ts";

const flush = () => new Promise((resolve) => setImmediate(resolve));

test("search reaches the server with literal special characters and a bounded page", async () => {
  let path;
  let result;
  const page = { items: [{ id: "beyond-first-page" }], total: 1, limit: 50, offset: 0 };
  requestIdentityPage(async (requested) => { path = requested; return page; }, "  a+b & %_  ", 0,
    (value) => { result = value; }, assert.fail);
  await flush();
  const url = new URL(path, "https://athena.test");
  assert.equal(url.pathname, "/v1/identities/inventory");
  assert.equal(url.searchParams.get("q"), "a+b & %_");
  assert.equal(url.searchParams.get("limit"), "50");
  assert.deepEqual(result, page);
});

test("a slow old search cannot replace a newer results page after cancellation", async () => {
  let finishOld;
  let oldSignal;
  const received = [];
  const cancel = requestIdentityPage((path, signal) => {
    oldSignal = signal;
    return new Promise((resolve) => { finishOld = resolve; });
  }, "old", 0, (value) => received.push(value), assert.fail);
  cancel();
  requestIdentityPage(async (path) => {
    assert.equal(new URL(path, "https://athena.test").searchParams.get("offset"), "200");
    return { items: [{ id: "last" }], total: 201, limit: 50, offset: 200 };
  }, "new", 200, (value) => received.push(value), assert.fail);
  finishOld({ items: [{ id: "old" }], total: 1, limit: 50, offset: 0 });
  await flush();
  assert.equal(oldSignal.aborted, true);
  assert.deepEqual(received.map((value) => value.items[0].id), ["last"]);
});

test("session expiry and service failures propagate instead of becoming an empty inventory", async () => {
  for (const status of [401, 403, 503]) {
    const failure = { status };
    let received;
    requestIdentityPage(async () => { throw failure; }, "", 50, assert.fail,
      (error) => { received = error; });
    await flush();
    assert.equal(received, failure);
  }
});

test("unmounted inventory ignores late failures", async () => {
  let reject;
  const cancel = requestIdentityPage(() => new Promise((resolve, fail) => { reject = fail; }),
    "", 0, assert.fail, assert.fail);
  cancel();
  reject(new Error("late failure"));
  await flush();
});
