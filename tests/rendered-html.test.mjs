import assert from "node:assert/strict";
import test from "node:test";

async function getWorker() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  return (await import(workerUrl.href)).default;
}

const env = {
  ASSETS: {
    fetch: async () => new Response("Not found", { status: 404 }),
  },
};

const context = {
  waitUntil() {},
  passThroughOnException() {},
};

test("server-renders the OpsSentinel dashboard", async () => {
  const worker = await getWorker();
  const response = await worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    env,
    context,
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>OpsSentinel/);
  assert.match(html, /Incident response cockpit/);
  assert.match(html, /Free Agent Mesh/);
  assert.doesNotMatch(html, /Parasail/i);
});

test("streams a complete no-paid-LLM incident flow", async () => {
  const worker = await getWorker();
  const response = await worker.fetch(
    new Request(
      "http://localhost/api/incidents/stream?incident_type=zero_day",
    ),
    env,
    context,
  );

  assert.equal(response.status, 200);
  assert.match(
    response.headers.get("content-type") ?? "",
    /^text\/event-stream\b/i,
  );

  const body = await response.text();
  const eventNames = [...body.matchAll(/^event: (.+)$/gm)].map(
    (match) => match[1],
  );
  assert.deepEqual(eventNames, [
    "stage",
    "stage",
    "stage",
    "stage",
    "complete",
  ]);
  assert.match(body, /"inference_mode":"evidence_rules"/);
  assert.doesNotMatch(body, /Parasail/i);
});

test("reports the free reasoning fallback without a secret", async () => {
  const worker = await getWorker();
  const response = await worker.fetch(
    new Request("http://localhost/api/status"),
    env,
    context,
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    youcom: "demo",
    reasoning: "evidence_rules",
    opsera: "simulated",
  });
});
