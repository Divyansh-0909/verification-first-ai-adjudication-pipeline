import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  ANALYST_INSTRUCTIONS,
  CONTRACT_VERSION,
  MODE,
  ROUTE,
  action,
  classification,
  createEvidenceJournal,
  createInMemoryAuditRepository,
  createOpenAIAdapter,
  createShadowAdjudicator,
  evidenceHash,
  evaluatePolicy,
  severity,
  validateAnalysis,
  validateEvidence,
} from "../src/index.js";

const now = "2020-01-01T00:00:00.500Z";
const policy = {
  policyVersion: "policy-v1",
  cases: {
    DISPUTE: {
      requiredCategories: ["record"],
      freshnessRequiredCategories: ["record"],
      maxAgeMsByCategory: { record: 1_000 },
      minConfidence: 0.8,
      allowedSeverities: [severity.LOW],
    },
  },
};

function bundle(options = {}) {
  const journal = createEvidenceJournal({
    caseId: "case-1",
    caseType: "DISPUTE",
    requiredCategories: ["record"],
    clock: () => new Date(now),
  });
  journal.record({
    id: "ev-1",
    category: "record",
    kind: "event",
    source: "system",
    observedAt: options.observedAt ?? "2020-01-01T00:00:00.000Z",
    receivedAt: options.receivedAt ?? "2020-01-01T00:00:00.000Z",
    quality: options.quality ?? {},
  });
  return journal.snapshot();
}

function envelope(input, changes = {}) {
  const { output: outputChanges = {}, ...envelopeChanges } = changes;
  const output = {
    caseId: input.caseId,
    suggestedClassification: classification.SUPPORTED,
    confidence: 0.9,
    factsSupporting: [
      { type: "FACT", evidenceIds: ["ev-1"], statement: "A record exists." },
    ],
    factsAgainst: [],
    inferences: [
      {
        type: "INFERENCE",
        evidenceIds: ["ev-1"],
        statement: "The record supports review.",
      },
    ],
    contradictions: [],
    missingEvidence: [],
    severityAssessment: severity.LOW,
    suggestedActionCategory: action.ADVISORY_SUPPORT,
    explanationSummary: "Advisory only.",
    ...outputChanges,
  };
  return {
    analysisId: changes.analysisId ?? randomUUID(),
    contractVersion: CONTRACT_VERSION,
    provider: "fake",
    model: "fake",
    evidenceHash: changes.evidenceHash ?? evidenceHash(input),
    ...envelopeChanges,
    output,
  };
}

function gate(input, result, suppliedHash = evidenceHash(input)) {
  return evaluatePolicy({
    bundle: input,
    envelope: result,
    hash: suppliedHash,
    policy,
    evaluatedAt: now,
  });
}

test("journal rejects duplicate evidence IDs", () => {
  const journal = createEvidenceJournal({ caseId: "x", caseType: "DISPUTE" });
  journal.record({
    id: "same",
    category: "record",
    kind: "event",
    source: "system",
  });
  assert.throws(
    () =>
      journal.record({
        id: "same",
        category: "record",
        kind: "event",
        source: "system",
      }),
    /Duplicate/,
  );
});

test("raw duplicate evidence IDs are invalid", () => {
  const input = structuredClone(bundle());
  input.timeline.push({ ...input.timeline[0] });
  assert.ok(
    validateEvidence(input, { evaluatedAt: now }).errors.includes(
      "DUPLICATE_EVIDENCE_ID",
    ),
  );
});

test("invented citations and empty citation arrays fail closed", () => {
  const input = bundle();
  const invented = envelope(input, {
    output: {
      factsSupporting: [
        { type: "FACT", evidenceIds: ["invented"], statement: "No." },
      ],
    },
  });
  assert.ok(
    validateAnalysis(input, invented).errors.includes(
      "INVENTED_EVIDENCE_REFERENCE",
    ),
  );
  const empty = envelope(input, {
    output: {
      factsSupporting: [{ type: "FACT", evidenceIds: [], statement: "No." }],
    },
  });
  assert.equal(validateAnalysis(input, empty).valid, false);
  assert.equal(gate(input, invented).route, ROUTE.HUMAN);
});

test("fact and inference type mismatches are schema failures", () => {
  const input = bundle();
  assert.equal(
    validateAnalysis(
      input,
      envelope(input, {
        output: {
          factsSupporting: [
            { type: "INFERENCE", evidenceIds: ["ev-1"], statement: "Wrong." },
          ],
        },
      }),
    ).valid,
    false,
  );
  assert.equal(
    validateAnalysis(
      input,
      envelope(input, {
        output: {
          inferences: [
            { type: "FACT", evidenceIds: ["ev-1"], statement: "Wrong." },
          ],
        },
      }),
    ).valid,
    false,
  );
});

test("unknown cases and missing required categories require a human", () => {
  const input = bundle();
  assert.equal(
    evaluatePolicy({
      bundle: { ...input, caseType: "UNKNOWN" },
      envelope: envelope(input),
      hash: evidenceHash(input),
      policy,
      evaluatedAt: now,
    }).route,
    ROUTE.HUMAN,
  );
  assert.equal(
    gate({ ...input, timeline: [] }, envelope(input)).route,
    ROUTE.HUMAN,
  );
});

test("null and out-of-range confidence are rejected", () => {
  const input = bundle();
  for (const confidence of [null, -0.01, 1.01, Infinity]) {
    assert.equal(
      validateAnalysis(input, envelope(input, { output: { confidence } }))
        .valid,
      false,
    );
  }
});

test("incompatible action and severity route a valid envelope to human review", () => {
  const input = bundle();
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: { suggestedActionCategory: action.ADVISORY_REJECT },
      }),
    ).route,
    ROUTE.HUMAN,
  );
  assert.equal(
    gate(
      input,
      envelope(input, { output: { severityAssessment: severity.HIGH } }),
    ).route,
    ROUTE.HUMAN,
  );
});

test("case and evidence hash binding mismatches are rejected", () => {
  const input = bundle();
  assert.ok(
    validateAnalysis(
      input,
      envelope(input, { evidenceHash: "a".repeat(64) }),
    ).errors.includes("EVIDENCE_HASH_MISMATCH"),
  );
  assert.ok(
    validateAnalysis(
      input,
      envelope(input, { output: { caseId: "other" } }),
    ).errors.includes("CASE_ID_MISMATCH"),
  );
  assert.equal(gate(input, envelope(input), "b".repeat(64)).route, ROUTE.HUMAN);
});

test("future and stale timestamps fail, and quality fresh cannot override age", () => {
  const future = bundle({
    observedAt: "2021-01-01T00:00:00.000Z",
    receivedAt: "2021-01-01T00:00:00.000Z",
  });
  assert.equal(validateEvidence(future, { evaluatedAt: now }).valid, false);
  const stale = bundle({
    observedAt: "2019-01-01T00:00:00.000Z",
    receivedAt: "2019-01-01T00:00:00.000Z",
    quality: { fresh: true },
  });
  assert.equal(gate(stale, envelope(stale)).route, ROUTE.HUMAN);
});

test("invalid or untrusted evidence quality forces human review", () => {
  const invalid = bundle({ quality: { invalid: true } });
  const missing = bundle({ quality: { provenance: "missing" } });
  const untrusted = bundle({ quality: { provenance: "untrusted" } });
  assert.equal(gate(invalid, envelope(invalid)).route, ROUTE.HUMAN);
  assert.equal(gate(missing, envelope(missing)).route, ROUTE.HUMAN);
  assert.equal(gate(untrusted, envelope(untrusted)).route, ROUTE.HUMAN);
});

test("invalid evaluated time fails closed", () => {
  const input = bundle();
  assert.equal(
    evaluatePolicy({
      bundle: input,
      envelope: envelope(input),
      hash: evidenceHash(input),
      policy,
      evaluatedAt: "not-a-time",
    }).route,
    ROUTE.HUMAN,
  );
});

test("derived evidence requires known non-self, acyclic provenance", () => {
  const input = structuredClone(bundle());
  input.timeline[0].basis = "derived";
  input.timeline[0].derivedFrom = ["missing"];
  assert.ok(
    validateEvidence(input, { evaluatedAt: now }).errors.includes(
      "INVALID_DERIVED_PROVENANCE",
    ),
  );
  input.timeline[0].derivedFrom = ["ev-1"];
  assert.ok(
    validateEvidence(input, { evaluatedAt: now }).errors.includes(
      "INVALID_DERIVED_PROVENANCE",
    ),
  );
  input.timeline.push({
    ...input.timeline[0],
    id: "ev-2",
    derivedFrom: ["ev-1"],
  });
  input.timeline[0].derivedFrom = ["ev-2"];
  assert.ok(
    validateEvidence(input, { evaluatedAt: now }).errors.includes(
      "CYCLIC_DERIVED_PROVENANCE",
    ),
  );
});

test("timeline contradictions are recomputed and force human review", () => {
  const journal = createEvidenceJournal({
    caseId: "c",
    caseType: "DISPUTE",
    requiredCategories: ["record"],
    clock: () => new Date(now),
  });
  journal.record({
    id: "a",
    category: "record",
    kind: "event",
    source: "a",
    claimKey: "status",
    value: "yes",
    observedAt: now,
    receivedAt: now,
  });
  journal.record({
    id: "b",
    category: "record",
    kind: "event",
    source: "b",
    claimKey: "status",
    value: "no",
    observedAt: now,
    receivedAt: now,
  });
  const input = journal.snapshot();
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: {
          factsSupporting: [
            { type: "FACT", evidenceIds: ["a"], statement: "yes" },
          ],
          inferences: [
            { type: "INFERENCE", evidenceIds: ["a"], statement: "uncertain" },
          ],
        },
      }),
    ).route,
    ROUTE.HUMAN,
  );
});

test("model-reported contradictions and missing evidence force human review", () => {
  const input = bundle();
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: {
          contradictions: [
            { evidenceIds: ["ev-1", "ev-1"], summary: "conflict" },
          ],
        },
      }),
    ).route,
    ROUTE.HUMAN,
  );
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: { missingEvidence: [{ category: "photo", reason: "needed" }] },
      }),
    ).route,
    ROUTE.HUMAN,
  );
});

test("uncertain outcomes and unsupported asserted support require human review", () => {
  const input = bundle();
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: {
          suggestedClassification: classification.UNCERTAIN,
          suggestedActionCategory: action.HUMAN_REVIEW,
        },
      }),
    ).route,
    ROUTE.HUMAN,
  );
  assert.equal(
    gate(
      input,
      envelope(input, {
        output: {
          suggestedClassification: classification.NEEDS_REVIEW,
          suggestedActionCategory: action.HUMAN_REVIEW,
        },
      }),
    ).route,
    ROUTE.HUMAN,
  );
  assert.equal(
    gate(input, envelope(input, { output: { factsSupporting: [] } })).route,
    ROUTE.HUMAN,
  );
});

test("malformed evidence and malformed provider output do not retry or advise", async () => {
  let calls = 0;
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze() {
        calls += 1;
        return null;
      },
    },
    policy,
    maxAttempts: 3,
    clock: () => new Date(now),
  });
  assert.equal((await adjudicator.evaluate(null)).route, ROUTE.HUMAN);
  assert.equal((await adjudicator.evaluate(bundle())).status, "MANUAL_REVIEW");
  assert.equal(calls, 1);
});

test("undefined, cyclic, and BigInt inputs fail closed without throwing", async () => {
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze() {
        throw new Error("must not call");
      },
    },
    policy,
    clock: () => new Date(now),
  });
  for (const value of [
    undefined,
    { value: 1n },
    (() => {
      const item = {};
      item.self = item;
      return item;
    })(),
  ]) {
    const result = await adjudicator.evaluate(value);
    assert.equal(result.route, ROUTE.HUMAN);
  }
});

test("429 and 503 retry with exponential requested delays", async () => {
  const input = bundle();
  const delays = [];
  let calls = 0;
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze() {
        calls += 1;
        if (calls < 3) throw { status: calls === 1 ? 429 : 503 };
        return envelope(input);
      },
    },
    policy,
    delay: async (ms) => delays.push(ms),
    maxAttempts: 3,
    clock: () => new Date(now),
  });
  assert.equal((await adjudicator.evaluate(input)).status, "COMPLETED");
  assert.deepEqual(delays, [30_000, 60_000]);
  assert.equal(calls, 3);
});

test("ordinary provider failures do not retry", async () => {
  let calls = 0;
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze() {
        calls += 1;
        throw new Error("bad output");
      },
    },
    policy,
    maxAttempts: 3,
    clock: () => new Date(now),
  });
  assert.equal((await adjudicator.evaluate(bundle())).status, "MANUAL_REVIEW");
  assert.equal(calls, 1);
});

test("concurrent and later identical work use one persisted evaluation", async () => {
  const input = bundle();
  let calls = 0;
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze(value) {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return envelope(value);
      },
    },
    policy,
    clock: () => new Date(now),
  });
  const results = await Promise.all([
    adjudicator.evaluate(input),
    adjudicator.evaluate(input),
  ]);
  assert.equal(calls, 1);
  assert.ok(results.every((result) => result.route === ROUTE.SHADOW));
  assert.equal((await adjudicator.evaluate(input)).status, "IDEMPOTENT_REPLAY");
});

test("nested snapshots and audit records are immutable", () => {
  const input = bundle();
  assert.throws(() => {
    input.timeline[0].source = "changed";
  }, TypeError);
  const repo = createInMemoryAuditRepository();
  const saved = repo.append({
    idempotencyKey: "key",
    gate: { route: ROUTE.HUMAN },
  }).record;
  assert.throws(() => {
    saved.gate.route = ROUTE.SHADOW;
  }, TypeError);
});

test("caller mutation during provider await cannot change validated bundle", async () => {
  const input = structuredClone(bundle());
  let supplied;
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze(value) {
        supplied = value;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return envelope(value);
      },
    },
    policy,
    clock: () => new Date(now),
  });
  const pending = adjudicator.evaluate(input);
  input.timeline[0].source = "mutated";
  await pending;
  assert.equal(supplied.timeline[0].source, "system");
});

test("repository failures propagate distinctly from analyst failures", async () => {
  const repo = {
    findByKey() {
      return null;
    },
    append() {
      throw new Error("storage unavailable");
    },
  };
  const adjudicator = createShadowAdjudicator({
    analyst: {
      async analyze(value) {
        return envelope(value);
      },
    },
    policy,
    repository: repo,
    clock: () => new Date(now),
  });
  await assert.rejects(adjudicator.evaluate(bundle()), /storage unavailable/);
});

test("OpenAI adapter uses structured parse, strict instructions, and wraps hash", async () => {
  const input = bundle();
  let request;
  const client = {
    responses: {
      async parse(value) {
        request = value;
        return {
          id: "response-1",
          output_parsed: envelope(input).output,
          usage: { input_tokens: 1, output_tokens: 2, total_tokens: 3 },
        };
      },
    },
  };
  const result = await createOpenAIAdapter({
    client,
    model: "explicit-model",
  }).analyze(input);
  assert.equal(request.instructions, ANALYST_INSTRUCTIONS);
  assert.equal(request.text.format.type, "json_schema");
  assert.equal(result.evidenceHash, evidenceHash(input));
  assert.equal(result.contractVersion, CONTRACT_VERSION);
});

test("OpenAI adapter rejects missing structured output", async () => {
  const client = {
    responses: {
      async parse() {
        return { id: "none", output_parsed: null };
      },
    },
  };
  await assert.rejects(
    createOpenAIAdapter({ client, model: "explicit" }).analyze(bundle()),
    /no structured output/,
  );
});
