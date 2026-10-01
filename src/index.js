import { createHash, randomUUID } from "node:crypto";
import { setTimeout as retryDelay } from "node:timers/promises";
import { z } from "zod";
import { zodTextFormat } from "openai/helpers/zod";

export const CONTRACT_VERSION = "verification-first-analysis-v1";
export const ROUTE = Object.freeze({
  SHADOW: "SHADOW_ADVISORY",
  HUMAN: "HUMAN_REVIEW",
});
export const MODE = Object.freeze({ DISABLED: "disabled", SHADOW: "shadow" });
export const classification = Object.freeze({
  SUPPORTED: "SUPPORTED",
  NOT_SUPPORTED: "NOT_SUPPORTED",
  UNCERTAIN: "UNCERTAIN",
  NEEDS_REVIEW: "NEEDS_REVIEW",
});
export const action = Object.freeze({
  ADVISORY_SUPPORT: "ADVISORY_SUPPORT",
  ADVISORY_REJECT: "ADVISORY_REJECT",
  HUMAN_REVIEW: "HUMAN_REVIEW",
});
export const severity = Object.freeze({
  LOW: "LOW",
  MODERATE: "MODERATE",
  HIGH: "HIGH",
});
const json = z.json();
const iso = z.iso.datetime();
export const evidenceEntrySchema = z
  .object({
    id: z.string().min(1),
    category: z.string().min(1),
    kind: z.string().min(1),
    value: json,
    source: z.string().trim().min(1),
    basis: z.enum(["direct", "derived"]),
    derivedFrom: z.array(z.string().min(1)),
    availability: z.enum(["available", "unknown", "not_available"]),
    claimKey: z.string().min(1).nullable(),
    observedAt: iso,
    receivedAt: iso,
    quality: z.record(z.string(), json),
  })
  .strict();
export const evidenceBundleSchema = z
  .object({
    evidenceVersion: z.string().min(1),
    caseId: z.string().min(1),
    caseType: z.string().min(1),
    generatedAt: iso,
    timeline: z.array(evidenceEntrySchema),
    completeness: z
      .object({
        requiredCategories: z.array(z.string().min(1)),
        complete: z.boolean(),
        missing: z.array(z.string().min(1)),
        unavailable: z.array(z.string().min(1)),
      })
      .strict(),
    contradictions: z.array(
      z
        .object({
          claimKey: z.string().min(1),
          observations: z
            .array(
              z
                .object({
                  value: json,
                  evidenceIds: z.array(z.string().min(1)).min(1),
                })
                .strict(),
            )
            .min(2),
        })
        .strict(),
    ),
  })
  .strict();
const citation = (type) =>
  z
    .object({
      type: z.literal(type),
      evidenceIds: z.array(z.string().min(1)).min(1),
      statement: z.string().trim().min(1),
    })
    .strict();
export const analysisSchema = z
  .object({
    caseId: z.string().min(1),
    suggestedClassification: z.enum(Object.values(classification)),
    confidence: z.number().finite().min(0).max(1),
    factsSupporting: z.array(citation("FACT")),
    factsAgainst: z.array(citation("FACT")),
    inferences: z.array(citation("INFERENCE")),
    contradictions: z.array(
      z
        .object({
          evidenceIds: z.array(z.string().min(1)).min(2),
          summary: z.string().min(1),
        })
        .strict(),
    ),
    missingEvidence: z.array(
      z
        .object({ category: z.string().min(1), reason: z.string().min(1) })
        .strict(),
    ),
    severityAssessment: z.enum(Object.values(severity)),
    suggestedActionCategory: z.enum(Object.values(action)),
    explanationSummary: z.string().min(1),
  })
  .strict();
export const analystEnvelopeSchema = z
  .object({
    analysisId: z.string().min(1),
    contractVersion: z.literal(CONTRACT_VERSION),
    provider: z.string().min(1),
    model: z.string().min(1),
    evidenceHash: z.string().regex(/^[a-f0-9]{64}$/),
    usage: z
      .object({
        inputTokens: z.number().int().nonnegative().nullable(),
        outputTokens: z.number().int().nonnegative().nullable(),
        totalTokens: z.number().int().nonnegative().nullable(),
        requestCount: z.number().int().positive(),
      })
      .strict()
      .optional(),
    output: analysisSchema,
  })
  .strict();
const clone = (value) => structuredClone(value);
const deepFreeze = (value) => {
  if (!value || typeof value !== "object" || Object.isFrozen(value))
    return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
};
const stable = (value) =>
  Array.isArray(value)
    ? value.map(stable)
    : value && typeof value === "object"
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((k) => [k, stable(value[k])]),
        )
      : value;
export const stableSerialize = (value) => JSON.stringify(stable(value));
const timestamp = (value) => {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()))
    throw new TypeError("Invalid timestamp");
  return date.toISOString();
};
const contradictionsFor = (entries) => {
  const claims = new Map();
  for (const entry of entries) {
    if (!entry.claimKey || entry.availability !== "available") continue;
    const values = claims.get(entry.claimKey) ?? new Map(),
      key = stableSerialize(entry.value),
      observation = values.get(key) ?? {
        value: clone(entry.value),
        evidenceIds: [],
      };
    observation.evidenceIds.push(entry.id);
    values.set(key, observation);
    claims.set(entry.claimKey, values);
  }
  return [...claims]
    .filter(([, v]) => v.size > 1)
    .map(([claimKey, v]) => ({ claimKey, observations: [...v.values()] }))
    .sort((a, b) => a.claimKey.localeCompare(b.claimKey));
};
export const evidenceHash = (bundle) => {
  const b = evidenceBundleSchema.parse(bundle);
  return createHash("sha256")
    .update(
      stableSerialize({
        evidenceVersion: b.evidenceVersion,
        caseId: b.caseId,
        caseType: b.caseType,
        timeline: b.timeline,
        completeness: b.completeness,
        contradictions: b.contradictions,
      }),
    )
    .digest("hex");
};
export function createEvidenceJournal({
  caseId,
  caseType,
  requiredCategories = [],
  clock = () => new Date(),
} = {}) {
  if (!caseId || !caseType)
    throw new TypeError("caseId and caseType are required");
  const entries = [],
    ids = new Set();
  let n = 0;
  const record = ({
    id = `ev_${String(++n).padStart(4, "0")}`,
    category,
    kind,
    value = null,
    source,
    basis = "direct",
    derivedFrom = [],
    availability = "available",
    claimKey = null,
    observedAt = clock(),
    receivedAt = clock(),
    quality = {},
  } = {}) => {
    if (!id || ids.has(id)) throw new TypeError(`Duplicate evidence id: ${id}`);
    if (
      !category ||
      !kind ||
      !source ||
      !["direct", "derived"].includes(basis) ||
      !["available", "unknown", "not_available"].includes(availability) ||
      (basis === "derived" && !derivedFrom.length)
    )
      throw new TypeError("Invalid evidence metadata");
    const entry = {
      id,
      category,
      kind,
      value: clone(value),
      source,
      basis,
      derivedFrom: [...derivedFrom],
      availability,
      claimKey,
      observedAt: timestamp(observedAt),
      receivedAt: timestamp(receivedAt),
      quality: clone(quality),
    };
    entries.push(entry);
    ids.add(id);
    return clone(entry);
  };
  const snapshot = () => {
    const timeline = clone(entries).sort(
      (a, b) =>
        a.observedAt.localeCompare(b.observedAt) ||
        a.receivedAt.localeCompare(b.receivedAt) ||
        a.id.localeCompare(b.id),
    );
    const available = new Set(
        timeline
          .filter((e) => e.availability === "available")
          .map((e) => e.category),
      ),
      missing = requiredCategories.filter(
        (c) => !timeline.some((e) => e.category === c),
      ),
      unavailable = requiredCategories.filter(
        (c) => !available.has(c) && !missing.includes(c),
      );
    return deepFreeze(
      evidenceBundleSchema.parse({
        evidenceVersion: "normalized-evidence-v1",
        caseId,
        caseType,
        generatedAt: timestamp(clock()),
        timeline,
        completeness: {
          requiredCategories: [...requiredCategories],
          complete: !missing.length && !unavailable.length,
          missing,
          unavailable,
        },
        contradictions: contradictionsFor(timeline),
      }),
    );
  };
  return { record, snapshot };
}
export function validateEvidence(bundle, { evaluatedAt = new Date() } = {}) {
  const parsed = evidenceBundleSchema.safeParse(bundle);
  if (!parsed.success)
    return { valid: false, errors: ["EVIDENCE_SCHEMA_INVALID"] };
  const b = parsed.data,
    errors = [],
    ids = new Set(),
    graph = new Map(),
    now = Date.parse(evaluatedAt);
  if (!Number.isFinite(now)) errors.push("EVALUATION_TIME_INVALID");
  for (const e of b.timeline) {
    if (ids.has(e.id)) errors.push("DUPLICATE_EVIDENCE_ID");
    ids.add(e.id);
    graph.set(e.id, e.derivedFrom);
    const o = Date.parse(e.observedAt),
      r = Date.parse(e.receivedAt);
    if (
      !Number.isFinite(o) ||
      !Number.isFinite(r) ||
      o > r ||
      o > now ||
      r > now
    )
      errors.push("INVALID_EVIDENCE_TIME");
    if (
      e.basis === "derived" &&
      (!e.derivedFrom.length ||
        e.derivedFrom.includes(e.id) ||
        e.derivedFrom.some(
          (id) =>
            !b.timeline.some(
              (x) => x.id === id && x.availability === "available",
            ),
        ))
    )
      errors.push("INVALID_DERIVED_PROVENANCE");
    if (e.basis === "direct" && e.derivedFrom.length)
      errors.push("INVALID_DIRECT_PROVENANCE");
    const provenance = e.quality.provenance;
    if (
      (e.quality.invalid !== undefined && e.quality.invalid !== false) ||
      (provenance !== undefined &&
        !["trusted", "verified", "direct", "derived"].includes(provenance))
    )
      errors.push("INVALID_EVIDENCE_QUALITY");
  }
  const visiting = new Set(),
    seen = new Set(),
    cycle = (id) => {
      if (visiting.has(id)) return true;
      if (seen.has(id)) return false;
      visiting.add(id);
      const found = (graph.get(id) ?? []).some(cycle);
      visiting.delete(id);
      seen.add(id);
      return found;
    };
  if ([...ids].some(cycle)) errors.push("CYCLIC_DERIVED_PROVENANCE");
  if (
    stableSerialize(contradictionsFor(b.timeline)) !==
    stableSerialize(b.contradictions)
  )
    errors.push("CONTRADICTION_SNAPSHOT_MISMATCH");
  return {
    valid: !errors.length,
    errors: [...new Set(errors)],
    bundle: deepFreeze(clone(b)),
  };
}
export function validateAnalysis(bundle, envelope) {
  const parsed = analystEnvelopeSchema.safeParse(envelope);
  if (!parsed.success)
    return {
      valid: false,
      errors: ["ANALYSIS_SCHEMA_INVALID"],
      citedEvidenceIds: [],
    };
  const e = parsed.data,
    errors = [],
    output = e.output;
  if (e.evidenceHash !== evidenceHash(bundle))
    errors.push("EVIDENCE_HASH_MISMATCH");
  if (output.caseId !== bundle.caseId) errors.push("CASE_ID_MISMATCH");
  const known = new Set(bundle.timeline.map((x) => x.id)),
    cited = [
      ...output.factsSupporting,
      ...output.factsAgainst,
      ...output.inferences,
      ...output.contradictions,
    ].flatMap((x) => x.evidenceIds);
  if (cited.some((id) => !known.has(id)))
    errors.push("INVENTED_EVIDENCE_REFERENCE");
  const clean = (s) => s.trim().replace(/\s+/g, " ").toLowerCase(),
    support = new Set(output.factsSupporting.map((x) => clean(x.statement)));
  if (output.factsAgainst.some((x) => support.has(clean(x.statement))))
    errors.push("SELF_CONTRADICTORY_FACTS");
  return {
    valid: !errors.length,
    errors,
    citedEvidenceIds: [...new Set(cited)],
  };
}
export const ANALYST_INSTRUCTIONS =
  "Analyze only the normalized evidence supplied. Never invent evidence or IDs. Keep FACT and INFERENCE separate; each must cite supplied IDs. Report uncertainty, contradictions, and missing evidence. Results are advisory only: do not make final decisions or recommend executable consequences, payments, refunds, account actions, liability, or appeal outcomes.";
export function createOpenAIAdapter({ client, model } = {}) {
  if (!client?.responses?.parse)
    throw new TypeError("Inject an OpenAI Responses client");
  if (!model) throw new TypeError("OPENAI_MODEL must be explicitly provided");
  return {
    async analyze(bundle) {
      const hash = evidenceHash(bundle),
        r = await client.responses.parse({
          model,
          instructions: ANALYST_INSTRUCTIONS,
          input: stableSerialize(bundle),
          text: {
            format: zodTextFormat(
              analysisSchema,
              "verification_first_analysis",
            ),
          },
        });
      if (!r.output_parsed)
        throw new Error("Provider returned no structured output");
      const u = r.usage ?? {};
      return analystEnvelopeSchema.parse({
        analysisId: r.id,
        contractVersion: CONTRACT_VERSION,
        provider: "openai",
        model,
        evidenceHash: hash,
        usage: {
          inputTokens: Number.isInteger(u.input_tokens) ? u.input_tokens : null,
          outputTokens: Number.isInteger(u.output_tokens)
            ? u.output_tokens
            : null,
          totalTokens: Number.isInteger(u.total_tokens) ? u.total_tokens : null,
          requestCount: 1,
        },
        output: r.output_parsed,
      });
    },
  };
}
export function evaluatePolicy({
  bundle,
  envelope,
  hash,
  policy,
  evaluatedAt = new Date(),
} = {}) {
  const passed = [],
    failed = [],
    add = (c, p, d) => (p ? passed : failed).push({ code: c, detail: d }),
    casePolicy = policy?.cases?.[bundle?.caseType],
    finish = () => ({
      route: failed.length ? ROUTE.HUMAN : ROUTE.SHADOW,
      humanReviewRequired: Boolean(failed.length),
      policyVersion: policy?.policyVersion ?? "invalid-policy",
      evaluatedAt: Number.isFinite(Date.parse(evaluatedAt))
        ? timestamp(evaluatedAt)
        : null,
      passedGates: passed,
      failedGates: failed,
      reasons: failed.map((x) => `${x.code}:${x.detail}`),
    });
  add("CASE_TYPE_ALLOWLIST", !!casePolicy, casePolicy ? "allowed" : "unknown");
  if (!casePolicy) return finish();
  const ev = validateEvidence(bundle, { evaluatedAt }),
    an = ev.valid
      ? validateAnalysis(bundle, envelope)
      : { valid: false, errors: ["EVIDENCE_INVALID"] };
  add(
    "EVIDENCE_VALIDATION",
    ev.valid,
    ev.valid ? "valid" : ev.errors.join(","),
  );
  add(
    "ANALYSIS_VALIDATION",
    an.valid,
    an.valid ? "valid" : an.errors.join(","),
  );
  if (!ev.valid) return finish();
  add("EVIDENCE_HASH", hash === evidenceHash(bundle), "verified");
  const available = new Map();
  for (const x of bundle.timeline)
    if (x.availability === "available")
      available.set(x.category, [...(available.get(x.category) ?? []), x]);
  const missing = (casePolicy.requiredCategories ?? []).filter(
      (c) => !available.has(c),
    ),
    now = Date.parse(evaluatedAt),
    stale = (casePolicy.freshnessRequiredCategories ?? []).filter(
      (c) =>
        !(available.get(c) ?? []).some(
          (x) =>
            now - Date.parse(x.observedAt) <=
            casePolicy.maxAgeMsByCategory?.[c],
        ),
    );
  add("REQUIRED_EVIDENCE", !missing.length, missing.join(",") || "complete");
  add("EVIDENCE_FRESHNESS", !stale.length, stale.join(",") || "fresh");
  add(
    "MATERIAL_CONTRADICTIONS",
    !bundle.contradictions.length,
    bundle.contradictions.length ? "unresolved" : "none",
  );
  if (an.valid) {
    const o = envelope.output;
    add(
      "AI_REPORTED_MISSING_EVIDENCE",
      !o.missingEvidence.length,
      o.missingEvidence.length ? "reported" : "none",
    );
    add(
      "AI_REPORTED_CONTRADICTIONS",
      !o.contradictions.length,
      o.contradictions.length ? "reported" : "none",
    );
    add(
      "CONFIDENCE_FLOOR",
      o.confidence >= casePolicy.minConfidence,
      String(o.confidence),
    );
    add(
      "SEVERITY_ALLOWLIST",
      (casePolicy.allowedSeverities ?? []).includes(o.severityAssessment),
      o.severityAssessment,
    );
    const compat =
      o.suggestedClassification === classification.SUPPORTED
        ? o.suggestedActionCategory === action.ADVISORY_SUPPORT
        : o.suggestedClassification === classification.NOT_SUPPORTED
          ? o.suggestedActionCategory === action.ADVISORY_REJECT
          : o.suggestedActionCategory === action.HUMAN_REVIEW;
    add(
      "CLASSIFICATION_ACTION_COMPATIBILITY",
      compat,
      `${o.suggestedClassification}/${o.suggestedActionCategory}`,
    );
    add(
      "ADVISORY_ELIGIBILITY",
      [classification.SUPPORTED, classification.NOT_SUPPORTED].includes(
        o.suggestedClassification,
      ) && o.suggestedActionCategory !== action.HUMAN_REVIEW,
      o.suggestedClassification,
    );
    const grounding =
      o.suggestedClassification === classification.SUPPORTED
        ? o.factsSupporting
        : o.factsAgainst;
    add(
      "GROUNDED_FACTS",
      grounding.length > 0,
      grounding.length ? "cited" : "absent",
    );
  }
  return finish();
}
export const evaluationKey = ({ caseId, hash, policyVersion }) =>
  [caseId, hash, policyVersion, CONTRACT_VERSION].join(":");
export function createInMemoryAuditRepository() {
  const rows = new Map();
  return {
    findByKey: (key) =>
      rows.has(key) ? deepFreeze(clone(rows.get(key))) : null,
    append: (row) => {
      if (rows.has(row.idempotencyKey))
        return {
          created: false,
          record: deepFreeze(clone(rows.get(row.idempotencyKey))),
        };
      const saved = deepFreeze({ ...clone(row), auditId: randomUUID() });
      rows.set(row.idempotencyKey, saved);
      return { created: true, record: deepFreeze(clone(saved)) };
    },
    list: () => deepFreeze([...rows.values()].map(clone)),
  };
}
const isTransient = (e) =>
  e?.code === "ETIMEDOUT" ||
  e?.name === "AbortError" ||
  e?.status === 429 ||
  Number(e?.status) >= 500;
export function createShadowAdjudicator({
  analyst,
  policy,
  repository = createInMemoryAuditRepository(),
  mode = MODE.SHADOW,
  maxAttempts = 3,
  delay = retryDelay,
  clock = () => new Date(),
} = {}) {
  if (
    !analyst?.analyze ||
    !repository?.findByKey ||
    !repository?.append ||
    !Object.values(MODE).includes(mode) ||
    !Number.isInteger(maxAttempts) ||
    maxAttempts < 1 ||
    maxAttempts > 10 ||
    typeof analyst.analyze !== "function" ||
    typeof repository.findByKey !== "function" ||
    typeof repository.append !== "function" ||
    typeof delay !== "function"
  )
    throw new TypeError("Invalid adjudicator configuration");
  // Capture configuration before any awaited analyst call. Change the policy
  // version when changing rules so persisted replay keys remain meaningful.
  policy = deepFreeze(clone(policy));
  const inflight = new Map();
  const evaluate = async (input) => {
    let validated;
    try {
      validated = validateEvidence(input, { evaluatedAt: clock() });
    } catch {
      // Non-JSON or cyclic input must never reach a provider or crash routing.
      validated = { valid: false, errors: ["EVIDENCE_SCHEMA_INVALID"] };
    }
    const safeBundle = validated.bundle ?? null;
    if (!validated.valid) {
      let fingerprint;
      try {
        fingerprint = stableSerialize(input) ?? "undefined";
      } catch {
        // Do not attempt to serialize an unsupported payload into the audit.
        fingerprint = `unserializable:${randomUUID()}`;
      }
      const key = `invalid:${createHash("sha256").update(fingerprint).digest("hex")}`,
        gate = {
          route: ROUTE.HUMAN,
          humanReviewRequired: true,
          reasons: validated.errors,
        };
      const saved = await repository.append({
        idempotencyKey: key,
        gate,
        error: { category: "EVIDENCE_SCHEMA_INVALID" },
        recordedAt: timestamp(clock()),
      });
      return {
        status: "MANUAL_REVIEW",
        route: ROUTE.HUMAN,
        result: saved.record,
      };
    }
    if (mode === MODE.DISABLED)
      return { status: "DISABLED", route: ROUTE.HUMAN };
    const hash = evidenceHash(safeBundle),
      key = evaluationKey({
        caseId: safeBundle.caseId,
        hash,
        policyVersion: policy?.policyVersion ?? "invalid-policy",
      }),
      saved = await repository.findByKey(key);
    if (saved)
      return {
        status: "IDEMPOTENT_REPLAY",
        route: saved.gate.route,
        result: saved,
      };
    if (inflight.has(key)) return inflight.get(key);
    const job = (async () => {
      let envelope,
        error,
        attempts = 0,
        malformedAnalysis = false;
      for (let a = 1; a <= maxAttempts; a += 1)
        try {
          attempts = a;
          envelope = await analyst.analyze(clone(safeBundle));
          break;
        } catch (e) {
          error = e;
          if (!isTransient(e) || a === maxAttempts) break;
          await delay(Math.min(900000, 30000 * 2 ** (a - 1)), a);
        }
      if (envelope !== undefined) {
        const parsed = analystEnvelopeSchema.safeParse(envelope);
        malformedAnalysis = !parsed.success;
        envelope = parsed.success ? deepFreeze(parsed.data) : null;
      }
      const gate = envelope
        ? evaluatePolicy({
            bundle: safeBundle,
            envelope,
            hash,
            policy,
            evaluatedAt: clock(),
          })
        : {
            route: ROUTE.HUMAN,
            humanReviewRequired: true,
            reasons: [
              malformedAnalysis ? "ANALYSIS_SCHEMA_INVALID" : "ANALYST_FAILURE",
            ],
          };
      const row = await repository.append({
        idempotencyKey: key,
        caseId: safeBundle.caseId,
        evidenceHash: hash,
        contractVersion: CONTRACT_VERSION,
        attempts,
        envelope: envelope ?? null,
        gate,
        error: envelope
          ? null
          : {
              category: malformedAnalysis
                ? "ANALYSIS_SCHEMA_INVALID"
                : isTransient(error)
                  ? "TRANSIENT_ANALYST_FAILURE"
                  : "ANALYST_FAILURE",
            },
        recordedAt: timestamp(clock()),
      });
      return {
        status: row.created
          ? envelope && gate.route !== ROUTE.HUMAN
            ? "COMPLETED"
            : "MANUAL_REVIEW"
          : "IDEMPOTENT_REPLAY",
        route: row.record.gate.route,
        result: row.record,
      };
    })();
    inflight.set(key, job);
    try {
      return await job;
    } finally {
      inflight.delete(key);
    }
  };
  return { evaluate, repository };
}
