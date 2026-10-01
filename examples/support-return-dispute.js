import {
  CONTRACT_VERSION,
  action,
  classification,
  createEvidenceJournal,
  createShadowAdjudicator,
  evidenceHash,
  severity,
} from "../src/index.js";
const journal = createEvidenceJournal({
  caseId: "return-42",
  caseType: "RETURN_DISPUTE",
  requiredCategories: ["order", "carrier_scan"],
});
journal.record({
  id: "order",
  category: "order",
  kind: "order_record",
  source: "support-system",
  value: { order: "42" },
  observedAt: "2020-01-01T00:00:00.000Z",
  receivedAt: "2020-01-01T00:00:00.000Z",
});
journal.record({
  id: "scan",
  category: "carrier_scan",
  kind: "delivery_scan",
  source: "carrier",
  value: { delivered: true },
  observedAt: "2020-01-01T00:00:00.000Z",
  receivedAt: "2020-01-01T00:00:00.000Z",
});
const bundle = journal.snapshot(),
  analyst = {
    async analyze(b) {
      return {
        analysisId: "synthetic-demo",
        contractVersion: CONTRACT_VERSION,
        provider: "synthetic",
        model: "none",
        evidenceHash: evidenceHash(b),
        output: {
          caseId: b.caseId,
          suggestedClassification: classification.SUPPORTED,
          confidence: 0.95,
          factsSupporting: [
            {
              type: "FACT",
              evidenceIds: ["scan"],
              statement: "Carrier recorded delivery.",
            },
          ],
          factsAgainst: [],
          inferences: [
            {
              type: "INFERENCE",
              evidenceIds: ["scan"],
              statement: "Return should be reviewed by support.",
            },
          ],
          contradictions: [],
          missingEvidence: [],
          severityAssessment: severity.LOW,
          suggestedActionCategory: action.ADVISORY_SUPPORT,
          explanationSummary: "Synthetic advisory only.",
        },
      };
    },
  };
const policy = {
  policyVersion: "support-return-v1",
  cases: {
    RETURN_DISPUTE: {
      requiredCategories: ["order", "carrier_scan"],
      freshnessRequiredCategories: [],
      minConfidence: 0.8,
      allowedSeverities: [severity.LOW],
    },
  },
};
console.log(
  JSON.stringify(
    await createShadowAdjudicator({
      analyst,
      policy,
      clock: () => new Date("2020-01-01T00:00:00.500Z"),
    }).evaluate(bundle),
    null,
    2,
  ),
);
