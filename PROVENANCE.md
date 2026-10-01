# Source lineage and extraction boundaries

This package generalizes the locally implemented responsibility-adjudication pipeline in RCS Travels. It preserves the architecture of a structured, evidence-only analyst followed by deterministic verification and routing. Domain identifiers, customer/captain records, credentials, payment writes, and application authentication are not included.

The source project is [Divyansh-0909/RCS-Travels-Website](https://github.com/Divyansh-0909/RCS-Travels-Website). The source paths below describe the local implementation at extraction time; unpublished application changes may not yet be available in that repository's default branch.

| Original RCS source                                    | Standalone responsibility                                                                                                     |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| `backend/services/responsibilityEvidence.js`           | Generic evidence journal, provenance, ordering, contradiction observations and immutable snapshots                            |
| `backend/services/responsibilityContracts.js`          | Generic evidence and structured analysis schemas                                                                              |
| `backend/services/responsibilityAnalyst.js`            | Evidence hash binding, citation validation, fact/inference separation and provider adapter                                    |
| `backend/services/responsibilityPolicyGate.js`         | Configurable required-evidence, freshness, quality, compatibility and routing gates                                           |
| `backend/services/responsibilityShadowConfig.js`       | Shadow/disabled modes and bounded retry configuration                                                                         |
| `backend/services/responsibilityShadowAdjudication.js` | Advisory processing, repeat-work deduplication and audit outcomes                                                             |
| `backend/services/responsibilityShadowRepository.js`   | Repository boundary; this package supplies an in-memory implementation rather than the application's Prisma/lease integration |

The generic package uses a synthetic support-return case in place of transport cancellation types. It retains the separation between analysis, policy routing, and final application actions. The standalone code is an extraction and generalization, not a verbatim dump of the application backend.

## Application components that remain application-specific

- Authenticated capture of booking, location, payment and administrative evidence.
- PostgreSQL/Prisma work claims and lease ownership across workers.
- Administrative decisions, appeals, finalization and notifications.
- Refund, wallet, compensation, liability and account-reliability effects.
- The RCS-specific benchmark corpus and local provider preflight outputs.

No private evidence or benchmark run artifacts were carried into this repository. The examples and test inputs are synthetic. Test results establish behavior against those inputs, not production model accuracy.
