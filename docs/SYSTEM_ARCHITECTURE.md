# AegisOps — System Architecture & Implementation Specification

See [docs/ADR_WAVE4_DEPLOYMENT.md](ADR_WAVE4_DEPLOYMENT.md) and [docs/DEPLOYMENT_RUNBOOK.md](DEPLOYMENT_RUNBOOK.md) for deployment architecture decisions, strict readiness controls, and operational runbooks.

## Core Architectural Pillars
1. **4-Layer Clean Architecture (`src/domain`, `src/application`, `src/infrastructure`, `src/presentation`):**
   - Strict separation of concerns across pure domain forensics/ledger modules, application orchestration, infrastructure adapters/guards, and React presentation components.
2. **Hybrid Deterministic Forensics + Multimodal Gemini Agent:**
   - 5 deterministic analyzers (`AccountProfileAnalyzer`, `MuleGraphAnalyzer`, `CyberSessionInspector`, `BusinessLogicAbuseDetector`, `ScamCampaignCorrelator`) compute exact facts, risk scores, and graph topology first (retaining authoritative risk classification and playbook recommendations).
   - `GeminiInvestigationAgentAdapter` (`gemini-3.5-flash-lite` primary default, `gemini-3.1-flash-lite` recommended configuration-only secondary fallback for new Google projects — live project access unverified until cloud smoke test; deterministic local fallback floor) synthesizes structured facts + untrusted synthetic multimodal evidence (delimited chat transcripts, uploaded sample screenshots) into a Vietnamese brief with citation reference validation (`TXN-*`, `LOG-*`, `DEV-*`, `EVT-*`, `EVD-*`; investigator semantic review required) and sanitized execution-path provenance (`PRIMARY_MODEL`, `FALLBACK_MODEL`, `DETERMINISTIC_FALLBACK`, `AI_UNAVAILABLE`).
3. **Closed-Loop Consumer Wallet Shield (Simulated Local Demo):**
   - Analyst 1-click L2 approval activates `ShieldRule` records evaluated locally by `ConsumerShieldEvaluator`.
   - The built-in **Consumer Wallet Shield Simulator** demonstrates immediate local interception (`BLOCKED` / `HELD` with zero premature balance debit) when a transfer targets a flagged mule account or scam pattern.
4. **Multi-Judge Session Isolation:**
   - Every browser gets an isolated `x-workspace-session` sandbox cloned from canonical seed data + 1-click Reset Demo.
