# AegisOps — System Architecture & Implementation Specification

See full interactive plan in the session artifact `implementation_plan.md`.

## Core Architectural Pillars
1. **4-Layer Clean Architecture (`src/domain`, `src/application`, `src/infrastructure`, `src/presentation`):**
   - Strict separation of concerns across pure domain forensics/ledger modules, application orchestration, infrastructure adapters/guards, and React presentation components.
2. **Hybrid Deterministic Forensics + Multimodal Gemini Agent:**
   - 5 deterministic analyzers (`AccountProfileAnalyzer`, `MuleGraphAnalyzer`, `CyberSessionInspector`, `BusinessLogicAbuseDetector`, `ScamCampaignCorrelator`) compute exact facts, risk scores, and graph topology first (retaining authoritative risk classification and playbook recommendations).
   - `GeminiInvestigationAgentAdapter` (`gemini-3.5-flash-lite` primary default, `gemini-2.5-flash-lite` secondary fallback, deterministic local fallback) synthesizes structured facts + untrusted multimodal evidence (delimited chat transcripts, uploaded screenshots) into a Vietnamese brief with citation reference validation (`TXN-*`, `LOG-*`, `DEV-*`, `EVT-*`, `EVD-*`; investigator semantic review required).
3. **Closed-Loop Consumer Wallet Shield (Simulated Local Demo):**
   - Analyst 1-click L2 approval activates `ShieldRule` records evaluated locally by `ConsumerShieldEvaluator`.
   - The built-in **Consumer Wallet Shield Simulator** demonstrates immediate local interception (`BLOCKED` / `HELD` with zero premature balance debit) when a transfer targets a flagged mule account or scam pattern.
4. **Multi-Judge Session Isolation:**
   - Every browser gets an isolated `x-workspace-session` sandbox cloned from canonical seed data + 1-click Reset Demo.
