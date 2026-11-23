/**
 * Deterministic Evidence Citation Reference Validator (CR-2.1 Accurate Scope):
 * - Validates **reference validity**: ensures every emitted citation ID exists in `validEvidenceIds`
 *   for the current investigation (rejecting fabricated or out-of-case IDs and repairing wrapped/unique-prefix IDs).
 * - Limitation: Does NOT perform semantic entailment verification of AI prose against evidence text;
 *   investigator review of the linked source records remains required.
 */
export const validateAndRepairCitations = (
  aiCitedIds: readonly string[] | undefined | null,
  validEvidenceIds: readonly string[],
  fallbackTopIds: readonly string[] = []
): string[] => {
  if (validEvidenceIds.length === 0) {
    return [];
  }

  const exactMap = new Map<string, string>();
  validEvidenceIds.forEach((id) => {
    exactMap.set(id.trim().toUpperCase(), id);
  });

  const validated: string[] = [];
  const seen = new Set<string>();

  const addIfNew = (canonicalId: string): void => {
    if (!seen.has(canonicalId)) {
      seen.add(canonicalId);
      validated.push(canonicalId);
    }
  };

  if (Array.isArray(aiCitedIds)) {
    for (const rawId of aiCitedIds) {
      if (typeof rawId !== 'string') continue;
      const cleaned = rawId.trim().toUpperCase();
      if (!cleaned) continue;

      // 1. Exact case-insensitive match
      const exactMatch = exactMap.get(cleaned);
      if (exactMatch) {
        addIfNew(exactMatch);
        continue;
      }

      // 2. Substring extraction if LLM wrapped ID inside text like "TXN-8841 (48tr)"
      for (const [upperValid, canonical] of exactMap.entries()) {
        if (cleaned.includes(upperValid)) {
          addIfNew(canonical);
          break;
        }
      }

      // 3. Single-candidate prefix match (e.g. LLM wrote "LOG-AUTH-309" when only one "LOG-AUTH-*" exists)
      const prefixParts = cleaned.split('-');
      if (prefixParts.length >= 2) {
        const prefix = `${prefixParts[0]}-${prefixParts[1]}-`;
        const candidates = validEvidenceIds.filter((v) => v.toUpperCase().startsWith(prefix));
        if (candidates.length === 1 && candidates[0]) {
          addIfNew(candidates[0]);
        }
      }
    }
  }

  // 4. If LLM omitted all valid citations, backfill from deterministic top forensic evidence IDs
  if (validated.length === 0) {
    const fallbackSource = fallbackTopIds.length > 0 ? fallbackTopIds : validEvidenceIds;
    for (const id of fallbackSource) {
      const exact = exactMap.get(id.trim().toUpperCase());
      if (exact) {
        addIfNew(exact);
      }
      if (validated.length >= 4) break;
    }
  }

  return validated;
};
