'use client';

import { CheckCircle2, FileText, Scale } from 'lucide-react';

interface ParsedSummaryPoint {
  tag?: { label: string; toneClass: string };
  content: string;
}

const detectSummaryTag = (sentence: string): ParsedSummaryPoint['tag'] => {
  if (/Chủ TK|Tổng dòng tiền|Z-Score/i.test(sentence)) {
    return {
      label: 'Dòng tiền & Chủ TK',
      toneClass: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
    };
  }
  if (/cụm thiết bị|Bipartite|Smurfing|Entropy|Mule/i.test(sentence) && !/Fan-In/i.test(sentence)) {
    return {
      label: 'Cụm thiết bị & Mạng lưới',
      toneClass: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
    };
  }
  if (/Phiên đăng nhập|Liveness|FaceID|Refresh|ATO|mật khẩu/i.test(sentence)) {
    return {
      label: 'Xác thực & Phiên',
      toneClass: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
    };
  }
  if (/xung đột đồng thời|TOCTOU|Webhook|HMAC/i.test(sentence)) {
    return {
      label: 'API & Webhook',
      toneClass: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
    };
  }
  if (/Fan-In|thao túng|URL|APK|giả mạo|nạn nhân/i.test(sentence)) {
    return {
      label: 'Tín hiệu Lừa đảo',
      toneClass: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
    };
  }
  return undefined;
};

/**
 * Splits dense multi-sentence Vietnamese forensic summaries into scannable bullet points
 * without breaking decimals (49.4x, 42.000.000, 0.86) or domains (example.vn).
 */
export const splitSummaryIntoPoints = (rawText: string): ParsedSummaryPoint[] => {
  const cleaned = rawText.trim();
  if (!cleaned) return [];

  // Split on sentence-ending punctuation followed by whitespace + uppercase/Vietnamese letter,
  // or on semicolon + space when separating distinct forensic clauses.
  const sentences = cleaned
    .split(/(?<=[.!?])\s+(?=[A-ZĐÀÁẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬÈÉẺẼẸÊẾỀỂỄỆÌÍỈĨỊÒÓỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÙÚỦŨỤƯỨỪỬỮỰỲÝỶỸỴ])|;\s+/)
    .map((s) => s.trim())
    .filter(Boolean);

  if (sentences.length <= 1) {
    return [{ content: cleaned }];
  }

  return sentences.map((sentence) => ({
    tag: detectSummaryTag(sentence),
    content: sentence,
  }));
};

export const StructuredSummaryPoints = ({
  text,
  compact = false,
}: {
  text: string;
  compact?: boolean;
}) => {
  const points = splitSummaryIntoPoints(text);

  if (points.length <= 1) {
    return <p className="text-xs text-slate-100 leading-relaxed">{text}</p>;
  }

  return (
    <div className={compact ? 'space-y-2' : 'space-y-2.5'}>
      {points.map((pt, idx) => (
        <div
          key={idx}
          className={`rounded-xl bg-slate-900/75 border border-slate-800/90 ${
            compact ? 'px-2.5 py-2' : 'px-3 py-2.5'
          } space-y-1`}
        >
          {pt.tag && (
            <div>
              <span
                className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded-md border ${pt.tag.toneClass}`}
              >
                {pt.tag.label}
              </span>
            </div>
          )}
          <p className="text-xs text-slate-100 leading-relaxed">{pt.content}</p>
        </div>
      ))}
    </div>
  );
};

interface ParsedRegulationCard {
  title: string;
  statuses: string[];
  bullets: string[];
}

const KNOWN_STATUS_CODES = [
  'REQUIREMENT_MAPPED',
  'CERTIFICATION_NOT_VERIFIED',
  'LEGAL_REVIEW_REQUIRED',
  'VERIFIED',
  'NOT_APPLICABLE',
] as const;

const parseRegulatoryReference = (raw: string): ParsedRegulationCard => {
  const colonIdx = raw.indexOf(': ');
  const title = colonIdx > 0 ? raw.slice(0, colonIdx).trim() : 'Đối chiếu Pháp lý';
  const body = colonIdx > 0 ? raw.slice(colonIdx + 2).trim() : raw.trim();

  const statuses: string[] = [];
  for (const code of KNOWN_STATUS_CODES) {
    if (body.includes(code) && !statuses.includes(code)) {
      // Avoid matching VERIFIED inside CERTIFICATION_NOT_VERIFIED
      if (code === 'VERIFIED' && body.includes('CERTIFICATION_NOT_VERIFIED') && !/:\s*VERIFIED\b/.test(body)) {
        continue;
      }
      statuses.push(code);
    }
  }

  const bullets = body
    .split(/(?<=[.!?\]])\s+(?=[A-ZĐÀÁẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬÈÉẺẼẸÊẾỀỂỄỆÌÍỈĨỊÒÓỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÙÚỦŨỤƯỨỪỬỮỰỲÝỶỸỴ\[])|\s+→\s+/)
    .map((s) => s.trim())
    .filter(Boolean);

  return { title, statuses, bullets: bullets.length > 0 ? bullets : [body] };
};

export const StructuredRegulatoryCards = ({ references }: { references: string[] }) => {
  return (
    <div className="space-y-2.5">
      {references.map((rawRef, idx) => {
        const parsed = parseRegulatoryReference(rawRef);
        return (
          <div
            key={idx}
            className="rounded-xl bg-slate-900/80 border border-slate-800 p-3 space-y-2"
          >
            <div className="flex flex-wrap items-start justify-between gap-2 pb-1.5 border-b border-slate-800/80">
              <div className="flex items-start gap-2 min-w-0">
                <Scale className="w-3.5 h-3.5 text-violet-400 shrink-0 mt-0.5" />
                <span className="text-xs font-bold text-violet-200 leading-snug min-w-0 break-words [overflow-wrap:anywhere]">
                  {parsed.title}
                </span>
              </div>
              {parsed.statuses.length > 0 && (
                <div className="flex flex-wrap items-center gap-1 max-w-full min-w-0">
                  {parsed.statuses.map((st) => (
                    <span
                      key={st}
                      className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-md border ${
                        st === 'VERIFIED'
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : st === 'REQUIREMENT_MAPPED'
                            ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                            : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                      }`}
                    >
                      {st === 'VERIFIED' ? (
                        <CheckCircle2 className="w-2.5 h-2.5" />
                      ) : (
                        <FileText className="w-2.5 h-2.5" />
                      )}
                      <span>{st}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>

            <ul className="space-y-1.5 text-xs text-slate-200">
              {parsed.bullets.map((line, bIdx) => (
                <li key={bIdx} className="flex items-start gap-2 leading-relaxed">
                  <span className="text-amber-400 font-bold mt-0.5 shrink-0">•</span>
                  <span className="min-w-0 break-words [overflow-wrap:anywhere]">{line}</span>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
};
