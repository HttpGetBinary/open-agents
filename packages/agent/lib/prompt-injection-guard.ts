/**
 * Prompt injection guard for agent file-reading tools.
 */

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /you\s+are\s+now\s+(a\s+)?[\w\s]{1,40}(assistant|agent|bot)/gi,
  /system\s*:\s*you/gi,
  /<<SYS>>[\s\S]*?<\/SYS>>/gi,
  /\[INST\][\s\S]*?\[\/INST\]/gi,
  /<\|im_start\|>[\s\S]*?<\|im_end\|>/gi,
];

export interface SanitizeResult {
  content: string;
  flagged: boolean;
  matches: string[];
}

export function sanitizeFileContent(raw: string, filePath: string): SanitizeResult {
  let content = raw;
  const matches: string[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    const found = content.match(pattern);
    if (found) {
      matches.push(...found.map((m) => m.trim()));
      content = content.replace(pattern, "[REDACTED: potential prompt injection]");
    }
  }

  const flagged = matches.length > 0;
  if (flagged) {
    console.warn(`[prompt-injection-guard] Flagged ${matches.length} pattern(s) in ${filePath}`);
  }
  return { content, flagged, matches };
}
