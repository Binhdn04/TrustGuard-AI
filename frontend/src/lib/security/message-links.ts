const BLOCK_TAGS = new Set([
  "ADDRESS",
  "ARTICLE",
  "BLOCKQUOTE",
  "DIV",
  "H1",
  "H2",
  "H3",
  "H4",
  "H5",
  "H6",
  "LI",
  "P",
  "SECTION",
]);

const IGNORED_TAGS = new Set(["HEAD", "SCRIPT", "STYLE"]);
const URL_PATTERN = /https?:\/\/[^\s<>"']+/giu;
const TRAILING_PUNCTUATION = /[.,!?;:)\]}]+$/u;

export interface MessageTextPart {
  text: string;
  href?: string;
}

export function safeHttpHref(value: string): string | null {
  const candidate = value.trim();
  try {
    const parsed = new URL(candidate);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? candidate : null;
  } catch {
    return null;
  }
}

function serializeClipboardNode(node: Node, foundLink: { current: boolean }): string {
  if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? "";
  if (!(node instanceof HTMLElement) || IGNORED_TAGS.has(node.tagName)) return "";
  if (node.tagName === "BR") return "\n";

  const content = Array.from(node.childNodes)
    .map((child) => serializeClipboardNode(child, foundLink))
    .join("");
  if (node.tagName === "A") {
    const href = safeHttpHref(node.getAttribute("href") ?? "");
    if (!href) return content;
    foundLink.current = true;
    const label = content.trim();
    return !label || label.includes(href) ? (label || href) : `${label} (${href})`;
  }
  return BLOCK_TAGS.has(node.tagName) ? `${content}\n` : content;
}

/** Preserve HTTP(S) hrefs that a textarea would otherwise discard from rich clipboard HTML. */
export function richClipboardTextWithLinks(html: string): string | null {
  if (!html.trim() || typeof DOMParser === "undefined") return null;
  const document = new DOMParser().parseFromString(html, "text/html");
  const foundLink = { current: false };
  const value = serializeClipboardNode(document.body, foundLink)
    .replace(/\u00a0/gu, " ")
    .replace(/[ \t]+\n/gu, "\n")
    .replace(/\n{3,}/gu, "\n\n")
    .trim();
  return foundLink.current && value ? value : null;
}

/** Split display text into escaped text and validated HTTP(S) link parts. */
export function messageTextParts(value: string): MessageTextPart[] {
  const parts: MessageTextPart[] = [];
  let cursor = 0;
  for (const match of value.matchAll(URL_PATTERN)) {
    const index = match.index;
    const raw = match[0];
    const href = raw.replace(TRAILING_PUNCTUATION, "");
    if (!safeHttpHref(href)) continue;
    if (index > cursor) parts.push({ text: value.slice(cursor, index) });
    parts.push({ text: href, href });
    if (href.length < raw.length) parts.push({ text: raw.slice(href.length) });
    cursor = index + raw.length;
  }
  if (cursor < value.length) parts.push({ text: value.slice(cursor) });
  return parts.length ? parts : [{ text: value }];
}
