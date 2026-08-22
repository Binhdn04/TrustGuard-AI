import { Fragment, type ReactNode } from "react";

import {
  messageTextParts,
  safeHttpHref,
} from "@/lib/security/message-links";

const INLINE_MARKDOWN_PATTERN = /\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<>"']+)|\*\*([^*\n]+)\*\*|__([^_\n]+)__|\*([^*\n]+)\*|_([^_\n]+)_|`([^`\n]+)`/giu;

interface ParagraphBlock {
  type: "paragraph";
  lines: string[];
}

interface ListBlock {
  type: "list";
  ordered: boolean;
  items: string[];
}

type MarkdownBlock = ParagraphBlock | ListBlock;

function parseBlocks(value: string): MarkdownBlock[] {
  const blocks: MarkdownBlock[] = [];
  let paragraph: string[] = [];
  let list: ListBlock | null = null;

  const flushParagraph = () => {
    if (paragraph.length) blocks.push({ type: "paragraph", lines: paragraph });
    paragraph = [];
  };
  const flushList = () => {
    if (list) blocks.push(list);
    list = null;
  };

  for (const line of value.replace(/\r\n?/gu, "\n").split("\n")) {
    if (!line.trim()) {
      flushParagraph();
      continue;
    }

    const orderedItem = line.match(/^\s*\d+[.)]\s+(.+)$/u);
    const unorderedItem = line.match(/^\s*[-*]\s+(.+)$/u);
    const item = orderedItem?.[1] ?? unorderedItem?.[1];
    if (item !== undefined) {
      flushParagraph();
      const ordered = Boolean(orderedItem);
      if (list && list.ordered !== ordered) flushList();
      if (!list) list = { type: "list", ordered, items: [] };
      list.items.push(item);
      continue;
    }

    flushList();
    paragraph.push(line);
  }

  flushParagraph();
  flushList();
  return blocks;
}

function renderPlainText(value: string, keyPrefix: string): ReactNode[] {
  return messageTextParts(value).map((part, index) =>
    part.href ? (
      <a
        key={`${keyPrefix}:link:${index}`}
        href={part.href}
        target="_blank"
        rel="noopener noreferrer nofollow"
        referrerPolicy="no-referrer"
        className="break-all font-medium underline decoration-current/50 underline-offset-2 hover:decoration-current"
        title="Mở liên kết trong tab mới; liên kết chưa được xác nhận an toàn"
      >
        {part.text}
      </a>
    ) : (
      <Fragment key={`${keyPrefix}:text:${index}`}>{part.text}</Fragment>
    ),
  );
}

function renderInline(value: string, keyPrefix: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let tokenIndex = 0;

  for (const match of value.matchAll(INLINE_MARKDOWN_PATTERN)) {
    const index = match.index;
    if (index > cursor) {
      nodes.push(...renderPlainText(value.slice(cursor, index), `${keyPrefix}:plain:${tokenIndex}`));
    }

    const key = `${keyPrefix}:token:${tokenIndex}`;
    const markdownLinkLabel = match[1];
    const markdownLinkHref = match[2];
    const bareUrl = match[3];
    const bold = match[4] ?? match[5];
    const italic = match[6] ?? match[7];
    const inlineCode = match[8];

    if (markdownLinkLabel !== undefined && markdownLinkHref !== undefined) {
      const href = safeHttpHref(markdownLinkHref);
      nodes.push(
        href ? (
          <a
            key={key}
            href={href}
            target="_blank"
            rel="noopener noreferrer nofollow"
            referrerPolicy="no-referrer"
            className="font-medium underline decoration-current/50 underline-offset-2 hover:decoration-current"
            title="Mở liên kết trong tab mới; liên kết chưa được xác nhận an toàn"
          >
            {renderInline(markdownLinkLabel, `${key}:label`)}
          </a>
        ) : (
          <Fragment key={key}>{match[0]}</Fragment>
        ),
      );
    } else if (bareUrl !== undefined) {
      nodes.push(...renderPlainText(bareUrl, key));
    } else if (bold !== undefined) {
      nodes.push(<strong key={key}>{renderInline(bold, `${key}:bold`)}</strong>);
    } else if (italic !== undefined) {
      nodes.push(<em key={key}>{renderInline(italic, `${key}:italic`)}</em>);
    } else if (inlineCode !== undefined) {
      nodes.push(
        <code key={key} className="rounded bg-foreground/10 px-1 py-0.5 font-mono text-[0.92em]">
          {inlineCode}
        </code>,
      );
    }

    cursor = index + match[0].length;
    tokenIndex += 1;
  }

  if (cursor < value.length) {
    nodes.push(...renderPlainText(value.slice(cursor), `${keyPrefix}:tail`));
  }
  return nodes;
}

/** Render the assistant's limited Markdown safely as React elements, never raw HTML. */
export function AssistantMarkdownMessage({ value }: { value: string }) {
  return (
    <div className="space-y-3 break-words">
      {parseBlocks(value).map((block, blockIndex) => {
        if (block.type === "list") {
          const List = block.ordered ? "ol" : "ul";
          return (
            <List
              key={`list:${blockIndex}`}
              className={`${block.ordered ? "list-decimal" : "list-disc"} space-y-1 pl-5`}
            >
              {block.items.map((item, itemIndex) => (
                <li key={`${itemIndex}:${item}`}>{renderInline(item, `list:${blockIndex}:${itemIndex}`)}</li>
              ))}
            </List>
          );
        }

        return (
          <p key={`paragraph:${blockIndex}`} className="whitespace-pre-wrap">
            {block.lines.map((line, lineIndex) => (
              <Fragment key={`${lineIndex}:${line}`}>
                {lineIndex > 0 && <br />}
                {renderInline(line, `paragraph:${blockIndex}:${lineIndex}`)}
              </Fragment>
            ))}
          </p>
        );
      })}
    </div>
  );
}
