import { Fragment } from "react";

import { messageTextParts } from "@/lib/security/message-links";

export function LinkedMessage({ value }: { value: string }) {
  return (
    <p className="whitespace-pre-wrap break-words">
      {messageTextParts(value).map((part, index) => (
        <Fragment key={`${index}:${part.text}`}>
          {part.href ? (
            <a
              href={part.href}
              target="_blank"
              rel="noopener noreferrer nofollow"
              referrerPolicy="no-referrer"
              className="break-all font-medium underline decoration-current/50 underline-offset-2 hover:decoration-current"
              title="Mở liên kết trong tab mới; liên kết chưa được xác nhận an toàn"
            >
              {part.text}
            </a>
          ) : part.text}
        </Fragment>
      ))}
    </p>
  );
}
