export interface RuntimeSenderIdentity {
  id?: string;
  url?: string;
}

export function isTrustedSidePanelSender(
  sender: RuntimeSenderIdentity,
  runtimeId: string,
  sidePanelUrl: string,
): boolean {
  return sender.id === runtimeId && sender.url === sidePanelUrl;
}

export function isTrustedExtensionSender(sender: RuntimeSenderIdentity, runtimeId: string): boolean {
  return sender.id === runtimeId;
}
