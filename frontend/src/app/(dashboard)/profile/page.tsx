import { AccountSettings, type AccountTab } from "@/components/account/account-settings";

const validTabs = new Set<AccountTab>(["profile", "preferences", "privacy"]);

export default async function ProfilePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const value = (await searchParams).tab;
  const requested = Array.isArray(value) ? value[0] : value;
  const initialTab = requested && validTabs.has(requested as AccountTab) ? requested as AccountTab : "profile";
  return <AccountSettings initialTab={initialTab} />;
}
