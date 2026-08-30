export type Decision = "allow" | "ask" | "deny";
export type OwnershipLevel = "read" | "edit" | "full";
export type CommandCategory = "allow" | "read" | "create" | "edit" | "delete" | "execute" | "remote" | "deny";
export type AccessKind = "read" | "edit" | "delete" | "execute" | "remote" | "unknown";

export interface OwnershipPatterns {
  edit: string[];
  full: string[];
}

export interface CommandRule {
  name: string;
  category: CommandCategory;
  note?: string;
}

export interface PolicyFile {
  version: 2;
  ownership: OwnershipPatterns;
  secrets: string[];
  commands: CommandRule[];
  tools: { read: string[] };
}

export interface PathAccess {
  path: string;
  kind: AccessKind;
  source?: string;
  literal?: boolean;
  existed?: boolean;
}

export interface Analysis {
  decision: Decision;
  reasons: string[];
  accesses: PathAccess[];
  creationCandidates: string[];
  trashablePaths: string[];
  ownershipCandidates: Array<{ path: string; required: "edit" | "full" }>;
}

export interface PolicyIssue {
  path: string;
  message: string;
}

export const EMPTY_ANALYSIS: Analysis = {
  decision: "allow",
  reasons: [],
  accesses: [],
  creationCandidates: [],
  trashablePaths: [],
  ownershipCandidates: [],
};

export function strongest(a: Decision, b: Decision): Decision {
  const rank: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };
  return rank[a] >= rank[b] ? a : b;
}
