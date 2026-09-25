export type SourcePathOperationKind = "read" | "write" | "delete";

export interface SourcePathOperation {
  kind: SourcePathOperationKind;
  /** Undefined when the source expression cannot be resolved without execution. */
  path?: string;
  source: string;
}

export type SourceExecution =
  | { kind: "shell"; command?: string; source: string; cwd?: string; dynamicCwd?: boolean }
  | { kind: "argv"; executable?: string; args?: Array<string | undefined>; source: string; cwd?: string; dynamicCwd?: boolean }
  | { kind: "module"; path?: string; source: string; cwd?: string; dynamicCwd?: boolean; sourceRelative?: boolean; language?: "javascript" | "python" | "julia" };

export interface SourceScreening {
  paths: SourcePathOperation[];
  executions: SourceExecution[];
  parseError?: string;
}
