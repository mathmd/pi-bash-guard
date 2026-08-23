declare module "shell-quote" {
  export type ParseToken = string | { op: string } | { comment: string } | { pattern: string };
  export function parse(command: string, env?: Record<string, string> | ((key: string) => string | object | undefined)): ParseToken[];
  export function quote(args: string[]): string;
}
