import { randomBytes } from "node:crypto";

const HEREDOC_MARKER_PREFIX = "__bash_guard_heredoc_";
const MAX_HEREDOCS = 64;

export interface ShellHeredoc {
  marker: string;
  source: string;
  originalOperator: string;
  quotedDelimiter: boolean;
}

export interface ShellHeredocExtraction {
  command: string;
  heredocs: Map<string, ShellHeredoc>;
  error?: string;
}

interface Declaration {
  marker: string;
  delimiter: string;
  stripTabs: boolean;
  originalOperator: string;
  quotedDelimiter: boolean;
}

function delimiterValue(raw: string): { value: string; quoted: boolean } | undefined {
  let value = "";
  let quote: "'" | '"' | undefined;
  let quoted = false;
  for (let index = 0; index < raw.length; index++) {
    const character = raw[index]!;
    if (quote) {
      if (character === quote) { quote = undefined; quoted = true; }
      else if (character === "\\" && quote === '"' && index + 1 < raw.length) {
        value += raw[++index]!;
        quoted = true;
      } else value += character;
      continue;
    }
    if (character === "'" || character === '"') { quote = character; quoted = true; continue; }
    if (character === "\\" && index + 1 < raw.length) {
      value += raw[++index]!;
      quoted = true;
      continue;
    }
    value += character;
  }
  return quote || !value ? undefined : { value, quoted };
}

function declarationsInLine(line: string, startNumber: number, nonce: string): { line: string; declarations: Declaration[]; error?: string } {
  const declarations: Declaration[] = [];
  let output = "";
  let quote: "'" | '"' | "`" | undefined;
  let escaped = false;
  let comment = false;
  let arithmeticParentheses = 0;
  let cursor = 0;

  for (let index = 0; index < line.length; index++) {
    const character = line[index]!;
    if (comment) break;
    if (escaped) { escaped = false; continue; }
    if (character === "\\" && quote !== "'") { escaped = true; continue; }
    if (arithmeticParentheses > 0) {
      if (character === "(") arithmeticParentheses++;
      else if (character === ")") arithmeticParentheses--;
      continue;
    }
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"' || character === "`") { quote = character; continue; }
    if (character === "#" && (index === 0 || /[\s;|&()]/.test(line[index - 1]!))) { comment = true; break; }
    if (line.startsWith("$((", index)) { arithmeticParentheses = 2; index += 2; continue; }
    if (line.startsWith("((", index) && (index === 0 || /[\s;|&()]/.test(line[index - 1]!))) {
      arithmeticParentheses = 2;
      index++;
      continue;
    }
    if (character !== "<" || line[index + 1] !== "<" || line[index - 1] === "<" || line[index + 2] === "<") continue;

    let operatorStart = index;
    while (operatorStart > cursor && /\d/.test(line[operatorStart - 1]!)) operatorStart--;
    if (operatorStart > cursor && /[A-Za-z_]/.test(line[operatorStart - 1]!)) operatorStart = index;
    let wordStart = index + 2;
    let stripTabs = false;
    if (line[wordStart] === "-") { stripTabs = true; wordStart++; }
    while (wordStart < line.length && /[ \t]/.test(line[wordStart]!)) wordStart++;
    if (wordStart >= line.length || /[;|&()<>{}\n\r]/.test(line[wordStart]!)) {
      return { line, declarations, error: "Shell heredoc delimiter could not be resolved safely" };
    }

    let wordEnd = wordStart;
    let wordQuote: "'" | '"' | undefined;
    let wordEscaped = false;
    while (wordEnd < line.length) {
      const current = line[wordEnd]!;
      if (wordEscaped) { wordEscaped = false; wordEnd++; continue; }
      if (current === "\\" && wordQuote !== "'") { wordEscaped = true; wordEnd++; continue; }
      if (wordQuote) {
        if (current === wordQuote) wordQuote = undefined;
        wordEnd++;
        continue;
      }
      if (current === "'" || current === '"') { wordQuote = current; wordEnd++; continue; }
      if (/\s/.test(current) || /[;|&()<>]/.test(current)) break;
      wordEnd++;
    }
    const rawDelimiter = line.slice(wordStart, wordEnd);
    const delimiter = delimiterValue(rawDelimiter);
    if (!delimiter) return { line, declarations, error: "Shell heredoc delimiter could not be resolved safely" };
    if (startNumber + declarations.length >= MAX_HEREDOCS) {
      return { line, declarations, error: `Shell command contains more than ${MAX_HEREDOCS} heredocs` };
    }

    const marker = `${HEREDOC_MARKER_PREFIX}${nonce}_${startNumber + declarations.length}__`;
    output += `${line.slice(cursor, operatorStart)} ${marker} `;
    const originalOperator = line.slice(operatorStart, wordEnd);
    declarations.push({
      marker,
      delimiter: delimiter.value,
      stripTabs,
      originalOperator,
      quotedDelimiter: delimiter.quoted,
    });
    cursor = wordEnd;
    index = wordEnd - 1;
  }

  output += line.slice(cursor);
  return { line: output, declarations };
}

function lineWithoutEnding(value: string): string {
  return value.replace(/\r?\n$/, "");
}

function continuedLine(value: string): boolean {
  const line = lineWithoutEnding(value);
  let slashes = 0;
  for (let index = line.length - 1; index >= 0 && line[index] === "\\"; index--) slashes++;
  return slashes % 2 === 1;
}

/**
 * Remove heredoc bodies from shell syntax while retaining a marker on the
 * command that consumes each body. This prevents body text from being parsed
 * as independent shell commands.
 */
export function extractShellHeredocs(source: string): ShellHeredocExtraction {
  const heredocs = new Map<string, ShellHeredoc>();
  const output: string[] = [];
  let offset = 0;
  let pending: Declaration[] = [];
  const nonce = randomBytes(12).toString("hex");

  while (offset < source.length) {
    const newline = source.indexOf("\n", offset);
    const end = newline < 0 ? source.length : newline + 1;
    const physicalLine = source.slice(offset, end);
    const found = declarationsInLine(physicalLine, heredocs.size + pending.length, nonce);
    if (found.error) return { command: output.join("") + source.slice(offset), heredocs, error: found.error };
    output.push(found.line);
    pending.push(...found.declarations);
    offset = end;

    if (continuedLine(physicalLine)) continue;
    for (const declaration of pending) {
      const body: string[] = [];
      let closed = false;
      while (offset < source.length) {
        const bodyNewline = source.indexOf("\n", offset);
        const bodyEnd = bodyNewline < 0 ? source.length : bodyNewline + 1;
        const rawLine = source.slice(offset, bodyEnd);
        const comparison = lineWithoutEnding(rawLine);
        const comparable = declaration.stripTabs ? comparison.replace(/^\t+/, "") : comparison;
        offset = bodyEnd;
        if (comparable === declaration.delimiter) { closed = true; break; }
        body.push(declaration.stripTabs ? rawLine.replace(/^\t+/, "") : rawLine);
      }
      if (!closed) {
        return { command: output.join(""), heredocs, error: `Shell heredoc delimiter was not found: ${declaration.delimiter}` };
      }
      heredocs.set(declaration.marker, {
        marker: declaration.marker,
        source: body.join(""),
        originalOperator: declaration.originalOperator,
        quotedDelimiter: declaration.quotedDelimiter,
      });
    }
    pending = [];
  }

  if (pending.length) {
    return { command: output.join(""), heredocs, error: `Shell heredoc delimiter was not found: ${pending[0]!.delimiter}` };
  }
  return { command: output.join(""), heredocs };
}

export function isHeredocMarker(value: string): boolean {
  return value.startsWith(HEREDOC_MARKER_PREFIX) && value.endsWith("__");
}

export function displayHeredocOperators(command: string, heredocs: Map<string, ShellHeredoc>): string {
  let display = command;
  for (const heredoc of heredocs.values()) display = display.replaceAll(heredoc.marker, heredoc.originalOperator);
  return display;
}

export function heredocHasDynamicExpansion(heredoc: ShellHeredoc): boolean {
  if (heredoc.quotedDelimiter) return false;
  let escaped = false;
  for (const character of heredoc.source) {
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (character === "$" || character === "`") return true;
  }
  return false;
}
