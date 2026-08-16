import type { CommandCategory } from "./types.ts";

/** Shell grammar words that are not executable commands. */
export const SHELL_PREFIX_WORDS = new Set([
  "if", "then", "elif", "else", "do", "{", "!", "time", "coproc",
]);

export const SHELL_HEADER_WORDS = new Set(["for", "select", "while", "until", "case", "function"]);
export const SHELL_CLOSING_WORDS = new Set(["fi", "done", "esac", "}"]);

const ALLOW = new Set([
  // Shell state, introspection, and inert utilities.
  ":", "true", "false", "set", "shopt", "export", "readonly", "unset", "declare", "typeset", "local",
  "umask", "ulimit", "alias", "unalias", "hash", "help", "history", "jobs", "disown", "wait", "shift",
  "return", "break", "continue", "printf", "echo", "pwd", "basename", "dirname", "yes", "sleep", "seq",
  "clear", "tput", "stty", "tty", "logname", "whoami", "id", "groups", "who", "w", "uptime", "date",
  "cal", "nproc", "arch", "uname", "hostname", "hostid", "getconf", "locale", "printenv", "env",
]);

const READ = new Set([
  // Filesystem and text inspection.
  "test", "[", "ls", "stat", "file", "wc", "cat", "tac", "head", "tail", "less", "more", "od", "hexdump", "xxd",
  "strings", "cksum", "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum",
  "grep", "egrep", "fgrep", "rg", "find", "fd", "locate", "which", "whereis", "type", "readlink",
  "realpath", "du", "df", "mountpoint", "lsblk", "lscpu", "lsmem", "lspci", "lsusb", "free", "vmstat",
  "iostat", "sar", "ps", "pstree", "pgrep", "lsof", "top", "htop", "dmesg", "journalctl",
  "sort", "uniq", "cut", "paste", "join", "comm", "tr", "column", "fold", "fmt", "nl", "rev", "pr",
  "expand", "unexpand", "diff", "diff3", "cmp", "sdiff", "jq", "yq",
  "sed", "bc", "dc", "expr", "factor", "numfmt", "shuf",
  "tree", "namei", "getfacl", "getfattr", "lsattr", "readelf", "objdump", "nm", "size", "ldd",
  "git", "hg", "svn",
]);

const CREATE = new Set(["mkdir", "mktemp", "touch", "mkfifo", "mknod", "split", "csplit"]);
const EDIT = new Set([
  "chmod", "chown", "chgrp", "setfacl", "setfattr", "chattr", "truncate", "patch", "ed", "ex",
  "cp", "install", "mv", "ln", "tee",
]);
const DELETE = new Set(["rm", "rmdir", "unlink"]);
const EXECUTE = new Set([
  "source", ".", "eval", "xargs", "parallel", "make", "gmake", "ninja", "just", "task",
  "awk", "mawk", "gawk", "nawk", "strace",
]);
const REMOTE = new Set([
  "curl", "wget", "ftp", "sftp", "scp", "rsync", "ssh", "mosh", "nc", "ncat", "socat",
  "kubectl", "helm", "terraform", "tofu", "ansible", "ansible-playbook", "aws", "gcloud", "az", "doctl",
  "gh", "glab", "npm", "npx", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "gem",
  "go", "dotnet", "docker", "podman", "systemctl", "service", "loginctl", "nmcli", "ip", "iptables",
  "nft", "ufw", "mount", "umount", "swapon", "swapoff", "crontab", "at", "kill", "pkill", "killall", "fuser",
  "nix", "nix-shell", "nix-build", "nix-env", "nix-store", "nix-instantiate",
]);
const DENY = new Set(["mkfs", "wipefs", "shred", "fdisk", "gdisk", "sgdisk", "parted"]);

export function builtinCommandCategory(name: string): CommandCategory | undefined {
  if (ALLOW.has(name)) return "allow";
  if (READ.has(name)) return "read";
  if (CREATE.has(name)) return "create";
  if (EDIT.has(name)) return "edit";
  if (DELETE.has(name)) return "delete";
  if (EXECUTE.has(name)) return "execute";
  if (REMOTE.has(name)) return "remote";
  if (DENY.has(name) || name.startsWith("mkfs.")) return "deny";
  return undefined;
}
