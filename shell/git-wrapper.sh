# git_checker shell integration (sourced from ~/.bashrc / ~/.zshrc).
# `git clone` itself is intercepted by the ~/.local/bin/git shim, which works in any shell.

# Review a directory you already have:  git-check <dir>
git-check() { git-safe-clone --scan "${1:-.}"; }

# Check the current directory BEFORE Claude Code loads anything from it (CLAUDE.md, .claude/,
# .mcp.json…). Unchanged directories cost one directory walk; changed files are re-scanned.
# Non-interactive uses (claude -p, --version, mcp, …) go straight through. GIT_CHECK=0 skips it.
function claude {  # `function` form: immune to an existing `alias claude=…`
  local a
  for a in "$@"; do
    case $a in
      -p|--print|-v|--version|-h|--help|mcp|config|update|doctor|install|migrate-installer|setup-token|plugin)
        command claude "$@"; return ;;
    esac
  done
  if [ "${GIT_CHECK:-1}" != 0 ] && command -v git-safe-clone >/dev/null 2>&1; then
    git-safe-clone --precheck "$PWD" || return $?
  fi
  command claude "$@"
}
