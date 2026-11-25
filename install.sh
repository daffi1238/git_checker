#!/usr/bin/env bash
# Install git_checker (idempotent).
#   ./install.sh             git shim + git-safe-clone + shell integration (git-check, claude pre-launch check)
#   ./install.sh --tools     also install semgrep, guarddog (uv/pipx) and osv-scanner (go)
#   ./install.sh --guard     also register the protect_secrets PreToolUse hook in ~/.claude/settings.json
#   ./install.sh --sentinel  also register the sentinel UserPromptSubmit hook (checks the directory of every session)
#   ./install.sh --all       all of the above
#   ./install.sh --uninstall
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
BIN="$HOME/.local/bin"
SETTINGS="$HOME/.claude/settings.json"
GUARD_CMD="/usr/bin/env python3 -I $ROOT/guard/protect_secrets.py"
SENTINEL_CMD="/usr/bin/env python3 -I $ROOT/gitcheck.py sentinel hook"
TOOLS="" GUARD="" SENTINEL="" UNINSTALL=""
for a in "$@"; do
  case $a in
    --tools) TOOLS=1 ;;
    --guard) GUARD=1 ;;
    --sentinel) SENTINEL=1 ;;
    --all) TOOLS=1 GUARD=1 SENTINEL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

backup_settings() { cp -p "$SETTINGS" "$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"; }

add_hook() {  # add_hook <event> <matcher|""> <command> <timeout> <marker>
  local ev=$1 matcher=$2 cmd=$3 timeout=$4 marker=$5
  if jq -e --arg ev "$ev" --arg m "$marker" '[.hooks[$ev][]?.hooks[]?.command] | any(contains($m))' "$SETTINGS" >/dev/null; then
    echo "$ev hook ($marker) already registered"
    return
  fi
  backup_settings
  jq --arg ev "$ev" --arg mt "$matcher" --arg c "$cmd" --argjson t "$timeout" \
    '.hooks[$ev] = ((.hooks[$ev] // []) + [({"hooks":[{"type":"command","command":$c,"timeout":$t}]} + (if $mt == "" then {} else {"matcher":$mt} end))])' \
    "$SETTINGS" >"$SETTINGS.tmp" && jq -e . "$SETTINGS.tmp" >/dev/null && mv "$SETTINGS.tmp" "$SETTINGS"
  echo "$ev hook ($marker) registered in $SETTINGS (backup created)"
}

if [[ -n $UNINSTALL ]]; then
  for f in git git-safe-clone; do
    [[ -L $BIN/$f && $(readlink -f "$BIN/$f") == "$ROOT"/bin/* ]] && rm -f "$BIN/$f" && echo "removed $BIN/$f"
  done
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f $rc ]] && sed -i.bak '/# git_checker$/d' "$rc" && echo "cleaned $rc"
  done
  if [[ -f $SETTINGS ]] && command -v jq >/dev/null; then
    backup_settings
    jq 'if .hooks then .hooks |= with_entries(.value |= map(select(([.hooks[]?.command] | any(contains("protect_secrets.py") or contains("gitcheck.py sentinel"))) | not))) else . end' \
      "$SETTINGS" >"$SETTINGS.tmp" && mv "$SETTINGS.tmp" "$SETTINGS" && echo "hooks removed from $SETTINGS"
  fi
  exit 0
fi

# ---------- requirements
command -v python3 >/dev/null || { echo "python3 (>=3.10) is missing"; exit 1; }
command -v jq >/dev/null || echo "WARNING: jq is missing (required): sudo apt install jq"
command -v claude >/dev/null || echo "WARNING: claude CLI is missing: no phase 3 (LLM), the minimum verdict will be WARN"

# ---------- binaries
mkdir -p "$BIN"
chmod +x "$ROOT/bin/git-safe-clone" "$ROOT/bin/git-shim" "$ROOT/gitcheck.py" "$ROOT/guard/protect_secrets.py"
ln -sf "$ROOT/bin/git-safe-clone" "$BIN/git-safe-clone"
ln -sf "$ROOT/bin/git-shim" "$BIN/git"     # intercepts `git clone`
echo "installed: $BIN/git (shim) and $BIN/git-safe-clone"
case ":$PATH:" in
  *":$BIN:"*) [[ $(type -P git) == "$BIN/git" ]] || echo "WARNING: $BIN is not ahead of /usr/bin in PATH; the shim will not act" ;;
  *) echo "WARNING: $BIN is not in PATH. Add to your ~/.bashrc:  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

LINE="[ -f \"$ROOT/shell/git-wrapper.sh\" ] && . \"$ROOT/shell/git-wrapper.sh\"  # git_checker"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [[ -f $rc ]] || continue
  grep -qF "# git_checker" "$rc" || { printf '\n%s\n' "$LINE" >>"$rc"; echo "added shell integration (git-check, claude pre-launch check) to $rc"; }
done

# this repository contains attack patterns on purpose (they are the detection rules): never flag it
python3 -I "$ROOT/gitcheck.py" sentinel trust "$ROOT" >/dev/null && echo "trusted for the sentinel: $ROOT"

# ---------- external scanners (optional)
if [[ -n $TOOLS ]]; then
  if command -v uv >/dev/null; then
    uv tool install semgrep || true
    uv tool install guarddog || true
  elif command -v pipx >/dev/null; then
    pipx install semgrep || true
    pipx install guarddog || true
  else
    echo "WARNING: neither uv nor pipx: not installing semgrep/guarddog (curl -LsSf https://astral.sh/uv/install.sh | sh)"
  fi
  if command -v go >/dev/null; then
    go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest || true
  else
    echo "WARNING: without go osv-scanner is not installed (or download the binary from github.com/google/osv-scanner/releases)"
  fi
fi

# ---------- Claude Code hooks
if [[ -n $GUARD || -n $SENTINEL ]]; then
  command -v jq >/dev/null || { echo "--guard/--sentinel need jq"; exit 1; }
  mkdir -p "$(dirname "$SETTINGS")"
  [[ -f $SETTINGS ]] || echo '{}' >"$SETTINGS"
  [[ -n $GUARD ]] && add_hook PreToolUse "Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep" "$GUARD_CMD" 10 "protect_secrets.py"
  [[ -n $SENTINEL ]] && add_hook UserPromptSubmit "" "$SENTINEL_CMD" 120 "gitcheck.py sentinel"
fi

# ---------- status
echo
for t in jq claude semgrep guarddog osv-scanner; do
  if command -v "$t" >/dev/null || [[ -x $HOME/go/bin/$t ]]; then echo "  ✔ $t"; else echo "  ✘ $t"; fi
done
echo "Done. Open a new terminal (or: hash -r; source ~/.bashrc) and try: git clone https://github.com/sindresorhus/slugify"
