HELM_PATH_COMMANDS_FILE="${COMMANDS_FILE:-/workspace/sessions/default/commands.jsonl}"
HELM_PATH_RUN_ID="${RUN_ID:-run}"
HELM_PATH_CMD_SEQ="${HELM_PATH_CMD_SEQ:-0}"
HELM_PATH_ACTIVE_COMMAND_ID=""
HELM_PATH_ACTIVE_STARTED_AT=""
HELM_PATH_ACTIVE_COMMAND_RAW=""
HELM_PATH_ACTIVE_CWD=""
HELM_PATH_LOGGING_READY=0

_helm_path_emit_hidden_marker() {
  local marker="$1"
  # Encode markers as terminal-title updates so they are captured by `script`
  # without being rendered as visible shell output.
  printf '\033]0;%s\007' "$marker"
}

_helm_path_write_command_record() {
  local finished_at="$1"
  local exit_code="$2"

  COMMANDS_FILE="$HELM_PATH_COMMANDS_FILE" \
  RUN_ID="$HELM_PATH_RUN_ID" \
  HELM_PATH_ACTIVE_COMMAND_ID="$HELM_PATH_ACTIVE_COMMAND_ID" \
  HELM_PATH_ACTIVE_STARTED_AT="$HELM_PATH_ACTIVE_STARTED_AT" \
  HELM_PATH_ACTIVE_COMMAND_RAW="$HELM_PATH_ACTIVE_COMMAND_RAW" \
  HELM_PATH_ACTIVE_CWD="$HELM_PATH_ACTIVE_CWD" \
  HELM_PATH_FINISHED_AT="$finished_at" \
  HELM_PATH_EXIT_CODE="$exit_code" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["COMMANDS_FILE"])
path.parent.mkdir(parents=True, exist_ok=True)
record = {
    "schema_version": 1,
    "command_id": os.environ["HELM_PATH_ACTIVE_COMMAND_ID"],
    "run_id": os.environ["RUN_ID"],
    "started_at": os.environ["HELM_PATH_ACTIVE_STARTED_AT"],
    "finished_at": os.environ["HELM_PATH_FINISHED_AT"],
    "cwd": os.environ["HELM_PATH_ACTIVE_CWD"],
    "command_raw": os.environ["HELM_PATH_ACTIVE_COMMAND_RAW"],
    "exit_code": int(os.environ["HELM_PATH_EXIT_CODE"]),
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(record) + "\n")
PY
}

_helm_path_finalize_command() {
  local exit_code="$1"
  if [ -z "$HELM_PATH_ACTIVE_COMMAND_ID" ]; then
    return
  fi

  local finished_at
  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  _helm_path_emit_hidden_marker "__HELM_PATH_CMD_END__::${HELM_PATH_ACTIVE_COMMAND_ID}::${exit_code}"
  _helm_path_write_command_record "$finished_at" "$exit_code"
  HELM_PATH_ACTIVE_COMMAND_ID=""
  HELM_PATH_ACTIVE_STARTED_AT=""
  HELM_PATH_ACTIVE_COMMAND_RAW=""
  HELM_PATH_ACTIVE_CWD=""
}

_helm_path_preexec() {
  if [ "$HELM_PATH_LOGGING_READY" != "1" ]; then
    return
  fi
  if [ -n "$HELM_PATH_ACTIVE_COMMAND_ID" ]; then
    return
  fi
  if [ "$BASH_COMMAND" = "__helm_path_precmd" ]; then
    return
  fi
  if [ "$BASH_COMMAND" = '[ ! -f "$HOME/.hushlogin" ]' ] || [ "$BASH_COMMAND" = "kali-motd" ]; then
    return
  fi
  if [ "$BASH_COMMAND" = '[ -d "$HOME/bin" ]' ] || [ "$BASH_COMMAND" = '[ -d "$HOME/.local/bin" ]' ]; then
    return
  fi
  if [ -n "${COMP_LINE:-}" ]; then
    return
  fi

  HELM_PATH_CMD_SEQ=$((HELM_PATH_CMD_SEQ + 1))
  HELM_PATH_ACTIVE_COMMAND_ID="${HELM_PATH_RUN_ID}-${HELM_PATH_CMD_SEQ}"
  HELM_PATH_ACTIVE_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  HELM_PATH_ACTIVE_COMMAND_RAW="$BASH_COMMAND"
  HELM_PATH_ACTIVE_CWD="$PWD"
  _helm_path_emit_hidden_marker "__HELM_PATH_CMD_START__::${HELM_PATH_ACTIVE_COMMAND_ID}"
}

__helm_path_precmd() {
  local exit_code="$?"
  if [ "$HELM_PATH_LOGGING_READY" != "1" ]; then
    HELM_PATH_LOGGING_READY=1
    return
  fi
  _helm_path_finalize_command "$exit_code"
}

__helm_path_on_exit() {
  local exit_code="$?"
  _helm_path_finalize_command "$exit_code"
}

if [ -f /etc/profile.d/bash_completion.sh ]; then
  . /etc/profile.d/bash_completion.sh
fi

PS1='\u@\h:\w\$ '
PROMPT_COMMAND="__helm_path_precmd"
trap '_helm_path_preexec' DEBUG
trap '__helm_path_on_exit' EXIT
