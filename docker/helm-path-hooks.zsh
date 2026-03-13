autoload -Uz add-zsh-hook

typeset -g HELM_PATH_CMD_SEQ=${HELM_PATH_CMD_SEQ:-0}
typeset -g HELM_PATH_ACTIVE_COMMAND_ID=""
typeset -g HELM_PATH_ACTIVE_STARTED_AT=""
typeset -g HELM_PATH_ACTIVE_COMMAND_RAW=""
typeset -g HELM_PATH_ACTIVE_CWD=""

_helm_path_write_command_record() {
  local finished_at="$1"
  local exit_code="$2"

  COMMANDS_FILE="${COMMANDS_FILE:-/workspace/sessions/default/commands.jsonl}" \
  RUN_ID="${RUN_ID:-run}" \
  HELM_PATH_ACTIVE_COMMAND_ID="${HELM_PATH_ACTIVE_COMMAND_ID}" \
  HELM_PATH_ACTIVE_STARTED_AT="${HELM_PATH_ACTIVE_STARTED_AT}" \
  HELM_PATH_ACTIVE_COMMAND_RAW="${HELM_PATH_ACTIVE_COMMAND_RAW}" \
  HELM_PATH_ACTIVE_CWD="${HELM_PATH_ACTIVE_CWD}" \
  HELM_PATH_FINISHED_AT="${finished_at}" \
  HELM_PATH_EXIT_CODE="${exit_code}" \
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
  if [[ -z "${HELM_PATH_ACTIVE_COMMAND_ID:-}" ]]; then
    return
  fi

  local finished_at
  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  print -r -- "__HELM_PATH_CMD_END__::${HELM_PATH_ACTIVE_COMMAND_ID}::${exit_code}"
  _helm_path_write_command_record "${finished_at}" "${exit_code}"
  HELM_PATH_ACTIVE_COMMAND_ID=""
  HELM_PATH_ACTIVE_STARTED_AT=""
  HELM_PATH_ACTIVE_COMMAND_RAW=""
  HELM_PATH_ACTIVE_CWD=""
}

_helm_path_preexec() {
  local command="$1"
  HELM_PATH_CMD_SEQ=$((HELM_PATH_CMD_SEQ + 1))
  HELM_PATH_ACTIVE_COMMAND_ID="${RUN_ID:-run}-${HELM_PATH_CMD_SEQ}"
  HELM_PATH_ACTIVE_STARTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  HELM_PATH_ACTIVE_COMMAND_RAW="${command}"
  HELM_PATH_ACTIVE_CWD="${PWD}"
  print -r -- "__HELM_PATH_CMD_START__::${HELM_PATH_ACTIVE_COMMAND_ID}"
}

_helm_path_precmd() {
  local exit_code="$?"
  _helm_path_finalize_command "${exit_code}"
}

_helm_path_zshexit() {
  local exit_code="$?"
  _helm_path_finalize_command "${exit_code}"
}

add-zsh-hook preexec _helm_path_preexec
add-zsh-hook precmd _helm_path_precmd
add-zsh-hook zshexit _helm_path_zshexit
