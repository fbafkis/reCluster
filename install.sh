#!/usr/bin/env sh
# MIT License
#
# Copyright (c) 2022-2022 Carlo Corradini
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Current directory
# shellcheck disable=SC1007
DIRNAME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Load commons
# shellcheck source=scripts/__commons.sh
# . "$DIRNAME/scripts/__commons.sh"
# MIT License
#
# Copyright (c) 2022-2022 Carlo Corradini
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Fail on error
set -o errexit
# Disable wildcard character expansion
set -o noglob

# ================
# GLOBALS
# ================
# Downloader
DOWNLOADER=
# Return value
RETVAL=

# ================
# PARSE ARGUMENTS
# ================
# Assert argument has a value
# @param $1 Argument name
# @param $2 Argument value
parse_args_assert_value() {
  [ -n "$2" ] || FATAL "Argument '$1' requires a non-empty value"
}
# Assert argument value is a non negative integer (>= 0)
# @param $1 Argument name
# @param $2 Argument value
parse_args_assert_non_negative_integer() {
  { is_integer "$2" && [ "$2" -ge 0 ]; } || FATAL "Value '$2' of argument '$1' is not a non negative number"
}
# Assert argument value is a positive integer (> 0)
# @param $1 Argument name
# @param $2 Argument value
parse_args_assert_positive_integer() {
  { is_integer "$2" && [ "$2" -gt 0 ]; } || FATAL "Value '$2' of argument '$1' is not a positive number"
}
# Parse command line arguments
# @param $@ Arguments
parse_args_commons() {
  # Number of shift
  _shifts=1

  # Parse
  case $1 in
  --disable-color)
    # Disable color
    LOG_COLOR_ENABLE=false
    ;;
  --disable-spinner)
    # Disable spinner
    SPINNER_ENABLE=false
    ;;
  --log-level)
    # Log level
    parse_args_assert_value "$@"

    case $2 in
    fatal) LOG_LEVEL=$LOG_LEVEL_FATAL ;;
    error) LOG_LEVEL=$LOG_LEVEL_ERROR ;;
    warn) LOG_LEVEL=$LOG_LEVEL_WARN ;;
    info) LOG_LEVEL=$LOG_LEVEL_INFO ;;
    debug) LOG_LEVEL=$LOG_LEVEL_DEBUG ;;
    *) FATAL "Value '$2' of argument '$1' is invalid" ;;
    esac
    _shifts=2
    ;;
  --spinner)
    # Spinner
    parse_args_assert_value "$@"

    case $2 in
    dots) SPINNER_SYMBOLS=$SPINNER_SYMBOLS_DOTS ;;
    grayscale) SPINNER_SYMBOLS=$SPINNER_SYMBOLS_GRAYSCALE ;;
    propeller) SPINNER_SYMBOLS=$SPINNER_SYMBOLS_PROPELLER ;;
    *) FATAL "Value '$2' of argument '$1' is invalid" ;;
    esac
    _shifts=2
    ;;
  -*)
    # Unknown argument
    WARN "Unknown argument '$1' is ignored"
    ;;
  *)
    # No argument
    WARN "Skipping argument '$1'"
    ;;
  esac

  # Return
  RETVAL=$_shifts
}

# ================
# LOGGER
# ================
# Fatal log level. Cause exit failure
LOG_LEVEL_FATAL=100
# Error log level
LOG_LEVEL_ERROR=200
# Warning log level
LOG_LEVEL_WARN=300
# Informational log level
LOG_LEVEL_INFO=500
# Debug log level
LOG_LEVEL_DEBUG=600
# Log level
LOG_LEVEL=$LOG_LEVEL_INFO
# Log color flag
LOG_COLOR_ENABLE=true

# Convert log level to equivalent name
# @param $1 Log level
to_log_level_name() {
  _log_level=${1:-LOG_LEVEL}
  _log_level_name=

  case $_log_level in
  "$LOG_LEVEL_FATAL") _log_level_name=fatal ;;
  "$LOG_LEVEL_ERROR") _log_level_name=error ;;
  "$LOG_LEVEL_WARN") _log_level_name=warn ;;
  "$LOG_LEVEL_INFO") _log_level_name=info ;;
  "$LOG_LEVEL_DEBUG") _log_level_name=debug ;;
  *) FATAL "Unknown log level '$_log_level'" ;;
  esac

  printf '%s\n' "$_log_level_name"
}

# Check if log level is enabled
# @param $1 Log level
is_log_level_enabled() {
  [ "$1" -le "$LOG_LEVEL" ]

  return $?
}

# Print log message
# @param $1 Log level
# @param $2 Message
_log_print_message() {
  _log_level=${1:-LOG_LEVEL_FATAL}
  shift
  _log_level_name=
  _log_message=${*:-}
  _log_prefix=
  _log_suffix="\033[0m"

  # Check log level
  is_log_level_enabled "$_log_level" || return 0

  case $_log_level in
  "$LOG_LEVEL_FATAL")
    _log_level_name=FATAL
    _log_prefix="\033[41;37m"
    ;;
  "$LOG_LEVEL_ERROR")
    _log_level_name=ERROR
    _log_prefix="\033[1;31m"
    ;;
  "$LOG_LEVEL_WARN")
    _log_level_name=WARN
    _log_prefix="\033[1;33m"
    ;;
  "$LOG_LEVEL_INFO")
    _log_level_name=INFO
    _log_prefix="\033[37m"
    ;;
  "$LOG_LEVEL_DEBUG")
    _log_level_name=DEBUG
    _log_prefix="\033[1;34m"
    ;;
  esac

  # Check color flag
  if [ "$LOG_COLOR_ENABLE" = false ]; then
    _log_prefix=
    _log_suffix=
  fi

  # Log
  printf '%b[%-5s] %b%b\n' "$_log_prefix" "$_log_level_name" "$_log_message" "$_log_suffix"
}

# Fatal log message
# @param $1 Message
FATAL() {
  _log_print_message "$LOG_LEVEL_FATAL" "$1" >&2
  exit 1
}
# Error log message
# @param $1 Message
ERROR() { _log_print_message "$LOG_LEVEL_ERROR" "$1" >&2; }
# Warning log message
# @param $1 Message
WARN() { _log_print_message "$LOG_LEVEL_WARN" "$1" >&2; }
# Informational log message
# @param $1 Message
INFO() { _log_print_message "$LOG_LEVEL_INFO" "$1"; }
# Debug log message
# @param $1 Message
# @param $2 JSON value
DEBUG() {
  _log_print_message "$LOG_LEVEL_DEBUG" "$1"
  if [ -n "$2" ] && is_log_level_enabled "$LOG_LEVEL_DEBUG"; then
    printf '%s\n' "$2" | jq '.'
  fi
}

# ================
# SPINNER
# ================
# Spinner PID
SPINNER_PID=
# Spinner symbol time in seconds
SPINNER_TIME=.1
# Spinner symbols dots
SPINNER_SYMBOLS_DOTS="⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏"
# Spinner symbols grayscale
SPINNER_SYMBOLS_GRAYSCALE="░░░░░░░ ▒░░░░░░ ▒▒░░░░░ ▒▒▒░░░░ ▒▒▒▒░░░ ▒▒▒▒▒░░ ▒▒▒▒▒▒░ ▒▒▒▒▒▒▒ ░▒▒▒▒▒▒ ░░▒▒▒▒▒ ░░░▒▒▒▒ ░░░░▒▒▒ ░░░░░▒▒ ░░░░░░▒"
# Spinner symbols propeller
SPINNER_SYMBOLS_PROPELLER="/ - \\ |"
# Spinner symbols
SPINNER_SYMBOLS=$SPINNER_SYMBOLS_PROPELLER
# Spinner flag
SPINNER_ENABLE=true

# Spinner logic
_spinner() {
  # Termination flag
  _terminate=false
  # Termination signal
  trap '_terminate=true' USR1
  # Message
  _spinner_message=${1:-""}

  while :; do
    # Cursor invisible
    tput civis

    for s in $SPINNER_SYMBOLS; do
      # Save cursor position
      tput sc
      # Symbol and message
      printf "%s %s" "$s" "$_spinner_message"
      # Restore cursor position
      tput rc

      # Terminate
      if [ "$_terminate" = true ]; then
        # Clear line from position to end
        tput el
        break 2
      fi

      # Animation time
      sleep "$SPINNER_TIME"

      # Check parent still alive
      # Parent PID
      _spinner_ppid=$(ps -p "$$" -o ppid=)
      if [ -n "$_spinner_ppid" ]; then
        # shellcheck disable=SC2086
        _spinner_parent_up=$(ps --no-headers $_spinner_ppid)
        if [ -z "$_spinner_parent_up" ]; then break 2; fi
      fi
    done
  done

  # Cursor normal
  tput cnorm
  return 0
}

# Start spinner
# @param $1 Message
# shellcheck disable=SC2120
spinner_start() {
  _spinner_message=${1:-"Loading..."}
  INFO "$_spinner_message"

  [ "$SPINNER_ENABLE" = true ] || return 0
  [ -z "$SPINNER_PID" ] || FATAL "Spinner PID ($SPINNER_PID) already defined"

  # Spawn spinner process
  _spinner "$_spinner_message" &
  # Spinner process id
  SPINNER_PID=$!
}

# Stop spinner
spinner_stop() {
  [ "$SPINNER_ENABLE" = true ] || return 0
  [ -n "$SPINNER_PID" ] || FATAL "Spinner PID is undefined"

  # Send termination signal
  kill -s USR1 "$SPINNER_PID"
  # Wait may fail
  wait "$SPINNER_PID" || :
  # Reset pid
  SPINNER_PID=
}

# ================
# ASSERT
# ================
# Assert command is installed
# @param $1 Command name
assert_cmd() {
  check_cmd "$1" || FATAL "Command '$1' not found"
  DEBUG "Command '$1' found at '$(command -v "$1")'"
}

# Assert spinner
assert_spinner() {
  [ "$SPINNER_ENABLE" = true ] || return 0

  assert_cmd ps
  assert_cmd tput
}

# Assert Docker image
# @param $1 Docker image
# @param $2 Dockerfile
# @param $3 Dockerfile context
assert_docker_image() {
  assert_cmd docker
  _docker_image=$1
  _dockerfile=${2:-}
  _dockerfile_context=${3:-}

  ! docker image inspect "$_docker_image" >/dev/null 2>&1 || {
    DEBUG "Docker image '$_docker_image' found"
    return 0
  }

  WARN "Docker image '$_docker_image' not found"

  if [ -z "$_dockerfile" ]; then
    INFO "Pulling Docker image '$_docker_image'"
    docker pull "$_docker_image" || FATAL "Error pulling Docker image '$_docker_image'"
  else
    [ -n "$_dockerfile_context" ] || _dockerfile_context=$(dirname "$_dockerfile")
    INFO "Building Docker image '$_docker_image' using Dockerfile '$_dockerfile' with context '$_dockerfile_context'"
    docker build --rm -t "$_docker_image" -f "$_dockerfile" "$_dockerfile_context" || FATAL "Error building Docker image '$_docker_image'"
  fi
}

# Assert executable downloader
assert_downloader() {
  [ -z "$DOWNLOADER" ] || return 0

  _assert_downloader() {
    # Return failure if it doesn't exist or is no executable
    [ -x "$(command -v "$1")" ] || return 1

    # Set downloader
    DOWNLOADER=$1
    return 0
  }

  # Downloader command
  _assert_downloader curl ||
    _assert_downloader wget ||
    FATAL "No executable downloader found: 'curl' or 'wget'"
  DEBUG "Downloader '$DOWNLOADER' found at '$(command -v "$DOWNLOADER")'"
}

# Assert URL is reachable
# @param $1 URL address
# @param $2 Timeout in seconds
assert_url_reachability() {
  assert_downloader

  # URL address
  _url_address=$1
  # Timeout in seconds
  _timeout=${2:-10}

  DEBUG "Testing URL '$_url_address' reachability"
  case $DOWNLOADER in
  curl)
    curl --fail --silent --show-error --max-time "$_timeout" "$_url_address" >/dev/null || FATAL "URL address '$_url_address' is unreachable"
    ;;
  wget)
    wget --quiet --spider --timeout="$_timeout" --tries=1 "$_url_address" 2>&1 || FATAL "URL address '$_url_address' is unreachable"
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac
}

# ================
# CLEANUP
# ================
# Cleanup spinner
cleanup_spinner() {
  { [ "$SPINNER_ENABLE" = true ] && [ -n "$SPINNER_PID" ]; } || return 0

  DEBUG "Resetting cursor"
  tput rc
  tput cnorm
  SPINNER_ENABLE=
  SPINNER_PID=
}

# Cleanup Docker container
# @param $1 Container id
cleanup_docker_container() {
  { [ -n "$1" ] && check_cmd docker; } || return 0

  _container_id=$1
  DEBUG "Stopping Docker container '$_container_id'"
  docker stop "$_container_id" >/dev/null 2>&1 || return 0
  DEBUG "Removing Docker container '$_container_id'"
  docker rm "$_container_id" >/dev/null 2>&1 || return 0
}

# Cleanup directory
# @param $1 Directory path
cleanup_dir() {
  { [ -n "$1" ] && [ -d "$1" ]; } || return 0

  DEBUG "Removing directory '$1'"
  rm -rf "$1" || return 0
}

# ================
# FUNCTIONS
# ================
# Check command is installed
# @param $1 Command name
check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

# Parse URL address
# @param $1 URL address
parse_url() {
  assert_cmd cut
  assert_cmd grep
  assert_cmd sed

  # Protocol
  _url_proto=$(printf '%s\n' "$1" | sed 's,^\(.*://\).*,\1,')
  # Remove protocol
  _url=$(printf '%s\n' "$1" | sed "s,$_url_proto,,")
  # User
  _url_user=$(printf '%s\n' "$_url" | cut -d@ -f1 | cut -d: -f1)
  # Password
  _url_password=$(printf '%s\n' "$_url" | cut -d@ -f1 | cut -d: -f2)
  # Host
  _url_host=$(printf '%s\n' "$_url" | sed "s,$_url_user@,," | cut -d/ -f1 | sed 's,:.*,,')
  # Port
  _url_port=$(printf '%s\n' "$_url" | sed "s,$_url_user@,," | cut -d/ -f1 | sed -e 's,^.*:,:,' -e 's,.*:\([0-9]*\).*,\1,' -e 's,[^0-9],,')
  # Path
  _url_path=$(printf '%s\n' "$_url" | cut -d/ -f2-)

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg url "$_url" \
      --arg proto "$_url_proto" \
      --arg user "$_url_user" \
      --arg password "$_url_password" \
      --arg host "$_url_host" \
      --arg port "$_url_port" \
      --arg path "$_url_path" \
      '
        {
          "url": $url,
          "proto": $proto,
          "user": $user,
          "password": $password,
          "host": $host,
          "port": $port,
          "path": $path
        }
      '
  )
}

# Download a file
# @param $1 Output location
# @param $2 Download URL
download() {
  assert_downloader

  # Download
  DEBUG "Downloading file '$2' to '$1'"
  case $DOWNLOADER in
  curl)
    curl --fail --silent --location --output "$1" "$2" || FATAL "Download file '$2' failed"
    ;;
  wget)
    wget --quiet --output-document="$1" "$2" || FATAL "Download file '$2' failed"
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac

  DEBUG "Successfully downloaded file '$2' to '$1'"
}

# Print downloaded content
# @param $1 Download URL
download_print() {
  assert_downloader >/dev/null

  # Download
  case $DOWNLOADER in
  curl)
    curl --fail --silent --location --show-error "$1" || FATAL "Download print '$1' failed"
    ;;
  wget)
    wget --quiet --output-document=- "$1" 2>&1 || FATAL "Download print '$1' failed"
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac
}

# Remove and create directory
# @param $1 Directory path
recreate_dir() {
  _dir=$1
  DEBUG "Recreating directory '$_dir'"

  if [ -d "$_dir" ]; then
    WARN "Removing directory '$_dir'"
    rm -rf "$_dir" || FATAL "Error removing directory '$_dir'"
  fi

  INFO "Creating directory '$_dir'"
  mkdir -p "$_dir" || FATAL "Error creating directory '$_dir'"
}

# Check if value is an integer number
# @param $1 Value
is_integer() {
  [ -n "$1" ] || return 1

  case $1 in
  '' | *[!0-9]*) return 1 ;;
  *) return 0 ;;
  esac
}

# Git files
# @param $1 Git directory
git_files() {
  assert_cmd basename
  assert_cmd git
  assert_cmd jq

  _dir=$1
  # Append .git if not present
  [ "$(basename "$_dir")" = .git ] || _dir="$_dir/.git"

  DEBUG "Git files in '$_dir' Git directory"

  # Check if directory
  [ -d "$_dir" ] || FATAL "Directory '$_dir' does not exists"

  # Git files
  _git_files=$(
    git --git-dir "$_dir" ls-files --cached --others --exclude-standard --full-name |
      jq --raw-input --null-input '[inputs | select(length > 0)]'
  ) || FATAL "Error Git files in '$_dir' Git directory"

  # Return
  # shellcheck disable=2034
  RETVAL=$_git_files
}

# Check if directory in git
# @param $1 Git files
# @param $2 Directory
git_has_directory() {
  assert_cmd jq

  _git_files=$1
  _dir=$2

  DEBUG "Checking Git has directory '$_dir'"
  [ "$(printf '%s\n' "$_git_files" | jq --raw-output --arg dir "$_dir" 'any(.[]; startswith($dir))')" = true ]

  return $?
}

# Check if file in git
# @param $1 Git files
# @param $2 File
git_has_file() {
  assert_cmd jq

  _git_files=$1
  _file=$2

  DEBUG "Checking Git has file '$_file'"
  [ "$(printf '%s\n' "$_git_files" | jq --raw-output --arg file "$_file" 'any(.[]; . == $file)')" = true ]

  return $?
}

# ================
# CONFIGURATION
# ================
# Help usage string
# shellcheck disable=2034
HELP_COMMONS_USAGE=$(
  cat <<EOF
Usage commons: $(basename "$0") [--disable-color] [--disable-spinner] [--log-level <LEVEL>] [--spinner <SPINNER>]
EOF
)
# Help options string
# shellcheck disable=2034
HELP_COMMONS_OPTIONS=$(
  cat <<EOF
Options commons:
  --disable-color      Disable color

  --disable-spinner    Disable spinner

  --log-level <LEVEL>  Logger level
                       Default: $(to_log_level_name "$LOG_LEVEL")
                       Values:
                         fatal    Fatal level
                         error    Error level
                         warn     Warning level
                         info     Informational level
                         debug    Debug level

  --spinner <SPINNER>  Spinner
                       Default: propeller
                       Values:
                         dots         Dots spinner
                         grayscale    Grayscale spinner
                         propeller    Propeller spinner
EOF
)
# Log level
LOG_LEVEL=$LOG_LEVEL_INFO
# Log color flag
LOG_COLOR_ENABLE=true
# Spinner symbols
SPINNER_SYMBOLS=$SPINNER_SYMBOLS_PROPELLER
# Spinner flag
SPINNER_ENABLE=true

# ================
# CONFIGURATION
# ================
# Admin username
ADMIN_USERNAME="admin"
# Admin password
ADMIN_PASSWORD="Password\$0"
# Airgap environment flag
AIRGAP_ENV=false
# Autoscaler username
AUTOSCALER_USERNAME="autoscaler"
# Autoscaler password
AUTOSCALER_PASSWORD="Password\$0"
# Autoscaler version
AUTOSCALER_VERSION=latest
# Benchmark time in seconds
BENCH_TIME=30
# Configuration file
CONFIG_FILE="configs/recluster/config.yaml"
# Initialize cluster
INIT_CLUSTER=false
# K3s configuration file
K3S_CONFIG_FILE="configs/k3s/config.yaml"
# K3s registry configuration file
K3S_REGISTRY_CONFIG_FILE="configs/k3s/registries.yaml"
# K3s version
K3S_VERSION=latest
# Node exporter configuration file
NODE_EXPORTER_CONFIG_FILE="configs/node_exporter/config.yaml"
# Node exporter version
NODE_EXPORTER_VERSION=latest
# Power consumption device api url
PC_DEVICE_API="http://pc.recluster.local/cm?cmnd=status%2010"
# Power consumption interval in seconds
PC_INTERVAL=1
# Power consumption time in seconds
PC_TIME=30
# Power consumption warmup time in seconds
PC_WARMUP=10
# reCluster etc directory
RECLUSTER_ETC_DIR="/etc/recluster"
# reCluster opt directory
RECLUSTER_OPT_DIR="/opt/recluster"
# reCluster certificates directory
RECLUSTER_CERTS_DIR="configs/certs"
# reCluster server environment file
RECLUSTER_SERVER_ENV_FILE="configs/recluster/server.env"
# SSH authorized keys file
SSH_AUTHORIZED_KEYS_FILE="configs/ssh/authorized_keys"
# SSH configuration file
SSH_CONFIG_FILE="configs/ssh/ssh_config"
# SSH server configuration file
SSHD_CONFIG_FILE="configs/ssh/sshd_config"
# User
USER="root"

# ================
# GLOBALS
# ================
# Autoscaler directory
AUTOSCALER_DIR=
# Autoscaler token
AUTOSCALER_TOKEN=
# Configuration
CONFIG=
# K3s configuration
K3S_CONFIG=
# Node exporter configuration
NODE_EXPORTER_CONFIG=
# Node facts
NODE_FACTS='{}'
# Temporary directory
TMP_DIR=
#Sysbench binary path
SYSBENCH_PATH="/usr/bin/sysbench"
#Power on device IP
POWER_ON_DEVICE_IP=

# ================
# CLEANUP
# ================
cleanup() {
  # Exit code
  _exit_code=$?

  [ $_exit_code = 0 ] || WARN "Cleanup exit code $_exit_code"

  cd $_main_install_directory
  # Cleanup temporary directory
  cleanup_dir "$TMP_DIR"

  # Cleanup Sysbench compiling tmp directory
  cleanup_dir "$_sysbench_tmp_directory"

  # Cleanup spinner
  cleanup_spinner

  exit "$_exit_code"

}

# Trap
trap cleanup QUIT TERM EXIT

# ================
# FUNCTIONS
# ================
# Show help message
show_help() {
  cat <<EOF
Usage: $(basename "$0") [--admin-username <USERNAME>] [--admin-password <PASSWORD>] [--airgap]
        [--autoscaler-username <USERNAME>] [--autoscaler-password <PASSWORD>] [--autoscaler-version <VERSION>]
        [--bench-time <TIME>] [--certs-dir <DIR>] [--config-file <FILE>] [--help]
        [--init-cluster] [--k3s-config-file <FILE>] [--k3s-registry-config-file <FILE>] [--k3s-version <VERSION>]
        [--node-exporter-config-file <FILE>] [--node-exporter-version <VERSION>]
        [--pc-device-api <URL>] [--pc-interval <TIME>] [--pc-time <TIME>] [--pc-warmup <TIME>]
        [--server-env-file <FILE>] [--ssh-authorized-keys-file <FILE>] [--ssh-config-file <FILE>] [--sshd-config-file <FILE>]
        [--user <USER>]

$HELP_COMMONS_USAGE

reCluster installation script.

Options:
  --admin-username <USERNAME>         Admin username
                                      Default: $ADMIN_USERNAME
                                      Values:
                                        Any valid username

  --admin-password <PASSWORD>         Admin password
                                      Default: $ADMIN_PASSWORD
                                      Values:
                                        Any valid password

  --airgap                            Perform installation in Air-Gap environment

  --autoscaler-username <USERNAME>    Autoscaler username
                                      Default: $AUTOSCALER_USERNAME
                                      Values:
                                        Any valid username

  --autoscaler-password <PASSWORD>    Autoscaler password
                                      Default: $AUTOSCALER_PASSWORD
                                      Values:
                                        Any valid password

  --autoscaler-version <VERSION>      Autoscaler version
                                      Default: $AUTOSCALER_VERSION
                                      Values:
                                        Any Autoscaler version

  --bench-time <TIME>                 Benchmark execution time in seconds
                                      Default: $BENCH_TIME
                                      Values:
                                        Any positive number

  --certs-dir <DIR>                   Server certificates directory
                                      Default: $RECLUSTER_CERTS_DIR
                                      Values:
                                        Any valid directory

  --config-file <FILE>                Configuration file
                                      Default: $CONFIG_FILE
                                      Values:
                                        Any valid file

  --help                              Show this help message and exit

  --init-cluster                      Initialize cluster components and logic
                                        Enable only when bootstrapping for the first time

  --k3s-config-file <FILE>            K3s configuration file
                                      Default: $K3S_CONFIG_FILE
                                      Values:
                                        Any valid file

  --k3s-registry-config-file <FILE>   K3s registry configuration file
                                      Default: $K3S_REGISTRY_CONFIG_FILE
                                      Values:
                                        Any valid file

  --k3s-version <VERSION>             K3s version
                                      Default: $K3S_VERSION
                                      Values:
                                        Any K3s version

  --node-exporter-config-file <FILE>  Node exporter configuration file
                                      Default: $NODE_EXPORTER_CONFIG_FILE
                                      Values:
                                        Any valid file

  --node-exporter-version <VERSION>   Node exporter version
                                      Default: $NODE_EXPORTER_VERSION
                                      Values:
                                        Any Node exporter version

  --pc-device-api <URL>               Power consumption device api URL
                                      Default: $PC_DEVICE_API
                                      Values:
                                        Any valid URL

  --pc-interval <TIME>                Power consumption read interval time in seconds
                                      Default: $PC_INTERVAL
                                      Values:
                                        Any positive number

  --pc-time <TIME>                    Power consumption execution time in seconds
                                      Default: $PC_TIME
                                      Values:
                                        Any positive number

  --pc-warmup <TIME>                  Power consumption warmup time in seconds
                                      Default: $PC_WARMUP
                                      Values:
                                        Any positive number

  --server-env-file <FILE>            Server environment file
                                      Default: $RECLUSTER_SERVER_ENV_FILE
                                      Values:
                                        Any valid file

  --ssh-authorized-keys-file <FILE>   SSH authorized keys file
                                      Default: $SSH_AUTHORIZED_KEYS_FILE
                                      Values:
                                        Any valid file

  --ssh-config-file <FILE>            SSH configuration file
                                      Default: $SSH_CONFIG_FILE
                                      Values:
                                        Any valid file

  --sshd-config-file <FILE>           SSH server configuration file
                                      Default: $SSHD_CONFIG_FILE
                                      Values:
                                        Any valid file

  --user <USER>                       User
                                      Default: $USER
                                      Values:
                                        Any valid user

$HELP_COMMONS_OPTIONS
EOF
}

# Assert init system
assert_init_system() {
  if [ -x /sbin/openrc-run ]; then
    # OpenRC
    INIT_SYSTEM=openrc
  elif [ -x /bin/systemctl ] || type systemctl >/dev/null 2>&1; then
    # systemd
    INIT_SYSTEM=systemd
  fi

  # Init system check
  if [ -n "$INIT_SYSTEM" ]; then
    # Supported
    DEBUG "Init system is '$INIT_SYSTEM'"
  else
    # Not supported
    FATAL "No supported init system found: 'OpenRC' or 'systemd'"
  fi
}

# Assert timezone
assert_timezone() {
  _timezone_file="/etc/timezone"
  _timezone="Etc/UTC"

  [ -f "$_timezone_file" ] || FATAL "Timezone file '$_timezone_file' not found"
  _current_timezone=$(cat $_timezone_file)
  [ "$_current_timezone" = "$_timezone" ] || FATAL "Timezone is not '$_timezone' but '$_current_timezone'"
}

# Assert user
assert_user() {
  id "$USER" >/dev/null 2>&1 || FATAL "User '$USER' does not exists"
}

### Sysbench management methods

# Sysbench status check method
check_sysbench() {

  # Look for an already existing compiled version of Sysbench on the system
  if [ -f "$HOME/bin/recluster_sysbench" ]; then
    whiptail --title "Check Sysbench" --msgbox "It seems that already exists a compiled version of sysbench installed on this system. Testing this first..." 8 78
    SYSBENCH_PATH="$HOME/bin/recluster_sysbench"
  fi

  whiptail --title "Check Sysbench" --msgbox "Checking if the Sysbench command is working properly." 8 78

  # Disabling the automatic error interruption for the script.
  set +e
  $SYSBENCH_PATH cpu --cpu-max-prime=10 run
  exit_code=$?
  # Re-enabling the automatic error interruption for the script.
  set -e

  # Print the sysbench exit error.
  DEBUG "Sysbench exit code: $exit_code"

  # Management of different exit code cases.
  # Illegal instruction case (code 132)
  if [ $exit_code -eq 132 ]; then
    whiptail --title "Error" --msgbox "Sysbench encountered an 'Illegal instruction' error. Looking for possible causes..." 10 78
    # Perform CPU's specs checking
    check_cpu_specs
    compile_sysbench
    # Command not found case (code 126)
  elif [ $exit_code -eq 127 ]; then
    whiptail --title "Error" --msgbox "Sysbench command not found. Please install it." 8 78
    # Ask the user if he wants to install Sysbench using the apk paceket manager, only if there is an internet connection.
    if wget --spider --quiet http://www.google.com; then
      if whiptail --title "Sysbench installation" --yesno "Do you want to install it using the apk packet manager?" 8 78; then
        # Install sysbench
        apk update
        apk add sysbench
        # Updating the sysbench binary path
        SYSBENCH_PATH="/usr/bin/sysbench"
        whiptail --title "Installation successful" --msgbox "Sysbench installation through apk packet manager succeded." 10 78
        # Call again the check_system method.
        check_sysbench
      else
        whiptail --title "Installation refused" --msgbox "The user has refused to install Sysbench through the apk packet manager. You can still proceed compiling Sysbench from source." 10 78
        compile_sysbench
      fi
    else
      # If there is no internet connection, notify the user to install sysbench offline.
      whiptail --title "Network Error" --msgbox "No internet connection, it is not possible to install Sysbench automatically using the apk packet manager. You can still proceed compiling Sysbench from source." 10 78
      compile_sysbench
    fi

  elif [ $exit_code -ne 0 ]; then
    whiptail --title "Error" --msgbox "Sysbench exited unexpectedly (exit code: $exit_code) because of currently unknown reasons. Please check the exit code. You can anyway try to proceed compiling Sysbench from source." 10 78
    compile_sysbench
  else
    whiptail --title "Info" --msgbox "Sysbench is present and working properly." 8 78
    INFO "Sysbench is present and working properly."
  fi
}

# Compile Sysbench method

compile_sysbench() {

  # List of required packages for Sysbench compilation
  _sysbench_packages="g++ autoconf make automake libtool pkgconfig libaio-dev"

  # Asking user to proceed with compilation
  if whiptail --title "Compile Sysbench" --yesno "Do you want to proceed compiling and autoconfiguring Sysbench from source? NOTE: without a working instance of Sysbench, the recluster installation will be terminated. (Y/n)" 12 78; then
    whiptail --title "Compilation Process" --infobox "Continuing..." 8 78
    # Remove already present pre compiled version of sysbench
    apk del sysbench

    # Check the internet connection
    assert_url_reachability "www.google.com"

    # Install all the required packages
    for package in $_sysbench_packages; do
      add_package "$package"
    done

    # Clean apk cache
    apk cache clean

    # Sysbench archive
    _sysbench_archive_name="./dependencies/sysbench.tar.gz"

    # Specifying tmp directory
    _sysbench_tmp_directory="./dependencies/sysbench_tmp"

    # Main current installation directory
    _main_install_directory=$(pwd)

    # Create tmp directory
    rm -rf ./dependencies/sysbench_tmp
    mkdir ./dependencies/sysbench_tmp

    # Extracting the Sysbench archive
    tar -xzf "$_sysbench_archive_name" -C "$_sysbench_tmp_directory" || {
      whiptail --title "Error" --msgbox "Error while extracting the Sysbench archive." 10 78
      return 1
    }

    # Find the extracted subdirectory
    _subdirectory_name=$(tar -tf "$_sysbench_archive_name" | head -n 1 | cut -d '/' -f 1)

    # Going into the Sysbench tmp directory
    if ! cd "$_sysbench_tmp_directory/$_subdirectory_name"; then
      whiptail --title "Error" --msgbox "Could not get into Sysbench installation directory." 10 78
      return 1
    fi

    # Running the Sysbench autogen script
    ./autogen.sh >/dev/null

    # Configure
    ./configure --without-mysql >/dev/null

    # Make
    make -j >/dev/null

    # Renaming the binary
    mv ./src/sysbench ./src/recluster_sysbench

    # Asking user if they want to install the working Sysbench into the system
    if whiptail --title "Sysbench Installation" --yesno "Now a working instance of Sysbench is available. Do you want to proceed installing this on the system so that it will be available after the end of the installation? Otherwise it will be removed when the installation ends. (y/N)" 12 78; then
      whiptail --title "Installation" --infobox "Installing the sysbench binary to the ~/bin/ location." 8 78
      # Creating the installation folder inside the current user home directory
      mkdir -p ~/bin/
      # Moving the binary
      cp ./src/recluster_sysbench ~/bin/
      # Updating the sysbench binary path
      SYSBENCH_PATH="$HOME/bin/recluster_sysbench"
    else
      whiptail --title "Temporary Installation" --infobox "The Sysbench binary will remain to the temporary location and will be removed after installation's ending." 8 78
      # Updating the sysbench binary path
      SYSBENCH_PATH="$_sysbench_tmp_directory/$_subdirectory_name/src/recluster_sysbench"
    fi

    cd "$_main_install_directory"
    whiptail --title "Success" --msgbox "Sysbench compiling, configuration and installation completed successfully." 10 78
    INFO "Checking if sysbench now is working"
    check_sysbench
  else
    whiptail --title "Aborted" --msgbox "Without a working instance of Sysbench the reCluster installation can't proceed. Aborting..." 10 78
    cd "$_main_install_directory"
    return 1
  fi
}

# Add dependency package
add_package() {
  package_name="$1"

  # Verify if the package is already present
  if apk info "$package_name" >/dev/null 2>&1; then
    DEBUG "The package $package_name is already installed."
  else
    # Install the package
    apk add "$package_name"

    # Verify the installation result
    if [ $? -eq 0 ]; then
      DEBUG "The package $package_name has been succesflly installed."
    else
      FATAL "Error while installing the package $package_name. Exiting ..."
      whiptail --title "Error while installing the package $package_name. Exiting ..." 10 78
    fi
  fi
}

check_cpu_specs() {
  local cpuinfo_file="/proc/cpuinfo"

  # Check for AVX flag
  avx_present=$(grep -iq "avx" "$cpuinfo_file" && echo true || echo false)
  DEBUG "Sysbench installation debugging: AVX instruction set: ${avx_present}"

  # Check for F16C flag
  f16c_present=$(grep -iq "f16c" "$cpuinfo_file" && echo true || echo false)
  DEBUG "Sysbench installation debugging: F16C instruction set: ${f16c_present}"

  # Check the CPUID level
  cpuid_level=$(grep -E '^cpuid level' "$cpuinfo_file" | cut -d ':' -f2 | tr -dc '[:digit:]')

  if [ "$avx_present" = true ] && [ "$f16c_present" = false ]; then
    whiptail --title "CPU Support" --msgbox "The AVX instruction set is supported by your CPU but the F16C instruction set is not. This is the reason because the pre compiled version of Sysbench installed through the APK packet manager is not working." 12 78
  elif [ "$avx_present" = false ] && [ "$f16c_present" = true ]; then
    whiptail --title "CPU Support" --msgbox "The AVX instruction set is not supported by your CPU but the F16C instruction set is. This is the reason because the pre compiled version of Sysbench installed through the APK packet manager is not working." 12 78
  elif [ "$avx_present" = false ] && [ "$f16c_present" = false ]; then
    whiptail --title "CPU Support" --msgbox "Neither the AVX instruction set nor the F16C instruction set are supported by your CPU. This is the reason because the pre compiled version of Sysbench installed through the APK packet manager is not working." 12 78
  elif [ "$avx_present" = true ] && [ "$f16c_present" = true ]; then
    whiptail --title "CPU Support" --msgbox "Both the AVX instruction set and the F16C instruction set are supported by your CPU. Going to check the CPUID level of your CPU as further required condition." 12 78
    if [[ $cpuid_level -le 11 ]]; then
      whiptail --title "CPUID Level Check" --msgbox "Your CPU CPUID level is lower than or equal to 11. This is the reason because the pre compiled version of Sysbench installed through the APK packet manager is not working." 12 78
    else
      whiptail --title "CPUID Level Warning" --msgbox "WARNING: Your CPU CPUID level is higher than 11 and all the other known requirements are met. Something unusual is happened, since the pre compiled Sysbench binary should be working. But it is not, probably other currently unknown conditions are not met." 12 78
    fi
  fi
}

###

# Home directory of user
user_home_dir() {
  _home_dir=

  case $USER in
  root) _home_dir="/root" ;;
  *) _home_dir="/home/$USER" ;;
  esac

  printf '%s\n' "$_home_dir"
}

# Create uninstall
create_uninstall() {
  _uninstall_script_file="/usr/local/bin/recluster.uninstall.sh"

  INFO "Creating uninstall script '$_uninstall_script_file'"
  $SUDO tee "$_uninstall_script_file" >/dev/null <<EOF
#!/usr/bin/env sh

[ \$(id -u) -eq 0 ] || exec sudo \$0 \$@

if command -v rc-service; then
  rc-service k3s-recluster stop
  rc-service node_exporter stop
  rc-service recluster.server stop
  rc-service postgresql stop
  rc-service recluster stop
fi
if command -v systemctl; then
  systemctl stop k3s-recluster.service
  systemctl stop node_exporter.service
  systemctl stop recluster.server.service
  systemctl stop postgresql.service
  systemctl stop recluster.service
fi

[ -x '/usr/local/bin/k3s-recluster-uninstall.sh' ] && /usr/local/bin/k3s-recluster-uninstall.sh
[ -x '/usr/local/bin/node_exporter.uninstall.sh' ] && /usr/local/bin/node_exporter.uninstall.sh

if command -v systemctl; then
  systemctl disable recluster.server.service
  systemctl disable recluster.service
  systemctl reset-failed recluster.server.service
  systemctl reset-failed recluster.service
  systemctl daemon-reload
fi
if command -v rc-update; then
  rc-update delete recluster.server default
  rc-update delete recluster default
fi

rm -f /etc/systemd/system/recluster.server.service
rm -f /etc/init.d/recluster.server
rm -f /var/log/recluster.server.log

rm -f /etc/systemd/system/recluster.service
rm -f /etc/init.d/recluster
rm -f /var/log/recluster.log

# Certificates
rm -f /usr/local/share/ca-certificates/registry.crt
rm -f /usr/local/share/ca-certificates/registry.key
update-ca-certificates

rm -rf "$RECLUSTER_ETC_DIR"
rm -rf "$RECLUSTER_OPT_DIR"

remove_uninstall() {
  rm -f "$_uninstall_script_file"
}
trap remove_uninstall EXIT
EOF

  $SUDO chown root:root "$_uninstall_script_file"
  $SUDO chmod 754 "$_uninstall_script_file"
}

# Setup SSH
setup_ssh() {
  _ssh_config_file="/etc/ssh/ssh_config"
  _ssh_config_dir=$(dirname "$_ssh_config_file")
  _sshd_config_file="/etc/ssh/sshd_config"
  _sshd_config_dir=$(dirname "$_sshd_config_file")
  _ssh_authorized_keys_file="$(user_home_dir)/.ssh/authorized_keys"
  _ssh_authorized_keys_dir=$(dirname "$_ssh_authorized_keys_file")

  spinner_start "Setting up SSH"

  # SSH configuration
  INFO "Copying SSH configuration file from '$SSH_CONFIG_FILE' to '$_ssh_config_file'"
  [ -d "$_ssh_config_dir" ] || {
    WARN "Creating SSH configuration directory '$_ssh_config_dir'"
    $SUDO mkdir -p "$_ssh_config_dir"
    $SUDO chown root:root "$_ssh_config_dir"
    $SUDO chmod 755 "$_ssh_config_dir"
  }
  yes | $SUDO cp --force "$SSH_CONFIG_FILE" "$_ssh_config_file"
  $SUDO chown root:root "$_ssh_config_file"
  $SUDO chmod 644 "$_ssh_config_file"

  # SSH server configuration
  INFO "Copying SSH server configuration file from '$SSHD_CONFIG_FILE' to '$_sshd_config_file'"
  [ -d "$_sshd_config_dir" ] || {
    WARN "Creating SSH server configuration directory '$_sshd_config_dir'"
    $SUDO mkdir -p "$_sshd_config_dir"
    $SUDO chown root:root "$_sshd_config_dir"
    $SUDO chmod 755 "$_sshd_config_dir"
  }
  yes | $SUDO cp --force "$SSHD_CONFIG_FILE" "$_sshd_config_file"
  $SUDO chown root:root "$_sshd_config_file"
  $SUDO chmod 644 "$_sshd_config_file"

  # SSH authorized keys
  [ -d "$_ssh_authorized_keys_dir" ] || {
    WARN "Creating SSH authorized keys directory '$_ssh_authorized_keys_dir'"
    $SUDO mkdir -p "$_ssh_authorized_keys_dir"
    $SUDO chown "$USER:$USER" "$_ssh_authorized_keys_dir"
    $SUDO chmod 700 "$_ssh_authorized_keys_dir"
  }
  while read -r _ssh_authorized_key; do
    INFO "Copying SSH authorized key '$_ssh_authorized_key' to SSH authorized keys '$_ssh_authorized_keys_file'"
    printf "%s\n" "$_ssh_authorized_key" | $SUDO tee -a "$_ssh_authorized_keys_file" >/dev/null || FATAL "Error copying SSH authorized key '$_ssh_authorized_key' to SSH authorized keys '$_ssh_authorized_keys_file'"
  done <<EOF
$(cat "$SSH_AUTHORIZED_KEYS_FILE")
EOF
  $SUDO chown "$USER:$USER" "$_ssh_authorized_keys_file"
  $SUDO chmod 644 "$_ssh_authorized_keys_file"

  # Restart SSH service
  case $INIT_SYSTEM in
  openrc)
    INFO "openrc: Restarting SSH"
    $SUDO rc-service sshd restart
    ;;
  systemd)
    INFO "systemd: Restarting SSH"
    $SUDO systemctl restart ssh
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  spinner_stop
}

# Setup certificates
setup_certificates() {
  _certs_dir="$RECLUSTER_ETC_DIR/certs"
  _ssh_crt_src="$DIRNAME/configs/certs/ssh.crt"
  _ssh_crt_dst="$_certs_dir/ssh.crt"
  _ssh_key_src="$DIRNAME/configs/certs/ssh.key"
  _ssh_key_dst="$_certs_dir/ssh.key"
  _token_crt_src="$DIRNAME/configs/certs/token.crt"
  _token_crt_dst="$_certs_dir/token.crt"
  _token_key_src="$DIRNAME/configs/certs/token.key"
  _token_key_dst="$_certs_dir/token.key"
  _registry_crt_src="$DIRNAME/configs/certs/registry.crt"
  _registry_crt_dst="/usr/local/share/ca-certificates/registry.crt"
  _registry_key_src="$DIRNAME/configs/certs/registry.key"
  _registry_key_dst="/usr/local/share/ca-certificates/registry.key"

  spinner_start "Setting up certificates"

  [ -f "$_ssh_crt_src" ] || FATAL "SSH certificate file '$_ssh_crt_src' does not exists"
  [ -f "$_ssh_key_src" ] || FATAL "SSH certificate file '$_ssh_key_src' does not exists"
  [ -f "$_token_crt_src" ] || FATAL "Token certificate file '$_token_crt_src' does not exists"
  [ -f "$_token_key_src" ] || FATAL "Token certificate file '$_token_key_src' does not exists"
  [ -f "$_registry_crt_src" ] || FATAL "Registry certificate file '$_registry_crt_src' does not exists"
  [ -f "$_registry_key_src" ] || FATAL "Registry certificate file '$_registry_key_src' does not exists"

  DEBUG "Creating reCluster certificates directory '$_certs_dir'"
  $SUDO rm -rf "$_certs_dir"
  $SUDO mkdir "$_certs_dir"

  DEBUG "Copying SSH certificate file '$_ssh_crt_src' to '$_ssh_crt_dst'"
  yes | $SUDO cp --force "$_ssh_crt_src" "$_ssh_crt_dst"
  DEBUG "Copying SSH certificate file '$_ssh_key_src' to '$_ssh_key_dst'"
  yes | $SUDO cp --force "$_ssh_key_src" "$_ssh_key_dst"
  DEBUG "Copying Token certificate file '$_token_crt_src' to '$_token_crt_dst'"
  yes | $SUDO cp --force "$_token_crt_src" "$_token_crt_dst"
  DEBUG "Copying Token certificate file '$_token_key_src' to '$_token_key_dst'"
  yes | $SUDO cp --force "$_token_key_src" "$_token_key_dst"
  DEBUG "Copying Registry certificate file '$_registry_crt_src' to '$_registry_crt_dst'"
  yes | $SUDO cp --force "$_registry_crt_src" "$_registry_crt_dst"
  DEBUG "Copying Registry certificate file '$_registry_key_src' to '$_registry_key_dst'"
  yes | $SUDO cp --force "$_registry_key_src" "$_registry_key_dst"

  INFO "Updating reCluster certificates directory '$_certs_dir' permissions"
  $SUDO chown --recursive root:root "$_certs_dir"
  $SUDO chmod --recursive 600 "$_certs_dir"
  INFO "Updating CA certificates"
  $SUDO update-ca-certificates

  spinner_stop
}

# Read interfaces
read_interfaces() {
  ip -details -json link show |
    jq \
      '
          map(if .linkinfo.info_kind // .link_type == "loopback" then empty else . end)
          | map(.name = .ifname)
          | map({address, name})
        '
}

# Read power consumption
# @param $1 Benchmark PID
read_power_consumption() {
  _read_power_consumption() {
    download_print "$PC_DEVICE_API" | jq --raw-output '.StatusSNS.ENERGY.Power'
  }
  _pid=$1
  _pcs='[]'
  # Standard deviation max tolerance inclusive
  _standard_deviation_tolerance=5

  # Warmup
  sleep "$PC_WARMUP"

  # Execute
  _end=$(date -ud "$PC_TIME second" +%s)
  while [ "$(date -u +%s)" -le "$_end" ]; do
    # Current power consumption
    _pc=$(_read_power_consumption)
    DEBUG "Reading power consumption: ${_pc}W"
    # Add current power consumption to list
    _pcs=$(printf '%s\n' "$_pcs" | jq --arg pc "$_pc" '. |= . + [$pc | tonumber]')
    # Sleep
    sleep "$PC_INTERVAL"
  done

  # Terminate benchmark process
  if [ -n "$_pid" ]; then
    DEBUG "Terminating benchmark process PID $_pid"
    kill -s KILL "$_pid"
    # Wait may fail
    wait "$_pid" || :
  fi

  # Check pcs
  [ "$(printf '%s\n' "$_pcs" | jq --raw-output 'length')" -ge 2 ] || FATAL "Power consumption readings not enough data"
  [ "$(printf '%s\n' "$_pcs" | jq --raw-output 'add')" -ge 1 ] || FATAL "Power consumption readings are below 1W"

  # Calculate mean
  _mean=$(
    printf '%s\n' "$_pcs" |
      jq \
        --raw-output \
        '
          add / length
          | . + 0.5
          | floor
        '
  )
  [ "$_mean" -ge 1 ] || FATAL "Power consumption mean is below 1W"
  DEBUG "Power consumption mean: $_mean"

  # Calculate standard deviation
  _standard_deviation=$(
    printf '%s\n' "$_pcs" |
      jq \
        --raw-output \
        '
          (add / length) as $mean
          | (map(. - $mean | . * .) | add) / (length - 1)
          | sqrt
        '
  )
  [ "$(printf '%s <= %s' "${_standard_deviation#-}" "$_standard_deviation_tolerance" | bc)" -eq 1 ] || FATAL "Power consumption standard deviation $_standard_deviation exceeds tolerance $_standard_deviation_tolerance"
  DEBUG "Power consumption standard deviation: $_standard_deviation"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg mean "$_mean" \
      --arg standard_deviation "$_standard_deviation" \
      '{
        "mean": $mean,
        "standardDeviation": $standard_deviation
      }'
  )
}

# Decode JWT token
# @param $1 JWT token
decode_token() {
  _decode_token() {
    printf '%s\n' "$1" | jq --raw-input --arg idx "$2" 'gsub("-";"+") | gsub("_";"/") | split(".") | .[$idx|tonumber] | @base64d | fromjson'
  }
  _token=$1

  DEBUG "Decoding JWT token '$_token'"

  # Token header
  _token_header=$(_decode_token "$_token" 0)
  # Token payload
  _token_payload=$(_decode_token "$_token" 1)

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --argjson header "$_token_header" \
      --argjson payload "$_token_payload" \
      '
        {
          "header": $header,
          "payload": $payload
        }
      '
  )
}

# Send server request
# @param $1 Request data
# @param $2 Server URL
send_server_request() {
  _req_data=$1
  _res_data=
  if [ -n "$2" ]; then
    _server_url=$2
  else
    _server_url="$(printf '%s\n' "$CONFIG" | jq --exit-status --raw-output '.recluster.server')/graphql"
  fi

  # Send request
  DEBUG "Sending server request data to '$_server_url':" "$_req_data"
  case $DOWNLOADER in
  curl)
    _res_data=$(
      curl --fail --silent --location --show-error \
        --request POST \
        --header 'Content-Type: application/json' \
        --data "$_req_data" \
        --url "$_server_url"
    ) || FATAL "Error sending server request to '$_server_url'"
    ;;
  wget)
    _res_data=$(
      wget --quiet --output-document=- \
        --header='Content-Type: application/json' \
        --post-data="$_req_data" \
        "$_server_url" 2>&1
    ) || FATAL "Error sending server request to '$_server_url'"
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac
  DEBUG "Received server response data from '$_server_url':" "$_res_data"

  # Check error response
  if printf '%s\n' "$_res_data" | jq --exit-status 'has("errors")' >/dev/null 2>&1; then
    FATAL "Server '$_server_url' response data error:" "$_res_data"
  fi

  # Return
  RETVAL=$_res_data
}

# Create server user
# @param $1 Username
# @param $2 Password
create_server_user() {
  _username=$1
  _password=$2
  _user_data=$(
    jq \
      --null-input \
      --compact-output \
      --arg username "$_username" \
      --arg password "$_password" \
      '
        {
          "username": $username,
          "password": $password
        }
      '
  )
  _user_req_data=$(
    jq \
      --null-input \
      --compact-output \
      --argjson data "$_user_data" \
      '
        {
          "query": "mutation ($data: CreateUserInput!) { createUser(data: $data) { id } }",
          "variables": { "data": $data }
        }
      '
  )
  _user_res_data=

  # Send request
  INFO "Creating user '$_username'"
  send_server_request "$_user_req_data"
  _user_res_data="$(printf '%s\n' "$RETVAL" | jq '.data.createUser')"

  # Return
  RETVAL=$_user_res_data
}

# Sign in server user
# @param $1 Username
# @param $2 Password
sign_in_server_user() {
  _username=$1
  _password=$2
  _sign_in_req_data=$(
    jq \
      --null-input \
      --compact-output \
      --arg username "$_username" \
      --arg password "$_password" \
      '
        {
          "query": "mutation ($username: NonEmptyString!, $password: NonEmptyString!) { signIn(username: $username, password: $password) }",
          "variables": { "username": $username, "password": $password }
        }
      '
  )
  _sign_in_res_data=

  # Send request
  INFO "Signing in user '$_username'"
  send_server_request "$_sign_in_req_data"
  _sign_in_res_data=$RETVAL

  # Extract token
  _token=$(printf '%s\n' "$_sign_in_res_data" | jq --raw-output '.data.signIn')

  # Decode token
  decode_token "$_token"
  _token_decoded=$RETVAL

  # Success
  INFO "Successfully signed in user '$_username'"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg token "$_token" \
      --argjson decoded "$_token_decoded" \
      '
        {
          "token": $token,
          "decoded": $decoded
        }
      '
  )
}

# Read CPU information
read_cpu_info() {
  _cpu_info=$(
    lscpu --json |
      jq \
        '
          .lscpu
          | map({(.field): .data})
          | add
          | with_entries(if .key | endswith(":") then .key |= sub(":";"") else . end)
          | .Flags /= " "
          | .vulnerabilities = (to_entries | map(.key | select(startswith("Vulnerability "))[14:]))
          | with_entries(select(.key | startswith("Vulnerability ") | not))
          | . + {"architecture": .Architecture}
          | . + {"flags": .Flags}
          | . + {"cores": (."CPU(s)" | tonumber)}
          | . + {"vendor": ."Vendor ID"}
          | . + {"family": (."CPU family" | tonumber)}
          | . + {"model": (.Model | tonumber)}
          | . + {"name": ."Model name"}
          | . + {"cacheL1d": (."L1d cache" | split(" ") | .[0] + " " + .[1])}
          | . + {"cacheL1i": (."L1i cache" | split(" ") | .[0] + " " + .[1])}
          | . + {"cacheL2": (."L2 cache" | split(" ") | .[0] + " " + .[1])}
          | . + {"cacheL3": (."L3 cache" | split(" ") | .[0] + " " + .[1])}
          | {architecture, flags, cores, vendor, family, model, name, vulnerabilities, cacheL1d, cacheL1i, cacheL2, cacheL3}
        '
  )

  # Convert architecture
  _architecture=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.architecture')
  case $_architecture in
  x86_64) _architecture=amd64 ;;
  aarch64) _architecture=arm64 ;;
  *) FATAL "CPU architecture '$_architecture' is not supported" ;;
  esac
  [ "$_architecture" = "$ARCH" ] || FATAL "CPU architecture '$_architecture' does not match architecture '$ARCH'"

  # Convert vendor
  _vendor=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.vendor')
  case $_vendor in
  AuthenticAMD) _vendor=amd ;;
  GenuineIntel) _vendor=intel ;;
  *) FATAL "CPU vendor '$_vendor' not supported" ;;
  esac

  # Convert cache to bytes
  _cache_l1d=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.cacheL1d' | sed -e 's/B.*//' -e 's/[[:space:]]*//g' | numfmt --from=iec-i)
  _cache_l1i=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.cacheL1i' | sed -e 's/B.*//' -e 's/[[:space:]]*//g' | numfmt --from=iec-i)
  _cache_l2=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.cacheL2' | sed -e 's/B.*//' -e 's/[[:space:]]*//g' | numfmt --from=iec-i)
  _cache_l3=$(printf '%s\n' "$_cpu_info" | jq --raw-output '.cacheL3' | sed -e 's/B.*//' -e 's/[[:space:]]*//g' | numfmt --from=iec-i)

  # Update
  _cpu_info=$(
    printf '%s\n' "$_cpu_info" |
      jq \
        --arg architecture "$_architecture" \
        --arg vendor "$_vendor" \
        --arg cachel1d "$_cache_l1d" \
        --arg cachel1i "$_cache_l1i" \
        --arg cachel2 "$_cache_l2" \
        --arg cachel3 "$_cache_l3" \
        '
          .architecture = ($architecture | ascii_upcase)
          | .vendor = ($vendor | ascii_upcase)
          | .cacheL1d = ($cachel1d | tonumber)
          | .cacheL1i = ($cachel1i | tonumber)
          | .cacheL2 = ($cachel2 | tonumber)
          | .cacheL3 = ($cachel3 | tonumber)
        '
  )

  # Return
  RETVAL=$_cpu_info
}

# Read memory information
read_memory_info() {
  _memory_info=$(
    grep MemTotal /proc/meminfo |
      sed -e 's/MemTotal://g' -e 's/[[:space:]]*//g' -e 's/B.*//' |
      tr '[:lower:]' '[:upper:]' |
      numfmt --from iec
  )

  # Return
  RETVAL=$_memory_info
}

# Read storage(s) information
read_storages_info() {
  _storages_info=$(
    lsblk --bytes --json |
      jq \
        '
          .blockdevices
          | map(select((.type == "disk") and (.rm == false)))
          | map({name, size})
        '
  )

  # Return
  RETVAL=$_storages_info
}

# Read interface(s) information

### Aux methods ###

# Update method for valid interfaces list
update_valid_interfaces() {
  _valid_interfaces=$(echo "$_valid_interfaces" | jq \
    --arg iname "$_iname" \
    --arg speed "$_speed" \
    --arg wol "$_wol" \
    --arg address "$_address" \
    '
      if length == 0 then
        [{"name": $iname, "speed": ($speed | tonumber), "wol": ($wol | split("")), "address": $address, "controller": false}]
      else
        map(if .name == $iname then
          . + {"speed": ($speed | tonumber), "wol": ($wol | split("")), "address": $address, "controller": false}
        else
          .
        end)
        | if any(.name == $iname) then
            .
          else
            . + [{"name": $iname, "speed": ($speed | tonumber), "wol": ($wol | split("")), "address": $address, "controller": false}]
          end
      end
    ')

  DEBUG "Updated valid interfaces' list: $_valid_interfaces"
}

# Let the user choose the interface
select_interface() {

  # Check if the array is empty
  if [ -z "$_valid_interfaces" ] || [ "$_valid_interfaces" = "[]" ]; then
    if whiptail --title "No Valid Interfaces" --yesno "There are no valid interfaces available. Would you like to retry fetching the interface info?" 10 60; then
      read_interfaces_info
      return
    else
      FATAL "With no interfaces available it is not possible to go on with the installation. Aborting..."
    fi
  fi

  # Estract dat from the JSON array
  interfaces=$(echo "$_valid_interfaces" | jq -c '.[]')

  DEBUG "Interfaces' data: $interfaces"

  # Prepare data for whiptail
  whiptail_args=""
  first_option=true
  for interface in $interfaces; do
    name=$(echo "$interface" | jq -r '.name')
    address=$(echo "$interface" | jq -r '.address')
    speed=$(echo "$interface" | jq -r '.speed')
    wol=$(echo "$interface" | jq -r '.wol | join(", ")')
    controller_interface=$(echo "$interface" | jq -r '.controller')

    # Convert control interface into "true" and "false" data
    if [ "$controller_interface" -eq 1 ]; then
      controller_interface="true"
    else
      controller_interface="false"
    fi

    description="Address: $address, Speed: $speed, WOL: $wol, Controller: $controller_interface"

    if [ "$first_option" = true ]; then
      whiptail_args="$whiptail_args \"$name\" \"$description\" ON"
      first_option=false
    else
      whiptail_args="$whiptail_args \"$name\" \"$description\" OFF"
    fi
  done

  # Build the whiptail command for the radio list
  whiptail_command="whiptail --radiolist \"Choose a network interface\" 20 100 10 $whiptail_args 3>&1 1>&2 2>&3"

  selected_interface=$(sh -c "$whiptail_command")

  # Verify if the user made a choice
  if [ $? -eq 0 ]; then
    INFO "You chose interface $selected_interface."

    # Update the "controller" field to "true" for the selected interface into the JSON array
    _valid_interfaces=$(echo "$_valid_interfaces" | jq --arg sel "$selected_interface" 'map(if .name == $sel then .controller = true else . end)')

    DEBUG "Updated valid interfaces' list: $_valid_interfaces"
  else
    if (whiptail --title "No interface chosen" --yesno "No interface was chose, and one is required to proceed with reCluster installation. Do you want to start over?" 10 60); then
      select_interface
    else
      FATAL "You can't proceed with reCluster installation without choosing an interface. Aborting..."
    fi
  fi

}

#Interface management method
read_interfaces_info() {

  _interfaces_info=$(read_interfaces)
  #Valid interfaces
  _valid_interfaces='[]'

  ### Cycle over interfaces to obtain additional information ###

  echo "$_interfaces_info" | jq -r '.[] | "\(.name) \(.address)"' >$TMP_DIR/interfaces_info.txt

  while read -r _iname _address; do
    INFO "Processing $_iname with address $_address" # Name

    # Speed
    _speed=$($SUDO ethtool "$_iname" | grep Speed | sed -e 's/Speed://g' -e 's/[[:space:]]*//g' -e 's/b.*//')
    if [ -z "$_speed" ] || [ "$_speed" = "Unknown!" ]; then
      _speed=0
    elif [[ $_speed =~ [0-9]+[MG] ]]; then
      # If _speed is in the format '1000M' or '1G', extract the number
      _speed=$(echo $_speed | sed -e 's/[MG]//')
      DEBUG "Valid speed value $_speed read for interface $_iname ."
    else
      INFO "$_speed"
      whiptail --title "Speed value not valid." --msgbox "The speed value '$_speed' for the interface '$_iname' is not valid. The interface will be excluded." 10 60
      WARN "The speed value '$_speed' for the interface '$_iname' is not valid. The interface will be excluded."
      _speed=0
    fi

    _wol=$($SUDO ethtool "$_iname" | grep 'Wake-on' | grep -v 'Supports Wake-on' | sed -e 's/Wake-on://g' -e 's/[[:space:]]*//g')
    INFO "Wol: $_wol"
    case $_wol in
    *g* | *b*)
      # Supported WOL
      whiptail --title "Info" --msgbox "Wake-On-LAN already enabled for interface '$_iname'." 8 78
      INFO "Wake-On-LAN already enabled for interface '$_iname'."
      _supports_wol=1
      ;;
    *d*)
      whiptail --title "Wake-On-Lan " --msgbox "Wake-On-LAN for interface '$_iname' is disabled." 8 78
      INFO "Wake-On-LAN for interface '$_iname' is disabled."
      # Ask the user if he wants to enable the WOL
      if whiptail --title "Enable WOL" --yesno "Do you want to enable Wake-On-LAN for '$_iname'?" 8 78; then
        # Enabling Wake-On-LAN
        $SUDO ethtool -s "$_iname" wol g
        local exitstatus=$?
        if [ $exitstatus -ne 0 ]; then
          WARN "Failed to set WOL for interface '$_iname'. ethtool exit status: $exitstatus"
        else
          INFO "WOL command executed successfully for interface '$_iname'."
        fi

        # Verify if WOL is enabled
        _wol=$($SUDO ethtool "$_iname" | grep "Wake-on" | grep -v 'Supports Wake-on' | awk -F': ' '{print $2}')
        INFO "WOL: $_wol"
        if [ "$_wol" == "g" ]; then
          whiptail --title "WOL Enabled" --msgbox "Wake-on-LAN enabled for interface '$_iname'." 8 78
          INFO "Wake-on-LAN enabled for interface '$_iname'."
          _interfaces_info=$(read_interfaces)
          _supports_wol=1
        else
          whiptail --title "WOL Not Enabled" --msgbox "Failed to enable Wake-on-LAN for interface '$_iname'. Current WOL flag: $_wol" 8 78
          WARN "Wake-on-LAN enabling failed for interface '$_iname'. Current WOL flag: $_wol"
          _supports_wol=0
        fi
      else
        whiptail --title "WOL Not Enabled" --msgbox "Wake-on-LAN enabling cancelled for interface '$_iname'." 8 78
        WARN "Wake-on-LAN enabling cancelled for interface '$_iname'."
        _supports_wol=0
      fi
      ;;
    *)
      _supports_wol=0
      # Wake-on-LAN not supported
      whiptail --title "Info" --msgbox "Interface '$_iname' doesn't support Wake-on-LAN" 8 78
      ;;
    esac

    # # WoL
    # _wol=$($SUDO ethtool "$_iname" | grep 'Wake-on' | grep -v 'Supports Wake-on' | sed -e 's/Wake-on://g' -e 's/[[:space:]]*//g')
    # INFO "Wol: $_wol"
    # case $_wol in
    # *g* | *b*)
    #   # Supported WOL
    #   whiptail --title "Info" --msgbox "Wake-On-LAN already enabled for interface '$_iname'." 8 78
    #   INFO "Wake-On-LAN already enabled for interface '$_iname'."
    #   _supports_wol=1
    #   ;;
    # *d*)
    #   whiptail --title "Info" --msgbox "Wake-On-LAN for interface '$_iname' is disabled." 8 78
    #   INFO "Wake-On-LAN for interface '$_iname' is disabled."
    #   # Ask the user if he wants to enable the WOL
    #   if whiptail --title "Enable WOL" --yesno "Do you want to enable Wake-On-LAN for '$_iname'?" 8 78; then
    #     # Enabling Wake-On-LAN
    #     $SUDO ethtool -s "$_iname" wol g
    #     whiptail --title "WOL Enabled" --msgbox "Wake-on-LAN enabled for interface '$_iname'." 8 78
    #     INFO "Wake-on-LAN enabled for interface '$_iname'."
    #     _supports_wol=1
    #   else
    #     whiptail --title "WOL Not Enabled" --msgbox "Wake-on-LAN enabling failed for interface '$_iname'." 8 78
    #     WARN "Wake-on-LAN enabling failed for interface '$_iname'."
    #     _supports_wol=0
    #   fi
    #   ;;
    # *)
    #   _supports_wol=0
    #   # Wake-on-LAN not supported
    #   whiptail --title "Info" --msgbox "Interface '$_iname' doesn't support Wake-on-LAN" 8 78
    #   ;;
    # esac

    ### Cases management ###

    #1: No WOL support, but valid speed.
    if [ $_supports_wol -eq 0 ] && [ "$_speed" -ne 0 ]; then
      #1.1: The current node is an initiator node.
      if [ "$INIT_CLUSTER" = true ]; then
        if whiptail --title "Check Interface Support" --yesno "It seems like the interface '$_iname' is not supporting Wake-on-LAN or it can't be enabled. Since this machine is going to be configured as initiator node, and Wake-on-Lan is not needed, do you want to add this interface to the list of valid interfaces?" 12 78; then
          update_valid_interfaces
        else
          INFO "The current interface '$_iname' has been excluded as the user marked it as not valid."
        fi
      fi
    #2: WOL support and valid speed, valid interface.
    elif [ $_supports_wol -eq 1 ] && [ "$_speed" -ne 0 ]; then
      if whiptail --title "Check Interface Support" --yesno "The interface '$_iname' is supporting Wake-on-LAN, and appears to be perfectly valid to be used as node management interface. Do you want to add it to the list of valid interfaces?" 12 78; then
        update_valid_interfaces
      else
        INFO "The current interface '$_iname' has been excluded by the user."
      fi
    #3: No valid speed, can't use the interface.
    elif [ "$_speed" -eq 0 ]; then
      whiptail --title "Info" --msgbox "Interface '$_iname' is not valid (unable to read speed value) and it is going to be excluded." 8 78
      INFO "Interface '$_iname' is not valid (unable to read speed value) and it is going to be excluded."
    fi
  done <$TMP_DIR/interfaces_info.txt
  rm $TMP_DIR/interfaces_info.txt

  INFO "Valid interfaces before selection: $_valid_interfaces".

  select_interface

  # Return
  RETVAL=$_valid_interfaces
}

# Execute CPU benchmark
run_cpu_bench() {
  _run_cpu_bench() {
    $SYSBENCH_PATH --time="$BENCH_TIME" --threads="$1" cpu run |
      grep 'events per second' |
      sed -e 's/events per second://g' -e 's/[[:space:]]*//g' |
      xargs printf "%.0f"
  }
  _threads=$(grep -c ^processor /proc/cpuinfo)

  # Single-thread
  DEBUG "Running CPU benchmark in single-thread (1)"
  _single_thread=$(_run_cpu_bench 1)
  DEBUG "CPU benchmark in single-thread (1): $_single_thread"

  # Multi-thread
  DEBUG "Running CPU benchmark in multi-thread ($_threads)"
  _multi_thread=$(_run_cpu_bench "$_threads")
  DEBUG "CPU benchmark in multi-thread ($_threads): $_multi_thread"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --argjson singleThread "$_single_thread" \
      --argjson multiThread "$_multi_thread" \
      '
        {
          "singleThread": $singleThread,
          "multiThread": $multiThread
        }
      '
  )
}

# Execute memory benchmark
run_memory_bench() {
  _run_memory_bench() {
    _memory_output=$($SYSBENCH_PATH --time="$BENCH_TIME" --memory-oper="$1" --memory-access-mode="$2" memory run |
      grep 'transferred' |
      sed -e 's/.*(\(.*\))/\1/' -e 's/B.*//' -e 's/[[:space:]]*//g' |
      numfmt --from=iec-i)
    printf '%s\n' $((_memory_output * 8))
  }

  # Read sequential
  DEBUG "Running memory benchmark in read sequential"
  _read_seq=$(_run_memory_bench read seq)
  DEBUG "Memory benchmark in read sequential: $_read_seq"

  # Read random
  DEBUG "Running memory benchmark in read random"
  _read_rand=$(_run_memory_bench read rnd)
  DEBUG "Memory benchmark in read random: $_read_rand"

  # Write sequential
  DEBUG "Running memory benchmark in write sequential"
  _write_seq=$(_run_memory_bench write seq)
  DEBUG "Memory benchmark in write sequential: $_write_seq"
  # Write random
  DEBUG "Running memory benchmark in write random"
  _write_rand=$(_run_memory_bench write rnd)
  DEBUG "Memory benchmark in write random: $_write_rand"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg readSeq "$_read_seq" \
      --arg readRand "$_read_rand" \
      --arg writeSeq "$_write_seq" \
      --arg writeRand "$_write_rand" \
      '
        {
          "read": {
            "sequential": ($readSeq | tonumber),
            "random": ($readRand | tonumber)
          },
          "write": {
            "sequential": ($writeSeq | tonumber),
            "random": ($writeRand | tonumber)
          }
        }
      '
  )
}

# Execute storage(s) benchmark
run_storages_bench() {
  _run_storages_bench() {
    # Io operation
    _io_opt=
    case $1 in
    read) _io_opt=$1 ;;
    write)
      _io_opt=written
      # Prepare write benchmark
      $SYSBENCH_PATH fileio cleanup >/dev/null
      $SYSBENCH_PATH fileio prepare >/dev/null
      ;;
    esac

    _io_output=$($SYSBENCH_PATH --time="$BENCH_TIME" --file-test-mode="$2" --file-io-mode="$3" fileio run | grep "$_io_opt, ")
    _io_throughput_value=$(printf '%s\n' "$_io_output" | sed -e 's/^.*: //' -e 's/[[:space:]]*//g')
    _io_throughput_unit=$(printf '%s\n' "$_io_output" | sed -e 's/.*,\(.*\)B\/s.*/\1/' -e 's/[[:space:]]*//g')

    _io_throughput=$(printf "%s%s\n" "$_io_throughput_value" "$_io_throughput_unit" | numfmt --from=iec-i)
    printf '%s\n' $((_io_throughput * 8))
  }

  # TODO Benchmark per storage

  # Prepare read benchmark
  DEBUG "Preparing storage(s) read benchmark"
  $SYSBENCH_PATH fileio cleanup >/dev/null
  $SYSBENCH_PATH fileio prepare >/dev/null

  # Read sequential synchronous
  DEBUG "Running storage(s) benchmark in read sequential synchronous"
  _read_seq_sync=$(_run_storages_bench read seqrd sync)
  DEBUG "Storage(s) benchmark in read sequential synchronous: $_read_seq_sync"

  # Read sequential asynchronous
  DEBUG "Running storage(s) benchmark in read sequential asynchronous"
  _read_seq_async=$(_run_storages_bench read seqrd async)
  DEBUG "Storage(s) benchmark in read sequential asynchronous: $_read_seq_async"

  # Read random synchronous
  DEBUG "Running storage(s) benchmark in read random synchronous"
  _read_rand_sync=$(_run_storages_bench read rndrd sync)
  DEBUG "Storage(s) benchmark in read random synchronous: $_read_rand_sync"

  # Read random asynchronous
  DEBUG "Running storage(s) benchmark in read random asynchronous"
  _read_rand_async=$(_run_storages_bench read rndrd async)
  DEBUG "Storage(s) benchmark in read random asynchronous: $_read_rand_async"

  # Write sequential synchronous
  DEBUG "Running storage(s) benchmark in write sequential synchronous"
  _write_seq_sync=$(_run_storages_bench write seqwr sync)
  DEBUG "Storage(s) benchmark in write sequential synchronous: $_write_seq_sync"

  # Write sequential asynchronous
  DEBUG "Running storage(s) benchmark in write sequential asynchronous"
  _write_seq_async=$(_run_storages_bench write seqwr async)
  DEBUG "Storage(s) benchmark in write sequential asynchronous: $_write_seq_async"

  # Write random synchronous
  DEBUG "Running storage(s) benchmark in write random synchronous"
  _write_rand_sync=$(_run_storages_bench write rndwr sync)
  DEBUG "Storage(s) benchmark in write random synchronous: $_write_rand_sync"

  # Write random asynchronous
  DEBUG "Running storage(s) benchmark in write random asynchronous"
  _write_rand_async=$(_run_storages_bench write rndwr async)
  DEBUG "Storage(s) benchmark in write random asynchronous: $_write_rand_async"

  # Clean
  DEBUG "Cleaning storage(s) benchmark"
  $SYSBENCH_PATH fileio cleanup >/dev/null

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg readSeqSync "$_read_seq_sync" \
      --arg readSeqAsync "$_read_seq_async" \
      --arg readRandSync "$_read_rand_sync" \
      --arg readRandAsync "$_read_rand_async" \
      --arg writeSeqSync "$_write_seq_sync" \
      --arg writeSeqAsync "$_write_seq_async" \
      --arg writeRandSync "$_write_rand_sync" \
      --arg writeRandAsync "$_write_rand_async" \
      '
        {
          "read": {
            "sequential": {
              "synchronous": ($readSeqSync | tonumber),
              "asynchronous": ($readSeqAsync | tonumber),
            },
            "random": {
              "synchronous": ($readRandSync | tonumber),
              "asynchronous": ($readRandAsync | tonumber),
            }
          },
          "write": {
            "sequential": {
              "synchronous": ($writeSeqSync | tonumber),
              "asynchronous": ($writeSeqAsync | tonumber),
            },
            "random": {
              "synchronous": ($writeRandSync | tonumber),
              "asynchronous": ($writeRandAsync | tonumber),
            }
          }
        }
      '
  )
}

# Read CPU power consumption
read_cpu_power_consumption() {
  _run_cpu_bench() {
    $SYSBENCH_PATH --time=0 --threads="$1" cpu run >/dev/null &
    read_power_consumption "$!"
  }
  _threads=$(grep -c ^processor /proc/cpuinfo)

  # Idle
  DEBUG "Reading CPU power consumption in idle"
  read_power_consumption
  _idle=$RETVAL
  DEBUG "CPU power consumption in idle:" "$_idle"

  # Multi-thread
  DEBUG "Reading CPU power consumption in multi-thread ($_threads)"
  _run_cpu_bench "$_threads"
  _multi_thread=$RETVAL
  DEBUG "CPU power consumption in multi-thread ($_threads):" "$_multi_thread"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --argjson idle "$_idle" \
      --argjson multi "$_multi_thread" \
      '
        {
          "idle": $idle,
          "multiThread": $multi
        }
      '
  )
}

# Wait K8s reachability
wait_k8s_reachability() {
  assert_cmd kubectl

  _wait_k8s_max_attempts_default=40
  _wait_k8s_max_attempts=$_wait_k8s_max_attempts_default
  _wait_k8s_sleep=3
  _node_name=$($SUDO grep 'node-name:' /etc/rancher/k3s/config.yaml | sed -e 's/node-name://g' -e 's/[[:space:]]*//' -e 's/^"//' -e 's/"$//')

  INFO "Waiting K8s reachability"

  DEBUG "Waiting K8s control plane reachability"
  _wait_k8s_max_attempts=$_wait_k8s_max_attempts_default
  while [ "$_wait_k8s_max_attempts" -gt 0 ]; do
    if $SUDO kubectl cluster-info >/dev/null 2>&1; then
      DEBUG "K8s control plane is reachable"
      break
    fi

    DEBUG "K8s control plane is not reachable, sleeping $_wait_k8s_sleep seconds"
    sleep "$_wait_k8s_sleep"
    _wait_k8s_max_attempts=$((_wait_k8s_max_attempts = _wait_k8s_max_attempts - 1))
  done
  [ "$_wait_k8s_max_attempts" -gt 0 ] || FATAL "K8s control plane is not reachable, maximum attempts reached"

  DEBUG "Waiting K8s node '$_node_name' reachability"
  _wait_k8s_max_attempts=$_wait_k8s_max_attempts_default
  while [ "$_wait_k8s_max_attempts" -gt 0 ]; do
    if $SUDO kubectl get node "$_node_name" 2>&1 | grep -q -E "$_node_name\s+Ready\s+"; then
      DEBUG "K8s node is reachable"
      break
    fi

    DEBUG "K8s node '$_node_name' is not reachable, sleeping $_wait_k8s_sleep seconds"
    sleep "$_wait_k8s_sleep"
    _wait_k8s_max_attempts=$((_wait_k8s_max_attempts = _wait_k8s_max_attempts - 1))
  done
  [ "$_wait_k8s_max_attempts" -gt 0 ] || FATAL "K8s node '$_node_name' is not reachable, maximum attempts reached"

  DEBUG "Waiting K8s kube-dns reachability"
  _wait_k8s_max_attempts=$_wait_k8s_max_attempts_default
  while [ "$_wait_k8s_max_attempts" -gt 0 ]; do
    if $SUDO kubectl get pod --selector k8s-app=kube-dns --namespace kube-system 2>&1 | grep -q -E '\s+Running\s+'; then
      DEBUG "K8s kube-dns is reachable"
      break
    fi

    DEBUG "K8s kube-dns is not reachable, sleeping $_wait_k8s_sleep seconds"
    sleep "$_wait_k8s_sleep"
    _wait_k8s_max_attempts=$((_wait_k8s_max_attempts = _wait_k8s_max_attempts - 1))
  done
  [ "$_wait_k8s_max_attempts" -gt 0 ] || FATAL "K8s kube-dns is not reachable, maximum attempts reached"

  DEBUG "K8s is reachable"
}

# Wait database reachability
wait_database_reachability() {
  _wait_database_max_attempts=40
  _wait_database_sleep=3

  INFO "Waiting database reachability"
  while [ "$_wait_database_max_attempts" -gt 0 ]; do
    if $SUDO su postgres -c "pg_isready" >/dev/null 2>&1; then
      DEBUG "Database is reachable"
      break
    fi

    DEBUG "Database is not reachable, sleeping $_wait_database_sleep seconds"
    sleep "$_wait_database_sleep"
    _wait_database_max_attempts=$((_wait_database_max_attempts = _wait_database_max_attempts - 1))
  done
  [ "$_wait_database_max_attempts" -gt 0 ] || FATAL "Database is not reachable, maximum attempts reached"
}

# Wait server reachability
wait_server_reachability() {
  _wait_server_max_attempts=40
  _wait_server_sleep=3
  _server_url=$(printf '%s\n' "$CONFIG" | jq --exit-status --raw-output '.recluster.server')

  INFO "Waiting server reachability"
  while [ "$_wait_server_max_attempts" -gt 0 ]; do
    if (assert_url_reachability "$_server_url/health" >/dev/null 2>&1); then
      DEBUG "Server is reachable"
      break
    fi

    DEBUG "Server is not reachable, sleeping $_wait_server_sleep seconds"
    sleep "$_wait_server_sleep"
    _wait_server_max_attempts=$((_wait_server_max_attempts = _wait_server_max_attempts - 1))
  done
  [ "$_wait_server_max_attempts" -gt 0 ] || FATAL "Server is not reachable, maximum attempts reached"
}

# Register current node
node_registration() {
  _req_data=$(
    jq \
      --null-input \
      --compact-output \
      --argjson data "$NODE_FACTS" \
      '
        {
          "query": "mutation ($data: CreateNodeInput!) { createNode(data: $data) }",
          "variables": { "data": $data }
        }
      '
  )

  INFO "Registering node"

  # Send request
  send_server_request "$_req_data"
  _res_data=$RETVAL

  # Extract token
  _token=$(printf '%s\n' "$_res_data" | jq --raw-output '.data.createNode')

  # Decode token
  decode_token "$_token"
  _token_decoded=$RETVAL

  # Success
  INFO "Successfully registered node"

  # Return
  RETVAL=$(
    jq \
      --null-input \
      --arg token "$_token" \
      --argjson decoded "$_token_decoded" \
      '
        {
          "token": $token,
          "decoded": $decoded
        }
      '
  )
}

################################################################################################################################

# Parse command line arguments
# @param $@ Arguments
parse_args() {
  while [ $# -gt 0 ]; do
    # Number of shift
    _shifts=1

    case $1 in
    --admin-username)
      # Admin username
      parse_args_assert_value "$@"

      ADMIN_USERNAME=$2
      _shifts=2
      ;;
    --admin-password)
      # Admin password
      parse_args_assert_value "$@"

      ADMIN_PASSWORD=$2
      _shifts=2
      ;;
    --airgap)
      # Airgap environment
      AIRGAP_ENV=true
      ;;
    --autoscaler-username)
      # Autoscaler username
      parse_args_assert_value "$@"

      AUTOSCALER_USERNAME=$2
      _shifts=2
      ;;
    --autoscaler-password)
      # Autoscaler password
      parse_args_assert_value "$@"

      AUTOSCALER_PASSWORD=$2
      _shifts=2
      ;;
    --autoscaler-version)
      #Autoscaler version
      parse_args_assert_value "$@"

      AUTOSCALER_VERSION=$2
      _shifts=2
      ;;
    --bench-time)
      # Benchmark time
      parse_args_assert_value "$@"
      parse_args_assert_positive_integer "$1" "$2"

      BENCH_TIME=$2
      _shifts=2
      ;;
    --certs-dir)
      # Certificates directory
      parse_args_assert_value "$@"

      RECLUSTER_CERTS_DIR=$2
      _shifts=2
      ;;
    --config-file)
      # Configuration file
      parse_args_assert_value "$@"

      CONFIG_FILE=$2
      _shifts=2
      ;;
    --help)
      # Display help message and exit
      show_help
      exit 0
      ;;
    --init-cluster)
      # Initialize cluster
      INIT_CLUSTER=true
      ;;
    --k3s-config-file)
      # K3s configuration file
      parse_args_assert_value "$@"

      K3S_CONFIG_FILE=$2
      _shifts=2
      ;;
    --k3s-registry-config-file)
      # K3s registry configuration file
      parse_args_assert_value "$@"

      K3S_REGISTRY_CONFIG_FILE=$2
      _shifts=2
      ;;
    --k3s-version)
      # K3s version
      parse_args_assert_value "$@"

      K3S_VERSION=$2
      _shifts=2
      ;;
    --node-exporter-config-file)
      # Node exporter configuration file
      parse_args_assert_value "$@"

      NODE_EXPORTER_CONFIG_FILE=$2
      _shifts=2
      ;;
    --node-exporter-version)
      # Node exporter version
      parse_args_assert_value "$@"

      NODE_EXPORTER_VERSION=$2
      _shifts=2
      ;;
    --pc-device-api)
      # Power consumption device api url
      parse_args_assert_value "$@"

      PC_DEVICE_API=$2
      _shifts=2
      ;;
    --pc-interval)
      # Power consumption interval
      parse_args_assert_value "$@"
      parse_args_assert_positive_integer "$1" "$2"

      PC_INTERVAL=$2
      _shifts=2
      ;;
    --pc-time)
      # Power consumption time
      parse_args_assert_value "$@"
      parse_args_assert_positive_integer "$1" "$2"

      PC_TIME=$2
      _shifts=2
      ;;
    --pc-warmup)
      # Power consumption warmup time
      parse_args_assert_value "$@"
      parse_args_assert_positive_integer "$1" "$2"

      PC_WARMUP=$2
      _shifts=2
      ;;
    --server-env-file)
      # Server environment file
      parse_args_assert_value "$@"

      RECLUSTER_SERVER_ENV_FILE=$2
      _shifts=2
      ;;
    --ssh-authorized-keys-file)
      # SSH authorized keys file
      parse_args_assert_value "$@"

      SSH_AUTHORIZED_KEYS_FILE=$2
      _shifts=2
      ;;
    --ssh-config-file)
      # SSH configuration file
      parse_args_assert_value "$@"

      SSH_CONFIG_FILE=$2
      _shifts=2
      ;;
    --sshd-config-file)
      # SSH server configuration file
      parse_args_assert_value "$@"

      SSHD_CONFIG_FILE=$2
      _shifts=2
      ;;
    --user)
      # User
      parse_args_assert_value "$@"

      USER=$2
      _shifts=2
      ;;
    *)
      # Commons
      parse_args_commons "$@"
      _shifts=$RETVAL
      ;;
    esac

    # Shift arguments
    while [ "$_shifts" -gt 0 ]; do
      shift
      _shifts=$((_shifts = _shifts - 1))
    done
  done
}

# Verify system
verify_system() {
  # Architecture
  ARCH=$(uname -m)
  case $ARCH in
  amd64 | x86_64) ARCH=amd64 ;;
  arm64 | aarch64) ARCH=arm64 ;;
  armv5*) ARCH=armv5 ;;
  armv6*) ARCH=armv6 ;;
  armv7*) ARCH=armv7 ;;
  s390x) ARCH=s390x ;;
  *) FATAL "Architecture '$ARCH' is not supported" ;;
  esac

  # Commands
  assert_cmd bc
  assert_cmd cp
  assert_cmd cut
  assert_cmd date
  assert_cmd ethtool
  assert_cmd grep
  assert_cmd id
  assert_cmd ip
  assert_cmd jq
  assert_cmd lscpu
  assert_cmd lsblk
  assert_cmd mktemp
  assert_cmd numfmt
  assert_cmd read
  assert_cmd sed
  assert_cmd ssh-keygen
  assert_cmd sudo
  #assert_cmd sysbench
  check_sysbench
  assert_cmd tar
  assert_cmd tee
  assert_cmd tr
  assert_cmd uname
  assert_cmd yq
  if [ "$INIT_CLUSTER" = true ]; then
    assert_cmd docker
    assert_cmd inotifywait
    assert_cmd node
    assert_cmd npm
    assert_cmd pg_ctl
    assert_cmd pg_isready

    assert_user postgres
  fi
  # Spinner
  assert_spinner
  # User
  assert_user
  # Init system
  assert_init_system
  # Timezone
  assert_timezone
  # Downloader command
  assert_downloader
  # Check power consumption device reachability
  assert_url_reachability "$PC_DEVICE_API"

  # Directories
  [ ! -d "$RECLUSTER_ETC_DIR" ] || FATAL "Directory '$RECLUSTER_ETC_DIR' already exists"
  [ ! -d "$RECLUSTER_OPT_DIR" ] || FATAL "Directory '$RECLUSTER_OPT_DIR' already exists"
  # Certificates
  [ -d "$RECLUSTER_CERTS_DIR" ] || FATAL "Certificates directory '$RECLUSTER_CERTS_DIR' does not exists"

  # Server env
  [ -f "$RECLUSTER_SERVER_ENV_FILE" ] || FATAL "Server environment file '$RECLUSTER_SERVER_ENV_FILE' does not exists"

  # Configuration
  [ -f "$CONFIG_FILE" ] || FATAL "Configuration file '$CONFIG_FILE' does not exists"
  INFO "Reading configuration file '$CONFIG_FILE'"
  CONFIG=$(yq e --output-format=json --no-colors '.' "$CONFIG_FILE") || FATAL "Error reading configuration file '$CONFIG_FILE'"
  DEBUG "Configuration:" "$CONFIG"
  # Kind
  _kind=$(printf '%s\n' "$CONFIG" | jq --exit-status --raw-output '.kind') || FATAL "Configuration requires 'kind'"
  [ "$_kind" = "controller" ] || [ "$_kind" = "worker" ] || FATAL "Configuration 'kind' must be 'controller' or 'worker' but '$_kind' found"
  # reCluster server URL
  _recluster_server_url=$(printf '%s\n' "$CONFIG" | jq --exit-status --raw-output '.recluster.server') || FATAL "Configuration requires 'recluster.server'"
  [ "$INIT_CLUSTER" = true ] || assert_url_reachability "$_recluster_server_url/health"

  # K3s configuration
  [ -f "$K3S_CONFIG_FILE" ] || FATAL "K3s configuration file '$K3S_CONFIG_FILE' does not exists"
  INFO "Reading K3s configuration file '$K3S_CONFIG_FILE'"
  K3S_CONFIG=$(yq e --output-format=json --no-colors '.' "$K3S_CONFIG_FILE") || FATAL "Error reading K3s configuration file '$K3S_CONFIG_FILE'"
  DEBUG "K3s configuration:" "$K3S_CONFIG"
  # K3s requires server and token if worker or controller (no init cluster)
  if { [ "$_kind" = "worker" ] || { [ "$_kind" = "controller" ] && [ "$INIT_CLUSTER" = false ]; }; } && [ "$(printf '%s\n' "$K3S_CONFIG" | jq --raw-output 'any(select(.server and .token))')" = false ]; then
    FATAL "K3s configuration requires 'server' and 'token'"
  fi
  # K3s node name
  [ "$(printf '%s\n' "$K3S_CONFIG" | jq --raw-output 'any(.; select(."node-name"))')" = false ] || {
    WARN "K3s configuration 'node-name' must not be provided"
    K3S_CONFIG=$(printf '%s\n' "$K3S_CONFIG" | jq 'del(."node-name")')
  }
  # K3s node id
  [ "$(printf '%s\n' "$K3S_CONFIG" | jq --raw-output 'any(.; select(."with-node-id"))')" = false ] || {
    WARN "K3s configuration 'with-node-id' must not be provided"
    K3S_CONFIG=$(printf '%s\n' "$K3S_CONFIG" | jq 'del(."with-node-id")')
  }
  # K3s write-kubeconfig-mode
  [ "$(printf '%s\n' "$K3S_CONFIG" | jq --raw-output 'any(.; select(."write-kubeconfig-mode"))')" = false ] || {
    WARN "K3s configuration 'write-kubeconfig-mode' must not be provided"
    K3S_CONFIG=$(printf '%s\n' "$K3S_CONFIG" | jq 'del(."write-kubeconfig-mode")')
  }
  # K3s registry configuration file
  [ -f "$K3S_REGISTRY_CONFIG_FILE" ] || FATAL "K3s registry configuration file '$K3S_REGISTRY_CONFIG_FILE' does not exists"

  # Node exporter configuration
  [ -f "$NODE_EXPORTER_CONFIG_FILE" ] || FATAL "Node exporter configuration file '$NODE_EXPORTER_CONFIG_FILE' does not exists"
  INFO "Reading Node exporter configuration file '$NODE_EXPORTER_CONFIG_FILE'"
  NODE_EXPORTER_CONFIG=$(yq e --output-format=json --no-colors '.' "$NODE_EXPORTER_CONFIG_FILE") || FATAL "Error reading Node exporter configuration file '$NODE_EXPORTER_CONFIG_FILE'"
  DEBUG "Node exporter configuration:" "$NODE_EXPORTER_CONFIG"

  # SSH configuration file
  [ -f "$SSH_CONFIG_FILE" ] || FATAL "SSH configuration file '$SSH_CONFIG_FILE' does not exists"
  # SSH server configuration file
  [ -f "$SSHD_CONFIG_FILE" ] || FATAL "SSH server configuration file '$SSHD_CONFIG_FILE' does not exists"
  # SSH authorized keys file
  [ -f "$SSH_AUTHORIZED_KEYS_FILE" ] || FATAL "SSH authorized keys file '$SSH_AUTHORIZED_KEYS_FILE' does not exists"
  [ -s "$SSH_AUTHORIZED_KEYS_FILE" ] || FATAL "SSH authorized keys file '$SSH_AUTHORIZED_KEYS_FILE' is empty"
  while read -r _ssh_authorized_key; do
    printf '%s\n' "$_ssh_authorized_key" | ssh-keygen -l -f - >/dev/null 2>&1 || FATAL "SSH authorized key '$_ssh_authorized_key' is not valid"
  done <<EOF
$(cat "$SSH_AUTHORIZED_KEYS_FILE")
EOF

  # Cluster initialization
  if [ "$INIT_CLUSTER" = true ]; then
    # Password: 1 uppercase, 1 symbol, 1 number, length between 8 and 32
    _password_regex='^.{8,32}$'

    [ "$_kind" = controller ] || FATAL "Cluster initialization requires configuration 'kind' value 'controller' but '$_kind' found"
    [ "$(printf '%s\n' "$K3S_CONFIG" | jq --exit-status 'any(.; ."cluster-init" == true)')" = true ] || WARN "Cluster initialization K3s configuration 'cluster-init' not found or set to 'false'"

    # Admin password
    printf '%s\n' "$ADMIN_PASSWORD" | grep -q -E "$_password_regex" || FATAL "Admin password '$ADMIN_PASSWORD' does not match regex '$_password_regex'"

    # Autoscaler password
    printf '%s\n' "$AUTOSCALER_PASSWORD" | grep -q -E "$_password_regex" || FATAL "Autoscaler password '$AUTOSCALER_PASSWORD' does not match regex '$_password_regex'"
    # Autoscaler version
    if [ "$AUTOSCALER_VERSION" = latest ]; then
      INFO "Finding Autoscaler latest release"
      AUTOSCALER_VERSION=$(download_print 'https://api.github.com/repos/carlocorradini/autoscaler/releases/latest' | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
      INFO "Autoscaler latest release is '$AUTOSCALER_VERSION'"
    fi
    AUTOSCALER_DIR="$DIRNAME/dependencies/autoscaler/$AUTOSCALER_VERSION"
    [ -d "$AUTOSCALER_DIR" ] || FATAL "Autoscaler directory '$AUTOSCALER_DIR' does not exists"
  fi

  # Airgap
  if [ "$AIRGAP_ENV" = true ]; then
    [ "$AUTOSCALER_VERSION" != latest ] || FATAL "Autoscaler version '$AUTOSCALER_VERSION' not available in Air-Gap environment"
    [ "$K3S_VERSION" != latest ] || FATAL "K3s version '$K3S_VERSION' not available in Air-Gap environment"
    [ "$NODE_EXPORTER_VERSION" != latest ] || FATAL "Node exporter version '$NODE_EXPORTER_VERSION' not available in Air-Gap environment"
  fi

  # Sudo
  if [ "$(id -u)" -eq 0 ]; then
    WARN "Already running as 'root'"
    SUDO=
  else
    WARN "Requesting 'root' privileges"
    SUDO=sudo
    $SUDO --reset-timestamp
    $SUDO true || FATAL "Failed to obtain 'root' privileges"
  fi

  # Interfaces
  _interfaces=$(read_interfaces)
  [ "$(printf '%s\n' "$_interfaces" | jq --raw-output 'length')" -ge 1 ] || FATAL "No interfaces found"
  while read -r _interface; do
    # Name
    _iname=$(printf '%s\n' "$_interface" | jq --raw-output '.name')
  done <<EOF
$(printf '%s\n' "$_interfaces" | jq --compact-output '.[]')
EOF
}

# Setup system
setup_system() {
  # Create uninstall
  create_uninstall

  # Temporary directory
  TMP_DIR=$(mktemp --directory -t recluster.XXXXXXXX)
  DEBUG "Created temporary directory '$TMP_DIR'"

  # Directories
  DEBUG "Creating directory '$RECLUSTER_ETC_DIR'"
  $SUDO mkdir -p "$RECLUSTER_ETC_DIR" || FATAL "Error creating directory '$RECLUSTER_ETC_DIR'"
  DEBUG "Creating directory '$RECLUSTER_OPT_DIR'"
  $SUDO mkdir -p "$RECLUSTER_OPT_DIR" || FATAL "Error creating directory '$RECLUSTER_OPT_DIR'"

  # SSH
  setup_ssh

  # Certificates
  setup_certificates

  # Cluster initialization
  if [ "$INIT_CLUSTER" = true ]; then
    spinner_start "Preparing Cluster initialization"

    # Docker
    DEBUG "Adding user '$USER' to group 'docker'"
    $SUDO addgroup "$USER" docker
    case $INIT_SYSTEM in
    openrc)
      INFO "openrc: Starting Docker service"
      $SUDO rc-service docker restart
      ;;
    systemd)
      INFO "systemd: Starting Docker service"
      $SUDO systemctl restart docker
      ;;
    *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
    esac

    spinner_stop
  fi

  # Airgap
  if [ "$AIRGAP_ENV" = true ]; then
    spinner_start "Preparing Air-Gap environment"

    # Directories
    _dep_dir="$DIRNAME/dependencies"
    _k3s_dep_dir="$_dep_dir/k3s/$K3S_VERSION"
    _node_exporter_dep_dir="$_dep_dir/node_exporter/$NODE_EXPORTER_VERSION"

    # Architecture
    _k3s_bin_suffix=
    _k3s_images_suffix=
    case $ARCH in
    amd64)
      _k3s_bin_suffix=
      _k3s_images_suffix=amd64
      ;;
    arm64)
      _k3s_bin_suffix=-arm64
      _k3s_images_suffix=arm64
      ;;
    arm*)
      _k3s_bin_suffix=-armhf
      _k3s_images_suffix=arm
      ;;
    s390x)
      _k3s_bin_suffix=-s390x
      _k3s_images_suffix=s390x
      ;;
    *) FATAL "Unknown architecture '$ARCH'" ;;
    esac

    # General
    _k3s_airgap_images_name="k3s-airgap-images-$_k3s_images_suffix"
    _node_exporter_release_name=node_exporter-$(printf '%s\n' "$NODE_EXPORTER_VERSION" | sed 's/^v//').linux-$ARCH

    # Globals
    AIRGAP_K3S_BIN="$TMP_DIR/k3s.bin"
    AIRGAP_K3S_IMAGES="$TMP_DIR/$_k3s_airgap_images_name.tar.gz"
    AIRGAP_NODE_EXPORTER_BIN="$TMP_DIR/node_exporter.bin"

    # Resources
    _k3s_dep_bin="$_k3s_dep_dir/k3s$_k3s_bin_suffix"
    _k3s_dep_images_tar="$_k3s_dep_dir/$_k3s_airgap_images_name.tar.gz"
    _node_exporter_dep_tar="$_node_exporter_dep_dir/$_node_exporter_release_name.tar.gz"

    # Check directories
    [ -d "$_k3s_dep_dir" ] || FATAL "K3s dependency directory '$_k3s_dep_dir' not found"
    [ -d "$_node_exporter_dep_dir" ] || FATAL "Node exporter dependency directory '$_node_exporter_dep_dir' not found"
    # Check resources
    [ -f "$_k3s_dep_bin" ] || FATAL "K3s dependency binary '$_k3s_dep_bin' not found"
    [ -f "$_k3s_dep_images_tar" ] || FATAL "K3s dependency images tar '$_k3s_dep_images_tar' not found"
    [ -f "$_node_exporter_dep_tar" ] || FATAL "Node exporter dependency tar '$_node_exporter_dep_tar' not found"

    # Extract Node exporter
    DEBUG "Extracting Node exporter archive '$_node_exporter_dep_tar'"
    tar xzf "$_node_exporter_dep_tar" -C "$TMP_DIR" --strip-components 1 "$_node_exporter_release_name/node_exporter" || FATAL "Error extracting Node exporter archive '$_node_exporter_dep_tar'"

    # Move to temporary directory
    cp "$_k3s_dep_bin" "$AIRGAP_K3S_BIN"
    cp "$_k3s_dep_images_tar" "$AIRGAP_K3S_IMAGES"
    mv "$TMP_DIR/node_exporter" "$AIRGAP_NODE_EXPORTER_BIN"

    # Permissions
    $SUDO chown root:root "$AIRGAP_K3S_BIN"
    $SUDO chmod 755 "$AIRGAP_K3S_BIN"
    $SUDO chown root:root "$AIRGAP_NODE_EXPORTER_BIN"
    $SUDO chmod 755 "$AIRGAP_NODE_EXPORTER_BIN"

    spinner_stop
  fi
}

# Read system information
read_system_info() {
  spinner_start "Reading system information"

  # CPU
  read_cpu_info
  _cpu_info=$RETVAL
  DEBUG "CPU info:" "$_cpu_info"
  INFO "CPU is '$(printf '%s\n' "$_cpu_info" | jq --raw-output .name)'"

  # Memory
  read_memory_info
  _memory_info=$RETVAL
  INFO "Memory is '$(printf '%s\n' "$_memory_info" | numfmt --to=iec-i)B'"

  # Storage(s)
  read_storages_info
  _storages_info=$RETVAL
  DEBUG "Storage(s) info:" "$_storages_info"
  _storages_info_msg="Storage(s) found $(printf '%s\n' "$_storages_info" | jq --raw-output 'length'):"
  while read -r _storage_info; do
    _storages_info_msg="$_storages_info_msg\n\t'$(printf '%s\n' "$_storage_info" | jq --raw-output .name)' of '$(printf '%s\n' "$_storage_info" | jq --raw-output .size | numfmt --to=iec-i)B'"
  done <<EOF
$(printf '%s\n' "$_storages_info" | jq --compact-output '.[]')
EOF
  INFO "$_storages_info_msg"

  # Interface(s)
  read_interfaces_info
  _interfaces_info=$RETVAL
  DEBUG "Interface(s) info:" "$_interfaces_info"
  INFO "Interface(s) found $(printf '%s\n' "$_interfaces_info" | jq --raw-output 'length'):
    $(printf '%s\n' "$_interfaces_info" | jq --raw-output '.[] | "\t'\''\(.name)'\'' at '\''\(.address)'\''"')"

  spinner_stop

  # Update
  NODE_FACTS=$(
    printf '%s\n' "$NODE_FACTS" |
      jq \
        --argjson cpu "$_cpu_info" \
        --argjson memory "$_memory_info" \
        --argjson storages "$_storages_info" \
        --argjson interfaces "$_interfaces_info" \
        '
          .cpu = $cpu
          | .memory = $memory
          | .storages = $storages
          | .interfaces = $interfaces
        '
  )
}

# Execute benchmarks
run_benchmarks() {
  spinner_start "Benchmarking"

  # CPU
  INFO "CPU benchmark"
  run_cpu_bench
  _cpu_benchmark=$RETVAL
  DEBUG "CPU benchmark:" "$_cpu_benchmark"

  # Memory
  INFO "Memory benchmark"
  run_memory_bench
  _memory_benchmark=$RETVAL
  DEBUG "Memory benchmark:" "$_memory_benchmark"

  # Storage(s)
  INFO "Storage(s) benchmark"
  # FIXME Execute
  # run_storages_bench
  # _storages_benchmark=$RETVAL
  _storages_benchmark="{}"
  DEBUG "Storage(s) benchmark:" "$_storages_benchmark"

  spinner_stop

  # Update
  NODE_FACTS=$(
    printf '%s\n' "$NODE_FACTS" |
      jq \
        --argjson cpu "$_cpu_benchmark" \
        --argjson memory "$_memory_benchmark" \
        --argjson storages "$_storages_benchmark" \
        '
          .cpu.singleThreadScore = $cpu.singleThread
          | .cpu.multiThreadScore = $cpu.multiThread
        '
  )
}

# Read power consumptions
read_power_consumptions() {
  spinner_start "Reading power consumption"

  # CPU
  INFO "CPU power consumption"
  read_cpu_power_consumption
  _cpu_power_consumption=$RETVAL
  DEBUG "CPU power consumption:" "$_cpu_power_consumption"

  spinner_stop

  # Update
  NODE_FACTS=$(
    printf '%s\n' "$NODE_FACTS" |
      jq \
        --argjson cpu "$_cpu_power_consumption" \
        '
          .minPowerConsumption = $cpu.idle.mean
          | .maxPowerConsumption = $cpu.multiThread.mean
        '
  )
}

####### Power on strategy configuration #######

# Function to configure power on strategy
configure_power_on_strategy() {
  INFO "Entering power on strategy configuration ..."

  DEBUG "$_valid_interfaces"

  if [ "$INIT_CLUSTER" = true ]; then
    whiptail --title "Power on strategy configuration" --infobox "Now it's time to select the desired power on strategy." 12 78
    INFO "Power on strategy configuration."

    _controller_iface_has_wol=$(echo "$_valid_interfaces" | jq -r '
            .[] | select(.controller == true) | .wol | index("d") | not
        ')

    DEBUG "Controller interface has WOL: $_controller_iface_has_wol"

    if [ "$_controller_iface_has_wol" == "true" ]; then
      CHOICE=$(whiptail --title "Power on strategy configuration" --radiolist \
        "Choose your desired power on strategy. Read the documentation to learn more about. Since Wake On Lan is available for the controller interface, it is pre-selected as default option." 15 50 4 \
        "WOL" "Wake On Lan" ON \
        "AO" "Always On" OFF \
        "SP" "Smart Plug" OFF \
        "BPD" "Button Press Device" OFF 3>&1 1>&2 2>&3)

      # Exit if the user cancels the dialog
      exitstatus=$?
      if [ $exitstatus != 0 ]; then
        FATAL "The configuration of the power strategy is mandatory."
      fi

      # Handle the selection with a case construct
      case $CHOICE in
      "WOL")
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "WOL"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnDevice = {}')
        INFO "The wake on lan power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The wake on lan (WOL) power on strategy has been selected." 12 78
        ;;
      "AO")
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "AO"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnDevice = {}')
        INFO "The always on power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The always on (AO) power on strategy has been selected." 12 78
        ;;
      "SP")
        get_power_on_smart_plug_ip_address
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "SP"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq --arg address "$POWER_ON_DEVICE_IP" --arg deviceType "$POWER_ON_DEVICE_TYPE" '.powerOnDevice = { address: $address, deviceType: "SMART_PLUG" }')
        INFO "The smart plug power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The smart plug (SP) power on strategy has been selected." 12 78
        ;;
      "BPD")
        get_button_press_device_ip_address
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "BPD"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq --arg address "$POWER_ON_DEVICE_IP" --arg deviceType "$POWER_ON_DEVICE_TYPE" '.powerOnDevice = { address: $address, deviceType: "BUTTON_PRESS" }')
        INFO "The button press device power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The button press device (BPD) power on strategy has been selected." 12 78
        ;;
      *)
        FATAL "Invalid power on strategy configuration"
        ;;
      esac
    else
      CHOICE=$(whiptail --title "Power on strategy selection" --radiolist \
        "Choose your desired power on strategy. Read the documentation to learn more about. Since Wake On Lan is NOT available for the controller interface, you can choose between the other 3 strategies." 15 50 4 \
        "AO" "Always On" ON \
        "SP" "Smart Plug" OFF \
        "BPD" "Button Press Device" OFF 3>&1 1>&2 2>&3)

      # Exit if the user cancels the dialog
      exitstatus=$?
      if [ $exitstatus != 0 ]; then
        FATAL "The configuration of the power strategy is mandatory."
      fi

      # Handle the selection with a case construct
      case $CHOICE in
      "AO")
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "AO"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnDevice = {}')
        INFO "The always on power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The always on (AO) power on strategy has been selected." 12 78
        ;;
      "SP")
        get_power_on_smart_plug_ip_address
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "SP"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq --arg address "$POWER_ON_DEVICE_IP" --arg deviceType "$POWER_ON_DEVICE_TYPE" '.powerOnDevice = { address: $address, deviceType: "SMART_PLUG" }')
        INFO "The smart plug power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The smart plug (SP) power on strategy has been selected." 12 78
        ;;
      "BPD")
        get_button_press_device_ip_address
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq '.powerOnStrategy = "BPD"')
        NODE_FACTS=$(printf '%s\n' "$NODE_FACTS" | jq --arg address "$POWER_ON_DEVICE_IP" --arg deviceType "$POWER_ON_DEVICE_TYPE" '.powerOnDevice = { address: $address, deviceType: "BUTTON_PRESS" }')
        INFO "The button press device power on strategy has been selected."
        whiptail --title "Power on strategy configuration" --infobox "The button press device (BPD) power on strategy has been selected." 12 78
        ;;
      *)
        FATAL "Invalid power on strategy configuration"
        ;;
      esac
    fi
  else
    whiptail --title "Power on strategy configuration" --infobox "Since this is a controller node no power on strategy choice is required." 12 78
    INFO "Power on strategy configuration skipped since this is a controller node."
  fi
}

# Aux function to get the IP of the power on smart plug

get_power_on_smart_plug_ip_address() {
  IP_ADDRESS=$(whiptail --title "Power on smart plug IP Address" --inputbox "Please enter the IP address of the power on smart plug:" 10 60 3>&1 1>&2 2>&3)

  # Exit if the user cancels the dialog
  exitstatus=$?
  if [ $exitstatus != 0 ]; then
    FATAL "Power on smart plug IP address input canceled."
  fi

  # Validate the IP address format
  if echo "$IP_ADDRESS" | grep -Eq '^(([1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4]))$'; then
    POWER_ON_DEVICE_IP=$IP_ADDRESS
    INFO "The power on smart plug IP address is: $POWER_ON_DEVICE_IP."
    whiptail --title "Power on smart plug IP" --infobox "The power on smart plug IP is $IP_ADDRESS." 12 78
  else
    INFO "Invalid IP address format."
    whiptail --title "Invalid IP address" --msgbox "Invalid IP address format." 8 35
    get_power_on_smart_plug_ip_address
  fi
}

# Aux function to get the IP of the button press device

get_button_press_device_ip_address() {
  IP_ADDRESS=$(whiptail --title "Button press device IP Address" --inputbox "Please enter the IP address of the button press device:" 10 60 3>&1 1>&2 2>&3)

  # Exit if the user cancels the dialog
  exitstatus=$?
  if [ $exitstatus != 0 ]; then
    FATAL "Button press device IP address input canceled."
  fi

  # Validate the IP address format
  if echo "$IP_ADDRESS" | grep -Eq '^(([1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4])\.([0-9]|[1-9][0-9]{0,1}|1[0-9]{2}|2[0-4][0-9]|25[0-4]))$'; then
    POWER_ON_DEVICE_IP=$IP_ADDRESS
    INFO "The button press device IP address is: $POWER_ON_DEVICE_IP."
    whiptail --title "Button press device IP" --infobox "The button press device IP is $IP_ADDRESS." 12 78
  else
    INFO "Invalid IP address format."
    whiptail --title "Invalid IP address" --msgbox "Invalid IP address format." 8 35
    get_power_on_smart_plug_ip_address
  fi
}

##############################################

# Finalize node facts
finalize_node_facts() {
  spinner_start "Finalizing node facts"

  _kind=$(printf '%s\n' "$CONFIG" | jq --raw-output '.kind')
  _has_taint_no_execute=$(printf '%s\n' "$K3S_CONFIG" | jq --raw-output 'any(select(."node-taint"); ."node-taint"[] | . == "CriticalAddonsOnly=true:NoExecute")')

  # Roles
  _roles="[]"
  if [ "$INIT_CLUSTER" = true ]; then _roles=$(printf '%s\n' "$_roles" | jq '. + ["RECLUSTER_CONTROLLER"]'); fi
  if [ "$_kind" = "controller" ]; then _roles=$(printf '%s\n' "$_roles" | jq '. + ["K8S_CONTROLLER"]'); fi
  if [ "$_kind" = "worker" ] || { [ "$_kind" = "controller" ] && [ "$_has_taint_no_execute" = false ]; }; then
    _roles=$(printf '%s\n' "$_roles" | jq '. + ["K8S_WORKER"]')
  fi
  DEBUG "Node roles:" "$_roles"

  NODE_FACTS=$(
    printf '%s\n' "$NODE_FACTS" |
      jq \
        --argjson roles "$_roles" \
        '
          .roles = $roles
        '
  )

  spinner_stop

  DEBUG "Node facts:" "$NODE_FACTS"
}

# Install K3s
install_k3s() {
  _k3s_version="$K3S_VERSION"
  _k3s_install_sh=
  _k3s_etc_dir=/etc/rancher/k3s
  _k3s_config_file="$_k3s_etc_dir/config.yaml"
  _k3s_registry_config_file="$_k3s_etc_dir/registries.yaml"
  _k3s_kind=

  spinner_start "Installing K3s '$K3S_VERSION'"

  # Uninstall
  if [ -x /usr/local/bin/k3s-recluster-uninstall.sh ]; then
    DEBUG "Uninstalling K3s"
    $SUDO /usr/local/bin/k3s-recluster-uninstall.sh
  fi

  # Check airgap environment
  if [ "$AIRGAP_ENV" = true ]; then
    # Airgap enabled
    _k3s_install_sh="$DIRNAME/dependencies/k3s/install.sh"
    _k3s_airgap_images=/var/lib/rancher/k3s/agent/images
    # Create directory
    $SUDO mkdir -p "$_k3s_airgap_images"
    # Move
    $SUDO mv --force "$AIRGAP_K3S_BIN" /usr/local/bin/k3s
    $SUDO mv --force "$AIRGAP_K3S_IMAGES" "$_k3s_airgap_images"
  else
    # Airgap disabled
    if [ "$_k3s_version" = latest ]; then _k3s_version=; fi
    _k3s_install_sh="$TMP_DIR/install.k3s.sh"
    # Download installer
    DEBUG "Downloading K3s installer"
    download "$_k3s_install_sh" https://get.k3s.io
    chmod 755 "$_k3s_install_sh"
  fi

  # Checks
  { [ -f "$_k3s_install_sh" ] && [ -x "$_k3s_install_sh" ]; } || FATAL "K3s installation script '$_k3s_install_sh' not found or not executable"

  # Kind
  _kind=$(printf '%s\n' "$CONFIG" | jq --raw-output '.kind')
  case $_kind in
  controller) _k3s_kind=server ;;
  worker) _k3s_kind=agent ;;
  *) FATAL "Unknown kind '$_kind'" ;;
  esac

  # Etc directory
  [ -d "$_k3s_etc_dir" ] || $SUDO mkdir -p "$_k3s_etc_dir"

  # Write configuration
  INFO "Writing K3s configuration to '$_k3s_config_file'"
  printf '%s\n' "$K3S_CONFIG" |
    yq e --no-colors --prettyPrint - |
    yq e --no-colors '(.. | select(tag == "!!str")) style="double"' - |
    $SUDO tee "$_k3s_config_file" >/dev/null
  $SUDO chown root:root "$_k3s_config_file"
  $SUDO chmod 644 "$_k3s_config_file"

  # Registry configuration
  INFO "Copying K3s registry configuration file from '$K3S_REGISTRY_CONFIG_FILE' to '$_k3s_registry_config_file'"
  yes | $SUDO cp --force "$K3S_REGISTRY_CONFIG_FILE" "$_k3s_registry_config_file"
  $SUDO chown root:root "$_k3s_config_file"
  $SUDO chmod 644 "$_k3s_config_file"

  # Install
  INSTALL_K3S_SKIP_ENABLE=true \
    INSTALL_K3S_SKIP_START=true \
    INSTALL_K3S_SKIP_DOWNLOAD="$AIRGAP_ENV" \
    INSTALL_K3S_VERSION="$_k3s_version" \
    INSTALL_K3S_NAME=recluster \
    INSTALL_K3S_EXEC="$_k3s_kind" \
    "$_k3s_install_sh" || FATAL "Error installing K3s '$K3S_VERSION'"

  spinner_stop

  # Success
  INFO "Successfully installed K3s '$K3S_VERSION'"
}

# Install Node exporter
install_node_exporter() {
  _node_exporter_version="$NODE_EXPORTER_VERSION"
  _node_exporter_install_sh=
  _node_exporter_config=

  spinner_start "Installing Node exporter '$NODE_EXPORTER_VERSION'"

  # Uninstall
  if [ -x /usr/local/bin/node_exporter.uninstall.sh ]; then
    DEBUG "Uninstalling Node exporter"
    $SUDO /usr/local/bin/node_exporter.uninstall.sh
  fi

  # Check airgap environment
  if [ "$AIRGAP_ENV" = true ]; then
    # Airgap enabled
    _node_exporter_install_sh="$DIRNAME/dependencies/node_exporter/install.sh"
    # Move
    $SUDO mv --force "$AIRGAP_NODE_EXPORTER_BIN" /usr/local/bin/node_exporter
  else
    # Airgap disabled
    if [ "$_node_exporter_version" = latest ]; then _node_exporter_version=; fi
    _node_exporter_install_sh="$TMP_DIR/install.node_exporter.sh"
    # Download installer
    DEBUG "Downloading Node exporter installer"
    download "$_node_exporter_install_sh" https://raw.githubusercontent.com/carlocorradini/node_exporter_installer/main/install.sh
    chmod 755 "$_node_exporter_install_sh"
  fi

  # Checks
  { [ -f "$_node_exporter_install_sh" ] && [ -x "$_node_exporter_install_sh" ]; } || FATAL "Node exporter installation script '$_node_exporter_install_sh' not found or not executable"

  # Configuration
  INFO "Writing Node exporter configuration"
  _node_exporter_config=$(
    printf '%s\n' "$NODE_EXPORTER_CONFIG" |
      jq \
        --raw-output \
        '
          .collector
          | to_entries
          | map(if .value == true then ("--collector."+.key) else ("--no-collector."+.key) end)
          | join(" ")
        '
  ) || FATAL "Error reading Node exporter configuration"

  # Install
  INSTALL_NODE_EXPORTER_SKIP_ENABLE=true \
    INSTALL_NODE_EXPORTER_SKIP_START=true \
    INSTALL_NODE_EXPORTER_SKIP_DOWNLOAD="$AIRGAP_ENV" \
    INSTALL_NODE_EXPORTER_VERSION="$_node_exporter_version" \
    INSTALL_NODE_EXPORTER_EXEC="$_node_exporter_config" \
    "$_node_exporter_install_sh" || FATAL "Error installing Node exporter '$NODE_EXPORTER_VERSION'"

  spinner_stop

  # Success
  INFO "Successfully installed Node exporter '$NODE_EXPORTER_VERSION'"
}

# Cluster initialization
cluster_init() {
  [ "$INIT_CLUSTER" = true ] || return 0

  INFO "Cluster initialization"

  _k3s_kubeconfig_file="/etc/rancher/k3s/k3s.yaml"
  _kubeconfig_file="$(user_home_dir)/.kube/config"
  _certs_dir="$RECLUSTER_ETC_DIR/certs"
  _server_service_name=recluster.server
  _server_env_file="$RECLUSTER_ETC_DIR/server.env"
  _server_dir="$RECLUSTER_OPT_DIR/server"

  _wait_k3s_kubeconfig_file_creation() {
    _k3s_kubeconfig_dir=$(dirname "$_k3s_kubeconfig_file")
    _k3s_kubeconfig_file_name=$(basename "$_k3s_kubeconfig_file")

    if [ -f "$_k3s_kubeconfig_file" ]; then
      # kubeconfig already exists
      INFO "K3s kubeconfig file already generated at '$_k3s_kubeconfig_file'"
    else
      # kubeconfig wait generation
      INFO "Waiting K3s kubeconfig file at '$_k3s_kubeconfig_file'"

      _k3s_kubeconfig_generated=false
      while [ "$_k3s_kubeconfig_generated" = false ]; do
        read -r _dir _action _file <<EOF
$(inotifywait -e create,close_write,moved_to --quiet "$_k3s_kubeconfig_dir")
EOF
        DEBUG "File '$_file' notify '$_action' at '$_dir'"
        if [ "$_file" = "$_k3s_kubeconfig_file_name" ]; then
          DEBUG "K3s kubeconfig file generated"
          _k3s_kubeconfig_generated=true
        fi
      done
    fi
  }

  # Start and stop K3s service to generate initial configuration
  case $INIT_SYSTEM in
  openrc)
    INFO "openrc: Starting K3s service"
    $SUDO rc-service k3s-recluster start
    _wait_k3s_kubeconfig_file_creation
    INFO "openrc: Stopping K3s service"
    $SUDO rc-service k3s-recluster stop
    ;;
  systemd)
    INFO "systemd: Starting K3s service"
    $SUDO systemctl start k3s-recluster
    _wait_k3s_kubeconfig_file_creation
    INFO "systemd: Stopping K3s service"
    $SUDO systemctl stop k3s-recluster
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  # Copy kubeconfig
  INFO "Copying K3s kubeconfig from '$_k3s_kubeconfig_file' to '$_kubeconfig_file'"
  _kubeconfig_dir=$(dirname "$_kubeconfig_file")
  [ -d "$_kubeconfig_dir" ] || $SUDO mkdir "$_kubeconfig_dir"
  yes | $SUDO cp --force "$_k3s_kubeconfig_file" "$_kubeconfig_file"
  $SUDO chown "$USER:$USER" "$_kubeconfig_file"
  $SUDO chmod 644 "$_kubeconfig_file"

  # Setup database
  INFO "Setting up database"
  DEBUG "Reading database URL from '$RECLUSTER_SERVER_ENV_FILE'"
  _database_url=$(grep 'DATABASE_URL=' "$RECLUSTER_SERVER_ENV_FILE" | sed -e 's/DATABASE_URL=//g' -e 's/[[:space:]]*//g' -e 's/*[[:space:]]//g' -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//')
  DEBUG "Parsing database URL '$_database_url'"
  parse_url "$_database_url"
  DEBUG "Database URL:" "$RETVAL"
  _database_user=$(printf '%s\n' "$RETVAL" | jq --raw-output '.user')
  _database_password=$(printf '%s\n' "$RETVAL" | jq --raw-output '.password')
  _database_db=$(printf '%s\n' "$RETVAL" | jq --raw-output '.path' | cut -d\? -f1)

  DEBUG "Stopping database"
  case $INIT_SYSTEM in
  openrc) $SUDO rc-service postgresql stop >/dev/null 2>&1 || $SUDO rc-service postgresql zap >/dev/null 2>&1 || : ;;
  systemd) $SUDO systemctl stop postgresql >/dev/null 2>&1 || $SUDO systemctl kill postgresql >/dev/null 2>&1 || : ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  DEBUG "Removing PostgreSQL data directory"
  $SUDO rm -rf /var/lib/postgresql

  case $INIT_SYSTEM in
  openrc)
    INFO "openrc: Creating PostgreSQL database cluster"
    $SUDO rc-service postgresql setup

    INFO "openrc: Starting database"
    $SUDO rc-service postgresql start
    wait_database_reachability
    ;;
  systemd)
    INFO "systemd: Creating PostgreSQL database cluster"
    # TODO
    FATAL "systemd: Creating PostgreSQL database cluster not implemented"

    INFO "systemd: Starting database"
    $SUDO systemctl start postgresql
    wait_database_reachability
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  DEBUG "Removing database '$_database_db'"
  $SUDO su postgres -c 'psql -c "DROP DATABASE IF EXISTS '"$_database_db"';"'
  DEBUG "Removing user '$_database_user'"
  $SUDO su postgres -c 'psql -c "DROP USER IF EXISTS '"$_database_user"';"'
  DEBUG "Creating database '$_database_db'"
  $SUDO su postgres -c 'psql -c "CREATE DATABASE '"$_database_db"';"'
  DEBUG "Creating user '$_database_user'"
  $SUDO su postgres -c 'psql -c "CREATE USER '"$_database_user"' WITH PASSWORD '\'"$_database_password"\'';"'
  DEBUG "Defining access privileges for user '$_database_user'"
  $SUDO su postgres -c 'psql -c "GRANT ALL PRIVILEGES ON DATABASE '"$_database_db"' TO '"$_database_user"';"'
  $SUDO su postgres -c 'psql -c "GRANT ALL PRIVILEGES ON SCHEMA public TO '"$_database_user"';"'
  $SUDO su postgres -c 'psql -c "ALTER USER '"$_database_user"' SUPERUSER;"'
  $SUDO su postgres -c 'psql -c "ALTER USER '"$_database_user"' CREATEDB"'

  # Copy server
  INFO "Copying server from '$DIRNAME/server' to '$_server_dir'"
  [ -d "$_server_dir" ] || $SUDO mkdir -p "$_server_dir"
  yes | $SUDO cp --force --archive "$DIRNAME/server/." "$_server_dir"
  $SUDO chown --recursive root:root "$_server_dir"
  $SUDO chmod --recursive 755 "$_server_dir"

  # Copy server env file
  INFO "Copying server environment file from '$RECLUSTER_SERVER_ENV_FILE' to '$_server_env_file'"
  yes | $SUDO cp --force "$RECLUSTER_SERVER_ENV_FILE" "$_server_env_file"
  $SUDO chown root:root "$_server_env_file"
  $SUDO chmod 600 "$_server_env_file"

  # Setup server
  INFO "Setting up server"
  DEBUG "Installing server dependencies"
  $SUDO npm --prefix "$_server_dir" ci --ignore-scripts
  yes | $SUDO cp --force "$_server_env_file" "$_server_dir/.env"
  DEBUG "Generating database assets"
  $SUDO npm --prefix "$_server_dir" run db:generate
  INFO "Applying migrations to production database"
  $SUDO npm --prefix "$_server_dir" run db:deploy
  DEBUG "Removing development dependencies"
  $SUDO npm --prefix "$_server_dir" prune --production
  $SUDO rm -rf "$_server_dir/prisma"
  $SUDO rm -f "$_server_dir/.env"

  # Server service
  INFO "Constructing server service '$_server_service_name'"
  case $INIT_SYSTEM in
  openrc)
    _openrc_server_service_file="/etc/init.d/$_server_service_name"
    _openrc_server_log_file="/var/log/$_server_service_name.log"

    INFO "openrc: Constructing server service file '$_openrc_server_service_file'"
    $SUDO tee $_openrc_server_service_file >/dev/null <<EOF
#!/sbin/openrc-run

description="reCluster server"

depend() {
  after network-online
}

supervisor=supervise-daemon
name=recluster.server
command="/usr/bin/node $_server_dir/build/main.js"

output_log=$_openrc_server_log_file
error_log=$_openrc_server_log_file

pidfile=/var/run/recluster.server.pid
respawn_delay=3
respawn_max=0

set -o allexport
# inline skip
source $_server_env_file
set +o allexport
EOF
    $SUDO chown root:root $_openrc_server_service_file
    $SUDO chmod 755 $_openrc_server_service_file

    $SUDO tee "/etc/logrotate.d/$_server_service_name" >/dev/null <<EOF
$_openrc_server_log_file {
	missingok
	notifempty
	copytruncate
}
EOF

    INFO "openrc: Starting server"
    $SUDO rc-service recluster.server restart
    wait_server_reachability
    ;;
  systemd)
    _systemd_server_service_file="/etc/systemd/system/$_server_service_name.service"

    INFO "systemd: Constructing server service file '$_systemd_server_service_file'"
    $SUDO tee $_systemd_server_service_file >/dev/null <<EOF
[Unit]
Description=reCluster server
After=network-online.target network.target
Wants=network-online.target network.target

[Service]
Type=simple
EnvironmentFile=$_server_env_file
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
TimeoutStartSec=0
Restart=always
RestartSec=3s
ExecStart=/usr/bin/node $_server_dir/build/main.js
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=recluster.server

[Install]
WantedBy=multi-user.target
EOF
    $SUDO chown root:root $_systemd_server_service_file
    $SUDO chmod 755 $_systemd_server_service_file

    $SUDO systemctl daemon-reload >/dev/null

    INFO "systemd: Starting server"
    $SUDO systemctl restart recluster.server
    wait_server_reachability
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  # Admin user
  INFO "Creating admin user '$ADMIN_USERNAME'"
  create_server_user "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
  _admin_id=$(printf '%s\n' "$RETVAL" | jq --raw-output '.id')
  DEBUG "Updating admin user '$ADMIN_USERNAME' roles"
  $SUDO su postgres -c 'PGPASSWORD='"$_database_password"' psql -d '"$_database_db"' -U '"$_database_user"' --no-password -c "UPDATE \"user\" SET roles = array_append(roles, '\''ADMIN'\'') WHERE id = '\'"$_admin_id"\'';"'

  # Autoscaler user
  INFO "Creating autoscaler user '$AUTOSCALER_USERNAME'"
  create_server_user "$AUTOSCALER_USERNAME" "$AUTOSCALER_PASSWORD"
  _autoscaler_id=$(printf '%s\n' "$RETVAL" | jq --raw-output '.id')
  DEBUG "Updating autoscaler user '$AUTOSCALER_USERNAME' roles"
  $SUDO su postgres -c 'PGPASSWORD='"$_database_password"' psql -d '"$_database_db"' -U '"$_database_user"' --no-password -c "UPDATE \"user\" SET roles = array_append(roles, '\''ADMIN'\'') WHERE id = '\'"$_autoscaler_id"\'';"'
  sign_in_server_user "$AUTOSCALER_USERNAME" "$AUTOSCALER_PASSWORD"
  AUTOSCALER_TOKEN=$(printf '%s\n' "$RETVAL" | jq --raw-output '.token')
}

# Install reCluster
install_recluster() {
  # Files
  _k3s_config_file=/etc/rancher/k3s/config.yaml
  _recluster_config_file="$RECLUSTER_ETC_DIR/config.yaml"
  _node_token_file="$RECLUSTER_ETC_DIR/token"
  _commons_script_file="$RECLUSTER_OPT_DIR/__commons.sh"
  _bootstrap_script_file="$RECLUSTER_OPT_DIR/bootstrap.sh"
  _shutdown_script_file="$RECLUSTER_OPT_DIR/shutdown.sh"
  # Configuration
  _node_label_id="recluster.io/id="
  _service_name=recluster
  # Registration data
  _registration_data=
  _node_token=
  _node_id=
  _node_name=

  spinner_start "Installing reCluster"

  # Write configuration
  printf '%s\n' "$CONFIG" |
    jq '.recluster' |
    yq e --no-colors --prettyPrint - |
    yq e --no-colors '(.. | select(tag == "!!str")) style="double"' - |
    $SUDO tee "$_recluster_config_file" >/dev/null
  $SUDO chown root:root "$_recluster_config_file"
  $SUDO chmod 600 "$_recluster_config_file"

  # Register node
  node_registration
  _registration_data=$RETVAL
  _node_token=$(printf '%s\n' "$_registration_data" | jq --raw-output '.token')
  _node_id=$(printf '%s\n' "$_registration_data" | jq --raw-output '.decoded.payload.id')

  # Write node token
  printf '%s\n' "$_node_token" | $SUDO tee "$_node_token_file" >/dev/null
  $SUDO chown root:root "$_node_token_file"
  $SUDO chmod 600 "$_node_token_file"

  # K3s node name
  _kind=$(printf '%s\n' "$CONFIG" | jq --raw-output '.kind')
  case $_kind in
  controller | worker) _node_name="$_kind.$_node_id" ;;
  *) FATAL "Unknown kind '$_kind'" ;;
  esac

  # K3s label
  _node_label_id="${_node_label_id}${_node_id}"

  # Update K3s configuration
  INFO "Updating K3s configuration '$_k3s_config_file'"
  $SUDO yq e '.node-name = "'"$_node_name"'" | .node-label += ["'"$_node_label_id"'"] | (.. | select(tag == "!!str")) style="double"' -i "$_k3s_config_file"

  #
  # Scripts
  #
  # Commons script
  INFO "Constructing '$(basename "$_commons_script_file")' script"
  $SUDO tee "$_commons_script_file" >/dev/null <<EOF
#!/usr/bin/env sh

# Fail on error
set -o errexit
# Disable wildcard character expansion
set -o noglob

# ================
# CONFIGURATION
# ================
# Configuration file
RECLUSTER_CONFIG_FILE="$_recluster_config_file"
# Node token file
RECLUSTER_NODE_TOKEN_FILE="$_node_token_file"

# ================
# GLOBALS
# ================
# Config
RECLUSTER_CONFIG=
# Node token
RECLUSTER_NODE_TOKEN=

# ================
# LOGGER
# ================
# Fatal log message
FATAL() {
  printf '[FATAL] %s\n' "\$@" >&2
  exit 1
}
# Info log message
INFO() {
  printf '[INFO ] %s\n' "\$@"
}
# Debug log message
DEBUG() {
  printf '[DEBUG] %s\n' "\$@"
}

# ================
# FUNCTIONS
# ================
# Read configuration file
read_config() {
  [ -z "\$RECLUSTER_CONFIG" ] || return 0

  DEBUG "Reading reCluster configuration file '\$RECLUSTER_CONFIG_FILE'"
  [ -f \$RECLUSTER_CONFIG_FILE ] || FATAL "reCluster configuration file '\$RECLUSTER_CONFIG_FILE' not found"
  RECLUSTER_CONFIG=\$(yq e --output-format=json --no-colors '.' "\$RECLUSTER_CONFIG_FILE") || FATAL "Error reading reCluster configuration file '\$RECLUSTER_CONFIG_FILE'"
}

# Read node token file
read_node_token() {
  [ -z "\$RECLUSTER_NODE_TOKEN" ] || return 0

  DEBUG "Reading node token file '\$RECLUSTER_NODE_TOKEN_FILE'"
  [ -f \$RECLUSTER_NODE_TOKEN_FILE ] || FATAL "Node token file '\$RECLUSTER_NODE_TOKEN_FILE' not found"
  RECLUSTER_NODE_TOKEN=\$(cat "\$RECLUSTER_NODE_TOKEN_FILE") || FATAL "Error reading node token file '\$RECLUSTER_NODE_TOKEN_FILE'"
}

# Update node status
# @param \$1 Status
update_node_status() {
  read_config
  read_node_token

  _status=\$1
  _server_url=\$(printf '%s\n' "\$RECLUSTER_CONFIG" | jq --exit-status --raw-output '.server') || FATAL "reCluster configuration requires server URL"
  _server_url="\$_server_url/graphql"
  _request_data=\$(
    jq \\
      --null-input \\
      --compact-output \\
      --arg status "\$_status" \\
      '
        {
          "query": "mutation (\$data: UpdateStatusInput!){ updateStatus(data: \$data) { id } }",
          "variables": { "data": { "status": \$status } }
        }
      '
  )
  _response_data=

  DEBUG "Updating node status '\$_status' at '\$_server_url'"

  # Send update request
EOF

  case $DOWNLOADER in
  curl)
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
      _response_data=\$(
        curl --fail --silent --location --show-error \\
          --request POST \\
          --header 'Content-Type: application/json' \\
          --header 'Authorization: Bearer '"\$RECLUSTER_NODE_TOKEN"'' \\
          --url "\$_server_url" \\
          --data "\$_request_data"
      ) || FATAL "Error sending update node status request to '\$_server_url'"
EOF
    ;;
  wget)
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
      _response_data=\$(
        wget --quiet --output-document=- \\
          --header='Content-Type: application/json' \\
          --header 'Authorization: Bearer '"\$RECLUSTER_NODE_TOKEN"'' \\
          --post-data="\$_request_data" \\
          "\$_server_url" 2>&1
      ) || FATAL "Error sending update node status request to '\$_server_url'"
EOF
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac

  $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  # Check error response
  if printf '%s\n' "\$_response_data" | jq --exit-status 'has("errors")' > /dev/null 2>&1; then
    FATAL "Error updating node status at '\$_server_url':\\n\$(printf '%s\n' "\$_response_data" | jq .)"
  fi
}

# Assert URL is reachable
# @param \$1 URL address
# @param \$2 Timeout in seconds
assert_url_reachability() {
  # URL address
  _url_address=\$1
  # Timeout in seconds
  _timeout=\${2:-10}

  DEBUG "Testing URL '\$_url_address' reachability"
EOF

  case $DOWNLOADER in
  curl)
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  curl --fail --silent --show-error --max-time "\$_timeout" "\$_url_address" > /dev/null || FATAL "URL address '\$_url_address' is unreachable"
EOF
    ;;
  wget)
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  wget --quiet --spider --timeout="\$_timeout" --tries=1 "\$_url_address" 2>&1 || FATAL "URL address '\$_url_address' is unreachable"
EOF
    ;;
  *) FATAL "Unknown downloader '$DOWNLOADER'" ;;
  esac

  $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
}

# Wait database reachability
wait_database_reachability() {
  _wait_database_max_attempts=40
  _wait_database_sleep=3

  INFO "Waiting database reachability"
  while [ "\$_wait_database_max_attempts" -gt 0 ]; do
    if su postgres -c "pg_isready" > /dev/null 2>&1; then
      DEBUG "Database is reachable"
      break
    fi

    DEBUG "Database is not reachable, sleeping \$_wait_database_sleep seconds"
    sleep "\$_wait_database_sleep"
    _wait_database_max_attempts=\$((_wait_database_max_attempts = _wait_database_max_attempts - 1))
  done
  [ "\$_wait_database_max_attempts" -gt 0 ] || FATAL "Database is not reachable, maximum attempts reached"
}

# Wait server reachability
wait_server_reachability() {
  read_config

  _wait_server_max_attempts=40
  _wait_server_sleep=3
  _server_url=\$(printf '%s\n' "\$RECLUSTER_CONFIG" | jq --exit-status --raw-output '.server') || FATAL "reCluster configuration requires server URL"

  INFO "Waiting server reachability"
  while [ "\$_wait_server_max_attempts" -gt 0 ]; do
    if (assert_url_reachability "\$_server_url/health" > /dev/null 2>&1); then
      DEBUG "Server is reachable"
      break
    fi

    DEBUG "Server is not reachable, sleeping \$_wait_server_sleep seconds"
    sleep "\$_wait_server_sleep"
    _wait_server_max_attempts=\$((_wait_server_max_attempts = _wait_server_max_attempts - 1))
  done
  [ "\$_wait_server_max_attempts" -gt 0 ] || FATAL "Server is not reachable, maximum attempts reached"
}

# Manage services
# @param \$1 Operation
manage_services() {
  _op=\$1
  _op_message=

  case \$_op in
    start) _op_message="Starting" ;;
    stop) _op_message="Stopping" ;;
    restart) _op_message="Restarting" ;;
    * ) FATAL "Unknown operation '\$_op'"
  esac
EOF

  case $INIT_SYSTEM in
  openrc)
    if [ "$INIT_CLUSTER" = true ]; then
      $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  INFO "openrc: \$_op_message Database"
  rc-service postgresql \$_op
  { [ "\$_op" = start ] || [ "\$_op" = restart ]; } && wait_database_reachability
  INFO "openrc: \$_op_message Server"
  rc-service recluster.server \$_op
  { [ "\$_op" = start ] || [ "\$_op" = restart ]; } && wait_server_reachability
EOF
    fi
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  INFO "openrc: \$_op_message Node exporter"
  rc-service node_exporter \$_op
  INFO "openrc: \$_op_message K3s"
  rc-service k3s-recluster \$_op
EOF
    ;;
  systemd)
    if [ "$INIT_CLUSTER" = true ]; then
      $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  INFO "systemd: \$_op_message Database"
  systemctl \$_op postgresql.service
  { [ "\$_op" = start ] || [ "\$_op" = restart ]; } && wait_database_reachability
  INFO "systemd: \$_op_message Server"
  systemctl \$_op recluster.server.service
  { [ "\$_op" = start ] || [ "\$_op" = restart ]; } && wait_server_reachability
EOF
    fi
    $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
  INFO "systemd: \$_op_message Node exporter"
  systemctl \$_op node_exporter.service
  INFO "systemd: \$_op_message K3s"
  systemctl \$_op k3s-recluster.service
EOF
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  $SUDO tee -a "$_commons_script_file" >/dev/null <<EOF
}
EOF
  $SUDO chown root:root "$_commons_script_file"
  $SUDO chmod 755 "$_commons_script_file"

  # Bootstrap script
  INFO "Constructing '$(basename "$_bootstrap_script_file")' script"
  $SUDO tee "$_bootstrap_script_file" >/dev/null <<EOF
#!/usr/bin/env sh

# Load commons
# inline skip
. "$_commons_script_file"

# ================
# MAIN
# ================
{
EOF
  if [ "$INIT_CLUSTER" = true ]; then
    $SUDO tee -a "$_bootstrap_script_file" >/dev/null <<EOF
  manage_services start
  update_node_status ACTIVE
EOF
  else
    $SUDO tee -a "$_bootstrap_script_file" >/dev/null <<EOF
  update_node_status ACTIVE
  manage_services start
EOF
  fi
  $SUDO tee -a "$_bootstrap_script_file" >/dev/null <<EOF
}
EOF
  $SUDO chown root:root "$_bootstrap_script_file"
  $SUDO chmod 755 "$_bootstrap_script_file"

  # Shutdown script
  INFO "Constructing '$(basename "$_shutdown_script_file")' script"
  $SUDO tee "$_shutdown_script_file" >/dev/null <<EOF
#!/usr/bin/env sh

# Load commons
# inline skip
. "$_commons_script_file"

# ================
# MAIN
# ================
{
  update_node_status INACTIVE
  manage_services stop
}
EOF
  $SUDO chown root:root "$_shutdown_script_file"
  $SUDO chmod 755 "$_shutdown_script_file"

  #
  # Services
  #
  # reCluster service
  INFO "Constructing reCluster service '$_service_name'"
  case $INIT_SYSTEM in
  openrc)
    _openrc_service_file="/etc/init.d/$_service_name"

    INFO "openrc: Constructing reCluster service file '$_openrc_service_file'"
    $SUDO tee "$_openrc_service_file" >/dev/null <<EOF
#!/sbin/openrc-run

description="reCluster"

depend() {
  need net
  use dns
  after firewall
  after network-online
  want cgroups
}

start() {
  /usr/bin/env sh $_bootstrap_script_file
}

stop() {
  /usr/bin/env sh $_shutdown_script_file
}
EOF
    $SUDO chown root:root "$_openrc_service_file"
    $SUDO chmod 0755 "$_openrc_service_file"

    INFO "openrc: Enabling reCluster service '$_service_name' at startup"
    $SUDO rc-update add "$_service_name" default >/dev/null
    ;;
  systemd)
    _systemd_service_file="/etc/systemd/system/$_service_name.service"

    INFO "systemd: Constructing reCluster service file '$_systemd_service_file'"
    $SUDO tee "$_systemd_service_file" >/dev/null <<EOF
[Unit]
Description=reCluster
After=network-online.target network.target
Wants=network-online.target network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/env sh $_bootstrap_script_file
ExecStop=/usr/bin/env sh $_shutdown_script_file

[Install]
WantedBy=multi-user.target
EOF
    $SUDO chown root:root "$_systemd_service_file"
    $SUDO chmod 0755 "$_systemd_service_file"

    INFO "systemd: Enabling reCluster service '$_service_name' at startup"
    $SUDO systemctl enable "$_service_name" >/dev/null
    $SUDO systemctl daemon-reload >/dev/null
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  spinner_stop

  # Success
  INFO "Successfully installed reCluster"
}

# Start recluster
start_recluster() {
  spinner_start "Starting reCluster"

  case $INIT_SYSTEM in
  openrc)
    INFO "openrc: Starting reCluster"
    $SUDO rc-service recluster restart
    ;;
  systemd)
    INFO "systemd: Starting reCluster"
    $SUDO systemctl restart recluster.service
    ;;
  *) FATAL "Unknown init system '$INIT_SYSTEM'" ;;
  esac

  spinner_stop
}

# Configure K8s
configure_k8s() {
  [ "$INIT_CLUSTER" = true ] || return 0
  spinner_start "Configuring K8s"

  _k8s_timeout="2m"
  _etc_hosts="/etc/hosts"
  _loadbalancer_dir="$DIRNAME/configs/k8s/loadbalancer"
  _loadbalancer_deployment="$_loadbalancer_dir/deployment.yaml"
  _loadbalancer_config="$_loadbalancer_dir/config.yaml"
  _registry_dir="$DIRNAME/configs/k8s/registry"
  _registry_deployment="$_registry_dir/deployment.yaml"
  _registry_k3s="$DIRNAME/configs/k3s/registries.yaml"
  _autoscaler_ca_dir="$DIRNAME/configs/k8s/autoscaler/ca"
  _autoscaler_ca_deployment="$_autoscaler_ca_dir/deployment.yaml"
  _autoscaler_ca_deployment_tmp="$TMP_DIR/autoscaler.ca.deployment.yaml"
  _autoscaler_ca_archive="$AUTOSCALER_DIR/cluster-autoscaler.$ARCH.tar.gz"

  assert_cmd kubectl
  [ -f "$_loadbalancer_deployment" ] || "Load Balancer deployment file '$_loadbalancer_deployment' does not exists"
  [ -f "$_loadbalancer_config" ] || FATAL "Load Balancer configuration file '$_loadbalancer_config' does not exists"
  [ -f "$_registry_deployment" ] || FATAL "Registry deployment file '$_registry_deployment' does not exists"
  [ -f "$_registry_k3s" ] || FATAL "Registry K3s file '$_registry_k3s' does not exists"
  [ -f "$_autoscaler_ca_deployment" ] || FATAL "Autoscaler CA deployment file '$_autoscaler_ca_deployment' does not exists"
  [ -f "$_autoscaler_ca_archive" ] || FATAL "Autoscaler CA archive file '$_autoscaler_ca_archive' does not exists"

  _registry_mirror=$($SUDO yq e --no-colors '.mirrors | to_entries | .[0].key' "$_registry_k3s") || FATAL "Error reading Registry mirror from '$_registry_k3s'"
  _registry_mirror_host=$(printf '%s\n' "$_registry_mirror" | sed 's/\([^:/]*\).*/\1/')
  _registry_endpoint_host=$($SUDO yq e --no-colors '.mirrors | to_entries | .[0].value.endpoint[0]' "$_registry_k3s" | sed 's/[^/]*\/\/\([^@]*@\)\?\([^:/]*\).*/\2/') || FATAL "Error reading Registry endpoint from '$_registry_k3s'"
  _registry_etc_host="$_registry_endpoint_host $_registry_mirror_host"
  _autoscaler_ca_tag="$_registry_mirror/recluster/cluster-autoscaler"
  _autoscaler_ca_tag_version="$_autoscaler_ca_tag:$AUTOSCALER_VERSION"
  _autoscaler_ca_tag_latest="$_autoscaler_ca_tag:latest"

  DEBUG "Copying Autoscaler CA deployment file '$_autoscaler_ca_deployment' to '$_autoscaler_ca_deployment_tmp'"
  cp --force "$_autoscaler_ca_deployment" "$_autoscaler_ca_deployment_tmp"
  _autoscaler_ca_deployment="$_autoscaler_ca_deployment_tmp"

  # Hosts add
  DEBUG "Adding host entry '$_registry_etc_host' to '$_etc_hosts'"
  printf '%s\n' "$_registry_etc_host" | $SUDO tee -a "$_etc_hosts" >/dev/null

  # K8s
  wait_k8s_reachability

  # Load Balancer
  INFO "Applying Load Balancer deployment '$_loadbalancer_deployment'"
  $SUDO kubectl apply -f "$_loadbalancer_deployment"
  INFO "Waiting Load Balancer is ready"
  $SUDO kubectl wait \
    --namespace metallb-system \
    --for=condition=ready pod \
    --selector=app=metallb \
    "--timeout=$_k8s_timeout"
  INFO "Applying Load Balancer configuration '$_loadbalancer_config'"
  $SUDO kubectl apply -f "$_loadbalancer_config"

  # Registry
  INFO "Applying Registry deployment '$_registry_deployment'"
  $SUDO kubectl apply -f "$_registry_deployment"
  INFO "Waiting Registry is ready"
  $SUDO kubectl wait \
    --namespace registry-system \
    --for=condition=ready pod \
    --selector=app=registry \
    "--timeout=$_k8s_timeout"

  # Autoscaler CAVERIFY_SY
  INFO "Replacing Autoscaler CA token"
  sed -i "s^\${{ __.token }}^$AUTOSCALER_TOKEN^" "$_autoscaler_ca_deployment"
  # TODO Do for all images
  INFO "Loading Autoscaler CA image '$_autoscaler_ca_archive'"
  $SUDO docker load --input "$_autoscaler_ca_archive"
  INFO "Tagging Autoscaler CA image '$_autoscaler_ca_tag_version'"
  $SUDO docker tag "recluster/cluster-autoscaler:latest" "$_autoscaler_ca_tag_version"
  INFO "Tagging Autoscaler CA image '$_autoscaler_ca_tag_latest'"
  $SUDO docker tag "recluster/cluster-autoscaler:latest" "$_autoscaler_ca_tag_latest"
  INFO "Pushing Autoscaler CA image(s) '$_autoscaler_ca_tag'"
  $SUDO docker push --all-tags "$_autoscaler_ca_tag"
  INFO "Applying Autoscaler CA deployment '$_autoscaler_ca_deployment'"
  $SUDO kubectl apply -f "$_autoscaler_ca_deployment"
  INFO "Waiting Autoscaler CA is ready"
  $SUDO kubectl wait \
    --namespace kube-system \
    --for=condition=ready pod \
    --selector=app=cluster-autoscaler \
    "--timeout=$_k8s_timeout"

  # Hosts remove
  DEBUG "Removing host entry '$_registry_etc_host' from '$_etc_hosts'"
  $SUDO sed -i "/$_registry_etc_host/d" "$_etc_hosts"

  spinner_stop
}

# ================
# MAIN
# ================
{
  parse_args "$@"
  verify_system
  setup_system
  read_system_info
  run_benchmarks
  read_power_consumptions
  configure_power_on_strategy
  finalize_node_facts
  install_k3s
  install_node_exporter
  cluster_init
  install_recluster
  start_recluster
  configure_k8s
  INFO "--> SUCCESS <--"
}
