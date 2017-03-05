#!/usr/bin/env bash

# define shell options
#----------------------------------------------------------
#set -x
#set -v
set -e
set -u
set -f

# define magic variables
#----------------------------------------------------------
declare -r VERSION="1.0.0"
declare -r FILE_NAME=$(basename "$0")
declare -r EXECUTE_DATE=$(date +%F)
declare -r EXECUTE_TIME=$(date +%T)
declare -r DASH_LINE=$(printf -- '-%.0s' {1..90})
declare -r TEST_FAIL=$(printf '\e[31m%s\e[0m' "failed")
declare -r TEST_PASS=$(printf '\e[0;32m%s\e[0m' "passed")
declare -r TEST_WARN=$(printf '\e[1;34m%s\e[0m' "warning")
declare SHOW_HEADER="true"
declare -r -i SUCCESS=0
declare -r -i BAD_ARGS=85
declare -r -i NO_SUPPORT=86

# define empty variables
#----------------------------------------------------------
declare OS_NAME
declare SSH_VERSION
declare SSH_CONFIG

# script functions
#----------------------------------------------------------
function fc_usage()
{
  printf "Usage: %s [-N] [-h] [-v]\n" "${FILE_NAME}"
}

function fc_version()
{
  printf "%s v%s\n" "${FILE_NAME}" "${VERSION}"
  exit "${SUCCESS}"
}

function fc_help()
{
  fc_usage
  echo " -N      do not show header"
  echo " -h      show help"
  echo " -v      show version"
  exit "${SUCCESS}"
}

function fc_bad_args()
{
  echo "[Error]: wrong arguments supplied"
  exit "${BAD_ARGS}"
}

function fc_nosupport()
{
  printf "%s is not supported yet\n" "${OS_NAME}"
  exit "${NO_SUPPORT}"
}

function fc_uname()
{
  OS_NAME=$(uname -s)
}

function fc_get_version()
{
  SSH_VERSION=$( (ssh -V) 2>&1 )
}

function fc_read_config()
{
  if [ "${OS_NAME}" == 'Linux' ];then
    SSH_CONFIG=$(sshd -T)
  elif [ "${OS_NAME}" == 'Darwin' ]; then
    # SSH_CONFIG=$(cat /private/etc/ssh/sshd_config)
    fc_nosupport
  else
    fc_nosupport
  fi
}

function fc_header()
{
  if [ "${OS_NAME}" == 'Linux' ]; then
    local OS_PRNAME=$(cat /etc/os-release | grep "PRETTY_NAME" | cut -d = -f2)
  else
    local OS_PRNAME=""
  fi

  printf " %s\n" "${DASH_LINE}"
  printf " %-32s %s\n" "Execute date" "${EXECUTE_DATE}"
  printf " %-32s %s\n" "Execute time" "${EXECUTE_TIME}"
  printf " %-32s %s %s\n" "OS" "${OS_NAME}" "${OS_PRNAME}"
  printf " %-32s %s\n" "SSH Version" "${SSH_VERSION}"
  printf " %s\n" "${DASH_LINE}"
}

# check script arguments
#----------------------------------------------------------
while getopts "Nvh" OPTION; do
  case "${OPTION}" in
    N)  SHOW_HEADER="false";;
    h)  fc_help;;
    v)  fc_version;;
    *)  fc_usage
        fc_bad_args;;
  esac
done

# main
#----------------------------------------------------------
function main()
{
  # set all needed global variables
  fc_uname
  fc_get_version
  fc_read_config

  # print header if true
  if [ "${SHOW_HEADER}" == "true" ];then
    fc_header
  fi

  # set all needed local variables
  local SSH_PROTOCOL=$(echo "${SSH_CONFIG}" | grep -i "^Protocol")
  local SSH_PROTOCOL_N=$(echo "${SSH_PROTOCOL}" | cut -d ' ' -f2)
  local MSG_PROTOCOL="SSH protocol version 1 has weaknesses"

  local SSH_ROOTLOGIN=$(echo "${SSH_CONFIG}" | grep -i "^PermitRootLogin")
  local MSG_ROOTLOGIN="It is best practice not to login as the root"

  local SSH_EMPTYPWD=$(echo "${SSH_CONFIG}" | grep -i "^PermitEmptyPasswords")
  local MSG_EMPTYPWD="Accounts should be protected and accountable"

  local SSH_USERENV=$(echo "${SSH_CONFIG}" | grep -i "^PermitUserEnvironment")
  local MSG_USERENV="You may enable users to bypass access restrictions"

  local SSH_PWDAUTH=$(echo "${SSH_CONFIG}" | grep -i "^PasswordAuthentication")
  local MSG_PWDAUTH="Better way is using public key authentication"

  local SSH_PUBKEY=$(echo "${SSH_CONFIG}" | grep -i '^PubkeyAuthentication')
  local MSG_PUBKEY="Better way is using public key authentication"

  local SSH_MAXTRIES=$(echo "${SSH_CONFIG}" | grep -i "^MaxAuthTries")
  local SSH_MAXTRIES_N=$(echo "${SSH_MAXTRIES}" | cut -d ' ' -f2)
  local MSG_MAXTRIES="Protect against brute-force attacks on the password"

  local SSH_IGNORERH=$(echo "${SSH_CONFIG}" | grep -i "^IgnoreRhosts")
  local MSG_IGNORERH="rhosts were a weak way to authenticate systems"

  local SSH_X11=$(echo "${SSH_CONFIG}" | grep -i "^X11Forwarding")
  local MSG_X11="X11 protocol was never built with security in mind"

  local SSH_USEDNS=$(echo "${SSH_CONFIG}" | grep -i "^UseDNS")
  local MSG_USEDNS="Use only when your internal DNS is properly configured"

  local SSH_LOGL=$(echo "${SSH_CONFIG}" | grep -i "^loglevel")
  local MSG_LOGL="Minimum INFO or VERBOSE should be configured"

  # print results
  if [ "${SSH_PROTOCOL_N}" -lt "2" ]; then
    printf " %-32s %-18s %s\n" \
    "${SSH_PROTOCOL}" "${TEST_FAIL}" "${MSG_PROTOCOL}"
  else
    printf " %-32s %s\n" "${SSH_PROTOCOL}" "${TEST_PASS}"
  fi

  if [ "${SSH_ROOTLOGIN}" == "permitrootlogin yes" ]; then
    printf " %-32s %-18s %s\n" \
    "${SSH_ROOTLOGIN}" "${TEST_FAIL}" "${MSG_ROOTLOGIN}"
  else
    printf " %-32s %s\n" "${SSH_ROOTLOGIN}" "${TEST_PASS}"
  fi

  if [ "${SSH_EMPTYPWD}" == "permitemptypasswords yes" ]; then
    printf " %-32s %-18s %s\n" \
    "${SSH_EMPTYPWD}" "${TEST_FAIL}" "${MSG_EMPTYPWD}"
  else
    printf " %-32s %s\n" "${SSH_EMPTYPWD}" "${TEST_PASS}"
  fi

  if [ "${SSH_USERENV}" == "permituserenvironment yes" ]; then
    printf " %-32s %-18s %s\n" "${SSH_USERENV}" "${TEST_FAIL}" "${MSG_USERENV}"
  else
    printf " %-32s %s\n" "${SSH_USERENV}" "${TEST_PASS}"
  fi

  if [ "${SSH_PWDAUTH}" == "passwordauthentication yes" ]; then
    printf " %-32s %-18s %s\n" "${SSH_PWDAUTH}" "${TEST_FAIL}" "${MSG_PWDAUTH}"
  else
    printf " %-32s %s\n" "${SSH_PWDAUTH}" "${TEST_PASS}"
  fi

  if [ "${SSH_PUBKEY}" == "pubkeyauthentication no" ]; then
    printf " %-32s %-18s %s\n" "${SSH_PUBKEY}" "${TEST_FAIL}" "${MSG_PUBKEY}"
  else
    printf " %-32s %s\n" "${SSH_PUBKEY}" "${TEST_PASS}"
  fi

  if [ "${SSH_MAXTRIES_N}" -gt "3" ]; then
    printf " %-32s %-18s %s\n" \
    "${SSH_MAXTRIES}" "${TEST_FAIL}" "${MSG_MAXTRIES}"
  else
    printf " %-32s %s\n" "${SSH_MAXTRIES}" "${TEST_PASS}"
  fi

  if [ "${SSH_IGNORERH}" == "ignorerhosts no" ]; then
    printf " %-32s %-18s %s\n" \
    "${SSH_IGNORERH}" "${TEST_FAIL}" "${MSG_IGNORERH}"
  else
    printf " %-32s %s\n" "${SSH_IGNORERH}" "${TEST_PASS}"
  fi

  if [ "${SSH_X11}" == "x11forwarding yes" ]; then
    printf " %-32s %-18s %s\n" "${SSH_X11}" "${TEST_FAIL}" "${MSG_X11}"
  else
    printf " %-32s %s\n" "${SSH_X11}" "${TEST_PASS}"
  fi

  if [ "${SSH_USEDNS}" == "usedns yes" ]; then
    printf " %-32s %-20s %s\n" "${SSH_USEDNS}" "${TEST_WARN}" "${MSG_USEDNS}"
  else
    printf " %-32s %s\n" "${SSH_USEDNS}" "${TEST_PASS}"
  fi

  if [ "${SSH_LOGL}" == "loglevel QUIET" ]; then
    printf " %-32s %-20s %s\n" "${SSH_LOGL}" "${TEST_WARN}" "${MSG_LOGL}"
  else
    printf " %-32s %s\n" "${SSH_LOGL}" "${TEST_PASS}"
  fi
}

main

# exit
#----------------------------------------------------------
exit "${SUCCESS}"
