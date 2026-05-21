#!/usr/bin/env bash


function ctrl_c(){
    echo -e "\n\n${redColour}[+] Exiting...${endColour}\n"
    exit 1
}

# Ctrl+C
trap ctrl_c SIGINT


# Colors 
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
cyanColour="\e[0;36m\033[1m"
whiteColour="\e[0;37m\033[1m"

# Central CVE knowledge map for easier maintenance.
KERNEL_PATCH_BASELINE="7.0.8"
CVE_COPY_FAIL="CVE-2026-31431"
CVE_DIRTYFRAG="CVE-2026-43284,CVE-2026-43500"
CVE_FRAGNESIA="CVE-2026-46300"
CVE_SSHKEY_SIGN_PWN="CVE-2026-46333"

declare -A FAMILY_CVE_MAP=(
   [copy_fail]="$CVE_COPY_FAIL"
   [copyfail2_electric_boogaloo]="$CVE_COPY_FAIL"
   [dirtyfrag]="$CVE_DIRTYFRAG"
   [fragnesia]="$CVE_FRAGNESIA"
   [sshkey-sign-pwn]="$CVE_SSHKEY_SIGN_PWN"
)

get_family_cve(){
   local family="$1"
   echo "${FAMILY_CVE_MAP[$family]:-CVE-UNKNOWN}"
}

get_file_package_owner(){
   local file_path="$1"

   if command -v pacman >/dev/null 2>&1; then
      pacman -Qo "$file_path" 2>/dev/null | awk '{print $5}' | head -n1
      return
   fi

   if command -v dpkg >/dev/null 2>&1; then
      dpkg -S "$file_path" 2>/dev/null | head -n1 | cut -d: -f1
      return
   fi

   if command -v rpm >/dev/null 2>&1; then
      rpm -qf "$file_path" 2>/dev/null | head -n1
      return
   fi

   echo "unknown"
}

is_write_digit(){
   local d="$1"
   case "$d" in
      2|3|6|7)
         return 0
         ;;
      *)
         return 1
         ;;
   esac
}

check_sshkey_sign_pwn_exposure(){
   local candidate
   local ptrace_file="/proc/sys/kernel/yama/ptrace_scope"
   local userns_file="/proc/sys/kernel/unprivileged_userns_clone"
   local perm_string
   local mode_digits
   local group_digit
   local other_digit

   sshkey_ptrace_scope="unknown"
   sshkey_unpriv_userns_clone="unknown"
   sshkey_binary_path="not_found"
   sshkey_binary_owner="unknown"
   sshkey_binary_mode="unknown"
   sshkey_binary_package="unknown"
   sshkey_binary_setuid="unknown"
   sshkey_binary_group_writable="unknown"
   sshkey_binary_other_writable="unknown"
   sshkey_binary_owner_root="unknown"
   sshkey_indicator_count=0

   if [[ -r "$ptrace_file" ]]; then
      sshkey_ptrace_scope="$(tr -d '[:space:]' < "$ptrace_file")"
      if [[ "$sshkey_ptrace_scope" == "0" ]]; then
         sshkey_indicator_count=$((sshkey_indicator_count + 1))
      fi
   fi

   if [[ -r "$userns_file" ]]; then
      sshkey_unpriv_userns_clone="$(tr -d '[:space:]' < "$userns_file")"
   fi

   for candidate in /usr/lib/ssh/ssh-keysign /usr/lib/openssh/ssh-keysign /usr/libexec/openssh/ssh-keysign; do
      if [[ -e "$candidate" ]]; then
         sshkey_binary_path="$candidate"
         break
      fi
   done

   if [[ "$sshkey_binary_path" != "not_found" ]]; then
      sshkey_binary_owner="$(stat -c '%U:%G' "$sshkey_binary_path" 2>/dev/null)"
      sshkey_binary_mode="$(stat -c '%a' "$sshkey_binary_path" 2>/dev/null)"
      sshkey_binary_package="$(get_file_package_owner "$sshkey_binary_path")"
      perm_string="$(stat -c '%A' "$sshkey_binary_path" 2>/dev/null)"

      if [[ "$perm_string" =~ ^-rws ]]; then
         sshkey_binary_setuid="yes"
      else
         sshkey_binary_setuid="no"
         sshkey_indicator_count=$((sshkey_indicator_count + 1))
      fi

      if [[ "${sshkey_binary_owner%%:*}" == "root" ]]; then
         sshkey_binary_owner_root="yes"
      else
         sshkey_binary_owner_root="no"
         sshkey_indicator_count=$((sshkey_indicator_count + 1))
      fi

      mode_digits="$sshkey_binary_mode"
      group_digit="${mode_digits: -2:1}"
      other_digit="${mode_digits: -1}"

      if is_write_digit "$group_digit"; then
         sshkey_binary_group_writable="yes"
         sshkey_indicator_count=$((sshkey_indicator_count + 1))
      else
         sshkey_binary_group_writable="no"
      fi

      if is_write_digit "$other_digit"; then
         sshkey_binary_other_writable="yes"
         sshkey_indicator_count=$((sshkey_indicator_count + 1))
      else
         sshkey_binary_other_writable="no"
      fi
   fi

   if [[ "$sshkey_indicator_count" -gt 0 ]]; then
      found_sshkey_indicator=1
   fi
}

print_sshkey_sign_pwn_status(){
   if [[ "$json_mode" -eq 1 ]]; then
      return
   fi

   echo -e "${blueColour}[*] sshkey-sign-pwn runtime exposure checks (read-only):${endColour}"
   echo -e "    - CVE: $(get_family_cve "sshkey-sign-pwn")"
   echo -e "    - unknown value note: unreadable or unavailable runtime source"
   echo -e "    - ptrace_scope: ${sshkey_ptrace_scope}"
   echo -e "    - unprivileged_userns_clone: ${sshkey_unpriv_userns_clone}"
   echo -e "    - ssh-keysign path: ${sshkey_binary_path}"
   if [[ "$sshkey_binary_path" != "not_found" ]]; then
      echo -e "    - ssh-keysign owner: ${sshkey_binary_owner}"
      echo -e "    - ssh-keysign mode: ${sshkey_binary_mode}"
      echo -e "    - ssh-keysign package owner: ${sshkey_binary_package}"
      echo -e "    - ssh-keysign setuid bit present: ${sshkey_binary_setuid}"
      echo -e "    - ssh-keysign group writable: ${sshkey_binary_group_writable}"
      echo -e "    - ssh-keysign other writable: ${sshkey_binary_other_writable}"
   fi

   if [[ "$found_sshkey_indicator" -eq 1 ]]; then
      echo -e "${yellowColour}[*] sshkey-sign-pwn indicators:${endColour} ${sshkey_indicator_count} potential exposure indicator(s) detected."
      if [[ "$sshkey_ptrace_scope" == "0" ]]; then
         echo -e "    - ptrace_scope=0 allows broad same-UID ptrace; stricter values reduce attack surface."
      fi
      if [[ "$sshkey_binary_setuid" == "no" ]]; then
         echo -e "    - ssh-keysign setuid bit is absent; verify this matches your distro hardening policy."
      fi
      if [[ "$sshkey_binary_owner_root" == "no" ]]; then
         echo -e "    - ssh-keysign owner is not root; verify package integrity."
      fi
      if [[ "$sshkey_binary_group_writable" == "yes" || "$sshkey_binary_other_writable" == "yes" ]]; then
         echo -e "    - ssh-keysign binary is writable by non-owner; investigate immediately."
      fi
   else
      echo -e "${greenColour}[+] sshkey-sign-pwn indicators:${endColour} no immediate runtime exposure indicators detected by local read-only checks."
   fi
}

# This script checks for vulnerable modules in the system and provides recommendations for mitigation. It is designed to be run with root privileges to ensure it can access all necessary system information.

print_help(){
   echo "[?] Note: This script checks copy_fail, copyfail2_electric_boogaloo, dirtyfrag, fragnesia, and sshkey-sign-pwn (${CVE_SSHKEY_SIGN_PWN}). Current knowledge baseline: kernel >= ${KERNEL_PATCH_BASELINE} is treated as patched for these exploit families. copyfail2_electric_boogaloo is tracked as a copy_fail variant family and mapped to ${CVE_COPY_FAIL} for operational triage."
   echo "[?] PoC note: If a copy_fail PoC errors with FileNotFoundError at AF_ALG bind, that typically means the requested transform is unavailable. This is a PoC-path failure and not conclusive proof of full safety."
   echo -e "${yellowColour}Usage:${endColour}"
   echo "Usage: $0 [--verbose|-v] [--very-verbose|--vvv] [--json|-j] [--help|-h]"
   echo "  --verbose, -v   Show per-module loaded/blocked status for the full watchlist"
   echo "  --very-verbose, --vvv  Show module status plus install/blacklist rule contents"
   echo "  --json, -j      Output machine-readable JSON summary (modules + kernel CVEs)"
   echo "  --help, -h      Show this help message"
}

is_module_loaded(){
   local module="$1"
   grep -qE "^${module} " /proc/modules
}

is_module_blocked(){
   local module="$1"
   modprobe -n -v "$module" 2>/dev/null | grep -q '/bin/false'
}

print_module_rule_contents(){
   local module="$1"
   local rules
   local effective

   rules="$(grep -RhsE "^[[:space:]]*(install|blacklist)[[:space:]]+${module}([[:space:]]|$)" /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null | sed -E 's/^[[:space:]]+//')"

   echo -e "${cyanColour}[*] Module rules:${endColour} module=${module}"
   if [[ -n "$rules" ]]; then
      while IFS= read -r line; do
         [[ -n "$line" ]] && echo "    $line"
      done <<< "$rules"
   else
      effective="$(modprobe -n -v "$module" 2>/dev/null)"
      if echo "$effective" | grep -q '/bin/false'; then
         echo "    install ${module} /bin/false (effective via modprobe policy)"
      else
         echo "    (no install/blacklist rule found in modprobe.d paths)"
      fi
   fi
}

get_module_cve(){
   local module="$1"
   case "$module" in
      algif_aead|af_alg)
         get_family_cve "copy_fail"
         ;;
      esp4|esp6)
         get_family_cve "copyfail2_electric_boogaloo"
         ;;
      rxrpc)
         get_family_cve "dirtyfrag"
         ;;
      xfrm_user|xfrm_algo|af_key)
         get_family_cve "copyfail2_electric_boogaloo"
         ;;
      *)
         echo "CVE-UNKNOWN"
         ;;
   esac
}

get_module_family(){
   local module="$1"
   case "$module" in
      algif_aead|af_alg)
         echo "copy_fail"
         ;;
      rxrpc)
         echo "dirtyfrag"
         ;;
      esp4|esp6)
         echo "copyfail2_electric_boogaloo"
         ;;
      xfrm_user|xfrm_algo|af_key)
         echo "copyfail2_electric_boogaloo"
         ;;
      *)
         echo "misc"
         ;;
   esac
}

normalize_kernel_version(){
   local raw="$1"
   local parsed
   local major
   local minor
   local patch

   parsed="$(echo "$raw" | sed -E 's/^([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/')"
   if [[ -z "$parsed" || "$parsed" == "$raw" && ! "$raw" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)? ]]; then
      echo "0.0.0"
      return
   fi

   IFS='.' read -r major minor patch <<< "$parsed"
   patch="${patch:-0}"
   echo "${major}.${minor}.${patch}"
}

ver_ge(){
   local a="$1"
   local b="$2"
   [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$b" ]]
}

ver_lt(){
   local a="$1"
   local b="$2"
   [[ "$a" != "$b" && "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}

is_cve_2026_31431_affected(){
   local version="$1"
   local major_minor="$(echo "$version" | cut -d'.' -f1,2)"

   # Source: prior semver branches + local baseline update.
   # Baseline update: kernel >= 7.0.8 treated as patched for copy_fail/copyfail2 family.
   if ver_lt "$version" "4.14.0"; then
      return 1
   fi

   if ver_ge "$version" "$KERNEL_PATCH_BASELINE"; then
      return 1
   fi

   if [[ "$major_minor" == "7.0" ]]; then
      return 0
   fi

   case "$major_minor" in
      5.10)
         ver_lt "$version" "5.10.254"
         return
         ;;
      5.15)
         ver_lt "$version" "5.15.204"
         return
         ;;
      6.1)
         ver_lt "$version" "6.1.170"
         return
         ;;
      6.6)
         ver_lt "$version" "6.6.137"
         return
         ;;
      6.12)
         ver_lt "$version" "6.12.85"
         return
         ;;
      6.18)
         ver_lt "$version" "6.18.22"
         return
         ;;
      6.19)
         ver_lt "$version" "6.19.12"
         return
         ;;
      *)
         return 0
         ;;
   esac
}

# catch-all-evidence-and-treat-as-affected-until-official-ranges-are-published approach for dirtyfrag since the PoC signal is strong and there are known exploitable builds. This allows the script to provide a more actionable output in the face of incomplete public information, while still being transparent about the evidence and assumptions being made.
is_dirtyfrag_evidence_affected(){
   local kernel_release="$1"
   local version="$2"

   if ver_ge "$version" "$KERNEL_PATCH_BASELINE"; then
      return 1
   fi

   # Local evidence override until official semver ranges are published.
   # Confirmed exploitable by local testing on 7.0.3-arch2-1 pre-mitigation.
   if [[ "$kernel_release" == "7.0.3-arch2-1" ]]; then
      return 0
   fi

   # Placeholder for future official ranges:
   # if ver_ge "$version" "X.Y.Z" && ver_lt "$version" "A.B.C"; then return 0; fi
   return 1
}

is_baseline_7_0_8_affected(){
   local version="$1"
   ver_lt "$version" "$KERNEL_PATCH_BASELINE"
}

print_verbose_knowledge_base(){
   echo -e "${blueColour}[*] Knowledge baseline:${endColour}"
   echo -e "    - copy_fail + copyfail2_electric_boogaloo: mapped to $(get_family_cve "copy_fail") for triage."
   echo -e "    - dirtyfrag: $(get_family_cve "dirtyfrag")."
   echo -e "    - fragnesia: $(get_family_cve "fragnesia")."
   echo -e "    - sshkey-sign-pwn.c: $(get_family_cve "sshkey-sign-pwn")."
   echo -e "    - Kernel baseline status: >= ${KERNEL_PATCH_BASELINE} treated as patched for all tracked families."
}

print_module_mitigation(){
   local module="$1"

   echo -e "${blueColour}[*] Recommended mitigation for ${module}:${endColour}"
   echo -e "    - Temporary block/autoload prevention:"
   echo -e "      printf 'install ${module} /bin/false\\nblacklist ${module}\\n' | sudo tee -a /etc/modprobe.d/99-${module}-mitigation.conf >/dev/null; sudo modprobe -r ${module} 2>/dev/null || sudo rmmod ${module} 2>/dev/null"

   case "$module" in
      algif_aead|af_alg)
         echo -e "    - This is in the AF_ALG crypto path. If unneeded, keep blocked until patched kernel is installed."
         ;;
      esp4|esp6|xfrm_user|xfrm_algo|af_key)
         echo -e "    - This is in the IPsec/XFRM stack. Only keep blocked if this host does not require IPsec."
         ;;
      rxrpc)
         echo -e "    - Keep blocked unless AFS/RxRPC is explicitly required in your environment."
         ;;
   esac

   echo -e "    - Permanent fix: install vendor kernel security updates."
   echo -e "${cyanColour}      Upstream stable kernels:${endColour} https://www.kernel.org/"
   echo -e "${cyanColour}      Ubuntu security notices:${endColour} https://ubuntu.com/security/notices"
   echo -e "${cyanColour}      Debian security tracker:${endColour} https://security-tracker.debian.org/tracker/"
   echo -e "${cyanColour}      Red Hat CVE/errata:${endColour} https://access.redhat.com/security/security-updates/"
   echo -e "${cyanColour}      Arch Linux security:${endColour} https://security.archlinux.org/"
   echo
}

vulnerable=("algif_aead" "af_alg" "esp4" "esp6" "rxrpc" "xfrm_user" "xfrm_algo" "af_key")
found_vulnerable=0
found_kernel_cve=0
verbose=0
very_verbose=0
json_mode=0
json_modules=""
json_first=1
json_kernel_cves=""
json_kernel_first=1
json_sshkey_runtime="{}"
kernel_release_raw="$(uname -r)"
kernel_version="$(normalize_kernel_version "$kernel_release_raw")"
dirtyfrag_evidence_affected=0
found_sshkey_indicator=0
sshkey_indicator_count=0

while [[ $# -gt 0 ]]; do
   case "$1" in
      -v|--verbose)
         verbose=1
         ;;
      --very-verbose|--vvv)
         very_verbose=1
         verbose=1
         ;;
      -j|--json)
         json_mode=1
         ;;
      -h|--help)
         print_help
         exit 0
         ;;
      *)
         echo -e "${redColour}[-] Unknown option:${endColour} $1"
         print_help
         exit 1
         ;;
   esac
   shift
done

if [[ "$verbose" -eq 1 && "$json_mode" -eq 0 ]]; then
   print_verbose_knowledge_base
fi

check_sshkey_sign_pwn_exposure

for vuln in "${vulnerable[@]}"; do
   cve_tag="$(get_module_cve "$vuln")"
   family_tag="$(get_module_family "$vuln")"
   loaded="no"
   blocked="no"

   if is_module_loaded "$vuln"; then
      loaded="yes"
   fi

   if is_module_blocked "$vuln"; then
      blocked="yes"
   fi

   if [[ "$json_mode" -eq 1 ]]; then
      if [[ "$json_first" -eq 0 ]]; then
         json_modules+=","
      fi
      if [[ "$loaded" == "yes" ]]; then
         loaded_bool="true"
      else
         loaded_bool="false"
      fi
      if [[ "$blocked" == "yes" ]]; then
         blocked_bool="true"
      else
         blocked_bool="false"
      fi
      json_modules+="{\"module\":\"${vuln}\",\"family\":\"${family_tag}\",\"cve\":\"${cve_tag}\",\"loaded\":${loaded_bool},\"blocked\":${blocked_bool}}"
      json_first=0
   fi

   if [[ "$very_verbose" -eq 1 && "$json_mode" -eq 0 ]]; then
      print_module_rule_contents "$vuln"
   fi

   if [[ "$loaded" == "yes" ]]; then
      if [[ "$verbose" -eq 1 ]]; then
         if [[ "$blocked" == "yes" ]]; then
            echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} family=${family_tag} module=${vuln} loaded=yes blocked=yes"
         else
            echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} family=${family_tag} module=${vuln} loaded=yes blocked=no"
         fi
      fi

      if [[ "$json_mode" -eq 0 ]]; then
         echo -e "${redColour}[!] WARNING:${endColour} family=${yellowColour}${family_tag}${endColour} module=${yellowColour}${vuln}${endColour} is loaded and on the vulnerable watchlist."
         print_module_mitigation "$vuln"
      fi
      found_vulnerable=1
   elif [[ "$verbose" -eq 1 && "$json_mode" -eq 0 ]]; then
      if [[ "$blocked" == "yes" ]]; then
         echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} family=${family_tag} module=${vuln} loaded=no blocked=yes"
      else
         echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} family=${family_tag} module=${vuln} loaded=no blocked=no"
      fi
   fi
done

if is_cve_2026_31431_affected "$kernel_version"; then
   found_kernel_cve=1
   if [[ "$json_mode" -eq 1 ]]; then
      json_kernel_cves+="{\"cve\":\"${CVE_COPY_FAIL}\",\"family\":\"copy_fail\",\"affected\":true,\"kernel\":\"${kernel_version}\",\"fixed_branches\":[\"5.10.254\",\"5.15.204\",\"6.1.170\",\"6.6.137\",\"6.12.85\",\"6.18.22\",\"6.19.12\",\"${KERNEL_PATCH_BASELINE}+\"]}"
      json_kernel_first=0
   else
      echo -e "${redColour}[!] Kernel CVE match:${endColour} ${yellowColour}${CVE_COPY_FAIL}${endColour} applies to kernel ${yellowColour}${kernel_version}${endColour} (family=copy_fail)."
      echo -e "${blueColour}[*] Fixed versions:${endColour} 5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12, ${KERNEL_PATCH_BASELINE}+"
      if [[ "$verbose" -eq 1 ]]; then
         echo -e "${yellowColour}[*] Variant mapping:${endColour} copyfail2_electric_boogaloo is currently treated as part of this CVE family for triage."
      fi
   fi
elif [[ "$json_mode" -eq 0 ]]; then
   echo -e "${greenColour}[+] Kernel check:${endColour} ${yellowColour}${kernel_version}${endColour} is not matched as affected by ${CVE_COPY_FAIL}."
fi

if is_dirtyfrag_evidence_affected "$kernel_release_raw" "$kernel_version"; then
   found_kernel_cve=1
   dirtyfrag_evidence_affected=1
   if [[ "$json_mode" -eq 1 ]]; then
      if [[ "$json_kernel_first" -eq 0 ]]; then
         json_kernel_cves+="," 
      fi
      json_kernel_cves+="{\"cve\":\"${CVE_DIRTYFRAG}\",\"family\":\"dirtyfrag\",\"affected\":true,\"kernel\":\"${kernel_version}\",\"kernel_release\":\"${kernel_release_raw}\",\"source\":\"evidence_override\",\"note\":\"Known exploitable build(s) detected; treat as vulnerable until official semver ranges are published\"}"
      json_kernel_first=0
   else
      echo -e "${redColour}[!] Kernel evidence match:${endColour} ${yellowColour}dirtyfrag${endColour} treated as affected on ${yellowColour}${kernel_release_raw}${endColour} (source=evidence_override)."
      echo -e "${yellowColour}[*] Dirtyfrag CVEs:${endColour} ${CVE_DIRTYFRAG}"
      echo -e "${yellowColour}[*] Advisory:${endColour} Do not assume latest kernel is safe for dirtyfrag until official fixed ranges are published."
   fi
fi

if [[ "$json_mode" -eq 1 ]]; then
   if [[ "$json_kernel_first" -eq 0 ]]; then
      json_kernel_cves+=","
   fi
   if is_baseline_7_0_8_affected "$kernel_version"; then
      fragnesia_affected="true"
      sshkey_affected="true"
      copyfail2_affected="true"
      found_kernel_cve=1
   else
      fragnesia_affected="false"
      sshkey_affected="false"
      copyfail2_affected="false"
   fi
   json_kernel_cves+="{\"cve\":\"$(get_family_cve "copyfail2_electric_boogaloo")\",\"family\":\"copyfail2_electric_boogaloo\",\"affected\":${copyfail2_affected},\"kernel\":\"${kernel_version}\",\"source\":\"knowledge_baseline_7_0_8\",\"note\":\"Tracked as copy_fail variant family\"}"
   json_kernel_cves+=",{\"cve\":\"$(get_family_cve "fragnesia")\",\"family\":\"fragnesia\",\"affected\":${fragnesia_affected},\"kernel\":\"${kernel_version}\",\"source\":\"knowledge_baseline_7_0_8\",\"note\":\"Kernel >= ${KERNEL_PATCH_BASELINE} treated as patched\"}"
   json_kernel_cves+=",{\"cve\":\"$(get_family_cve "sshkey-sign-pwn")\",\"family\":\"sshkey-sign-pwn\",\"affected\":${sshkey_affected},\"kernel\":\"${kernel_version}\",\"source\":\"knowledge_baseline_7_0_8\",\"note\":\"Kernel >= ${KERNEL_PATCH_BASELINE} treated as patched\"}"

   if [[ "$found_sshkey_indicator" -eq 1 ]]; then
      sshkey_runtime_risk="true"
   else
      sshkey_runtime_risk="false"
   fi
   json_sshkey_runtime="{\"cve\":\"$(get_family_cve "sshkey-sign-pwn")\",\"indicator_count\":${sshkey_indicator_count},\"risk_detected\":${sshkey_runtime_risk},\"unknown_value_note\":\"unreadable_or_unavailable_runtime_source\",\"ptrace_scope\":\"${sshkey_ptrace_scope}\",\"unprivileged_userns_clone\":\"${sshkey_unpriv_userns_clone}\",\"binary_path\":\"${sshkey_binary_path}\",\"binary_owner\":\"${sshkey_binary_owner}\",\"binary_mode\":\"${sshkey_binary_mode}\",\"binary_package\":\"${sshkey_binary_package}\",\"binary_setuid\":\"${sshkey_binary_setuid}\",\"binary_group_writable\":\"${sshkey_binary_group_writable}\",\"binary_other_writable\":\"${sshkey_binary_other_writable}\"}"
else
   echo -e "${blueColour}[*] Kernel release:${endColour} raw=${kernel_release_raw} normalized=${kernel_version}"
   if is_baseline_7_0_8_affected "$kernel_version"; then
      found_kernel_cve=1
      echo -e "${redColour}[!] Baseline advisory:${endColour} Kernel ${yellowColour}${kernel_version}${endColour} is below ${KERNEL_PATCH_BASELINE} and treated as potentially affected by copyfail2_electric_boogaloo, fragnesia, and sshkey-sign-pwn exploit families."
   else
      echo -e "${greenColour}[+] Baseline advisory:${endColour} Kernel ${yellowColour}${kernel_version}${endColour} meets ${KERNEL_PATCH_BASELINE}+ patched baseline for copyfail2_electric_boogaloo, dirtyfrag, fragnesia, and sshkey-sign-pwn exploit families."
   fi
   if [[ "$verbose" -eq 1 ]]; then
      echo -e "${yellowColour}[*] Family breakdown:${endColour} copy_fail($(get_family_cve "copy_fail")), copyfail2_electric_boogaloo(mapped to $(get_family_cve "copyfail2_electric_boogaloo")), dirtyfrag($(get_family_cve "dirtyfrag")), fragnesia($(get_family_cve "fragnesia")), sshkey-sign-pwn($(get_family_cve "sshkey-sign-pwn"))."
   fi
   print_sshkey_sign_pwn_status
   echo -e "${yellowColour}[*] PoC signal note:${endColour} copy_fail AF_ALG ${cyanColour}FileNotFoundError${endColour} at bind usually indicates missing transform support (PoC-path failure only, non-conclusive hardening signal)."
fi

if [[ "$json_mode" -eq 1 ]]; then
   if [[ "$found_vulnerable" -eq 0 && "$found_kernel_cve" -eq 0 && "$found_sshkey_indicator" -eq 0 ]]; then
      status="all_clear"
      risk_bool="false"
   else
      status="risk_detected"
      risk_bool="true"
   fi
   if [[ "$found_vulnerable" -eq 1 ]]; then
      found_modules_bool="true"
   else
      found_modules_bool="false"
   fi
   if [[ "$found_kernel_cve" -eq 1 ]]; then
      kernel_bool="true"
   else
      kernel_bool="false"
   fi

   if [[ "$found_sshkey_indicator" -eq 1 ]]; then
      sshkey_indicator_bool="true"
   else
      sshkey_indicator_bool="false"
   fi

   printf '{"status":"%s","risk_detected":%s,"found_vulnerable":%s,"found_kernel_cve":%s,"found_sshkey_indicator":%s,"kernel_release":"%s","kernel_version":"%s","modules":[%s],"kernel_cves":[%s],"sshkey_runtime":%s}\n' "$status" "$risk_bool" "$found_modules_bool" "$kernel_bool" "$sshkey_indicator_bool" "$kernel_release_raw" "$kernel_version" "$json_modules" "$json_kernel_cves" "$json_sshkey_runtime"
else
   if [[ "$found_vulnerable" -eq 0 && "$found_kernel_cve" -eq 0 && "$found_sshkey_indicator" -eq 0 ]]; then
      echo -e "${greenColour}[+] All clear:${endColour} No loaded watchlist modules and no matched known kernel CVEs."
   else
      echo -e "${redColour}[-] Risk detected:${endColour} One or more watchlist module, kernel CVE, or sshkey-sign-pwn runtime indicator checks indicate risk."
   fi

   if [[ "$verbose" -eq 1 && "$json_mode" -eq 0 ]]; then
      echo -e "${yellowColour}[*] Note:${endColour} For the most accurate details in ${cyanColour}-v/--verbose${endColour} and ${cyanColour}--very-verbose/--vvv${endColour}, it is recommended to run all flags as root."
   fi
fi
