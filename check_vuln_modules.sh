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

# This script checks for vulnerable modules in the system and provides recommendations for mitigation. It is designed to be run with root privileges to ensure it can access all necessary system information.

print_help(){
   echo "[?] Note: This script checks for copy_fail, copyfail2_electric_boogaloo, dirtyfrag, fragnesia, and related module vulnerabilities. ESP/XFRM module checks are shown as pending advisory status when no verified CVE naming is available. Kernel checks include CVE-2026-31431, dirtyfrag CVEs (CVE-2026-43284/CVE-2026-43500), and fragnesia CVE-2026-46300. As of now, 7.0.x kernels should be treated as dirtyfrag-affected until official fixed ranges are published (7.0.4 may change this)."
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
         echo "CVE-2026-31431"
         ;;
      esp4|esp6)
         echo "CVE-PENDING-ESP-XFRM"
         ;;
      rxrpc)
         echo "CVE-2026-43284,CVE-2026-43500"
         ;;
      xfrm_user|xfrm_algo|af_key)
         echo "CVE-PENDING-COPYFAIL2"
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
         echo "esp_xfrm_pending"
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

   # Source: MITRE CVE JSON semver branches.
   # affected from 4.14+, fixed on stable branches listed below, and 7.0+ marked fixed.
   if ver_lt "$version" "4.14.0"; then
      return 1
   fi

   if ver_ge "$version" "7.0.0"; then
      return 1
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

is_dirtyfrag_evidence_affected(){
   local kernel_release="$1"
   local version="$2"

   # Local evidence override until official semver ranges are published.
   # Confirmed exploitable by local testing on 7.0.3-arch1-2 pre-mitigation.
   if [[ "$kernel_release" == "7.0.3-arch1-2" ]]; then
      return 0
   fi

   # Conservative Arch policy to avoid false sense of safety while ranges are unpublished.
   if [[ "$kernel_release" == 7.0.*-arch* ]]; then
      return 0
   fi

   # Placeholder for future official ranges:
   # if ver_ge "$version" "X.Y.Z" && ver_lt "$version" "A.B.C"; then return 0; fi
   return 1
}

print_module_mitigation(){
   local module="$1"

   echo -e "${blueColour}[*] Recommended mitigation for ${module}:${endColour}"
   echo -e "    - Temporary block/autoload prevention:"
   echo -e "      sudo tee /etc/modprobe.d/99-${module}-mitigation.conf <<EOF"
   echo -e "      install ${module} /bin/false"
   echo -e "      blacklist ${module}"
   echo -e "      EOF"
   echo -e "      sudo modprobe -r ${module} 2>/dev/null || sudo rmmod ${module} 2>/dev/null"

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
kernel_release_raw="$(uname -r)"
kernel_version="$(normalize_kernel_version "$kernel_release_raw")"
dirtyfrag_evidence_affected=0

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
      json_kernel_cves+="{\"cve\":\"CVE-2026-31431\",\"family\":\"copy_fail\",\"affected\":true,\"kernel\":\"${kernel_version}\",\"fixed_branches\":[\"5.10.254\",\"5.15.204\",\"6.1.170\",\"6.6.137\",\"6.12.85\",\"6.18.22\",\"6.19.12\",\"7.0+\"]}"
      json_kernel_first=0
   else
      echo -e "${redColour}[!] Kernel CVE match:${endColour} ${yellowColour}CVE-2026-31431${endColour} applies to kernel ${yellowColour}${kernel_version}${endColour} (family=copy_fail)."
      echo -e "${blueColour}[*] Fixed versions:${endColour} 5.10.254, 5.15.204, 6.1.170, 6.6.137, 6.12.85, 6.18.22, 6.19.12, 7.0+"
   fi
elif [[ "$json_mode" -eq 0 ]]; then
   echo -e "${greenColour}[+] Kernel check:${endColour} ${yellowColour}${kernel_version}${endColour} is not matched as affected by CVE-2026-31431."
fi

if is_dirtyfrag_evidence_affected "$kernel_release_raw" "$kernel_version"; then
   found_kernel_cve=1
   dirtyfrag_evidence_affected=1
   if [[ "$json_mode" -eq 1 ]]; then
      if [[ "$json_kernel_first" -eq 0 ]]; then
         json_kernel_cves+="," 
      fi
      json_kernel_cves+="{\"cve\":\"CVE-2026-43284,CVE-2026-43500\",\"family\":\"dirtyfrag\",\"affected\":true,\"kernel\":\"${kernel_version}\",\"kernel_release\":\"${kernel_release_raw}\",\"source\":\"evidence_override\",\"note\":\"Known exploitable build(s) detected; treat as vulnerable until official semver ranges are published\"}"
      json_kernel_first=0
   else
      echo -e "${redColour}[!] Kernel evidence match:${endColour} ${yellowColour}dirtyfrag${endColour} treated as affected on ${yellowColour}${kernel_release_raw}${endColour} (source=evidence_override)."
      echo -e "${yellowColour}[*] Dirtyfrag CVEs:${endColour} CVE-2026-43284, CVE-2026-43500"
      echo -e "${yellowColour}[*] Advisory:${endColour} Do not assume latest kernel is safe for dirtyfrag until official fixed ranges are published."
   fi
fi

if [[ "$json_mode" -eq 1 ]]; then
   if [[ "$dirtyfrag_evidence_affected" -eq 0 ]]; then
      if [[ "$json_kernel_first" -eq 0 ]]; then
         json_kernel_cves+=","
      fi
      json_kernel_cves+="{\"cve\":\"CVE-2026-43284,CVE-2026-43500\",\"family\":\"dirtyfrag\",\"affected\":null,\"kernel\":\"${kernel_version}\",\"source\":\"unpublished_range\",\"note\":\"CVE IDs are known; public semver affected ranges are not published yet\"}"
      json_kernel_first=0
   fi
   if [[ "$json_kernel_first" -eq 0 ]]; then
      json_kernel_cves+=","
   fi
   json_kernel_cves+="{\"cve\":\"CVE-PENDING-ESP-XFRM\",\"family\":\"esp_xfrm_pending\",\"affected\":null,\"kernel\":\"${kernel_version}\",\"source\":\"unpublished_range\",\"note\":\"No verified public CVE naming/source for this advisory label yet\"}"
   json_kernel_cves+=",{\"cve\":\"CVE-2026-46300\",\"family\":\"fragnesia\",\"affected\":null,\"kernel\":\"${kernel_version}\",\"source\":\"unpublished_range\",\"note\":\"CVE ID is known; public semver affected ranges are not published yet\"}"
   json_kernel_cves+=",{\"cve\":\"CVE-PENDING-COPYFAIL2\",\"family\":\"copyfail2_electric_boogaloo\",\"affected\":null,\"kernel\":\"${kernel_version}\",\"note\":\"Public semver affected ranges are not published yet\"}"
else
   echo -e "${blueColour}[*] Kernel release:${endColour} raw=${kernel_release_raw} normalized=${kernel_version}"
   if [[ "$dirtyfrag_evidence_affected" -eq 0 ]]; then
      echo -e "${yellowColour}[*] Pending kernel advisories:${endColour} dirtyfrag (CVE-2026-43284/CVE-2026-43500), ESP/XFRM pending advisory (unverified CVE naming), fragnesia (CVE-2026-46300), copyfail2_electric_boogaloo (semver ranges not published yet)."
   else
      echo -e "${yellowColour}[*] Pending kernel advisories:${endColour} ESP/XFRM pending advisory (unverified CVE naming), fragnesia (CVE-2026-46300), copyfail2_electric_boogaloo (semver ranges not published yet)."
   fi
fi

if [[ "$json_mode" -eq 1 ]]; then
   if [[ "$found_vulnerable" -eq 0 && "$found_kernel_cve" -eq 0 ]]; then
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
   printf '{"status":"%s","risk_detected":%s,"found_vulnerable":%s,"found_kernel_cve":%s,"kernel_release":"%s","kernel_version":"%s","modules":[%s],"kernel_cves":[%s]}\n' "$status" "$risk_bool" "$found_modules_bool" "$kernel_bool" "$kernel_release_raw" "$kernel_version" "$json_modules" "$json_kernel_cves"
else
   if [[ "$found_vulnerable" -eq 0 && "$found_kernel_cve" -eq 0 ]]; then
      echo -e "${greenColour}[+] All clear:${endColour} No loaded watchlist modules and no matched known kernel CVEs."
   else
      echo -e "${redColour}[-] Risk detected:${endColour} One or more watchlist module or kernel CVE checks indicate risk."
   fi
fi
