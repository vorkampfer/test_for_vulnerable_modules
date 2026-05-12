#!/usr/bin/bash


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
   echo "Usage: $0 [--verbose|-v] [--json|-j] [--help|-h]"
   echo "  --verbose, -v   Show per-module loaded/blocked status for the full watchlist"
   echo "  --json, -j      Output machine-readable JSON summary"
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

get_module_cve(){
   local module="$1"
   case "$module" in
      algif_aead|af_alg)
         echo "CVE-2026-31431"
         ;;
      esp4|esp6|xfrm_user|xfrm_algo|af_key)
         echo "CVE-PENDING"
         ;;
      rxrpc)
         echo "CVE-PENDING"
         ;;
      *)
         echo "CVE-UNKNOWN"
         ;;
   esac
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
verbose=0
json_mode=0
json_modules=""
json_first=1

while [[ $# -gt 0 ]]; do
   case "$1" in
      -v|--verbose)
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
      json_modules+="{\"module\":\"${vuln}\",\"cve\":\"${cve_tag}\",\"loaded\":${loaded_bool},\"blocked\":${blocked_bool}}"
      json_first=0
   fi

   if [[ "$loaded" == "yes" ]]; then
      if [[ "$verbose" -eq 1 ]]; then
         if [[ "$blocked" == "yes" ]]; then
            echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} module=${vuln} loaded=yes blocked=yes"
         else
            echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} module=${vuln} loaded=yes blocked=no"
         fi
      fi

      if [[ "$json_mode" -eq 0 ]]; then
         echo -e "${redColour}[!] WARNING:${endColour} ${yellowColour}$vuln${endColour} is loaded and is on the vulnerable watchlist."
         print_module_mitigation "$vuln"
      fi
      found_vulnerable=1
   elif [[ "$verbose" -eq 1 && "$json_mode" -eq 0 ]]; then
      if [[ "$blocked" == "yes" ]]; then
         echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} module=${vuln} loaded=no blocked=yes"
      else
         echo -e "${yellowColour}[*] [${cve_tag}]:${endColour} module=${vuln} loaded=no blocked=no"
      fi
   fi
done

if [[ "$json_mode" -eq 1 ]]; then
   if [[ "$found_vulnerable" -eq 0 ]]; then
      status="all_clear"
      found_bool="false"
   else
      status="risk_detected"
      found_bool="true"
   fi
   printf '{"status":"%s","found_vulnerable":%s,"modules":[%s]}\n' "$status" "$found_bool" "$json_modules"
else
   if [[ "$found_vulnerable" -eq 0 ]]; then
      echo -e "${greenColour}[+] All clear:${endColour} No modules from the vulnerable watchlist are currently loaded."
   else
      echo -e "${redColour}[-] Risk detected:${endColour} One or more vulnerable watchlist modules are loaded."
   fi
fi
