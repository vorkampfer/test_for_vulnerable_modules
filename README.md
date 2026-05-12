# Test for vulnerable modules.
1. This script will only detect vulnerable modules used in copy_fail, dirtyfrag, copyfail2, etc...
2. It will also give you the official pages to visit to mitigate the exploit.
3. $ chmod u+x check_vuln_modules.sh
4. $ ./check_vuln_modules.sh

### Example:
```
ᐅ check_vuln_modules.sh --verbose
[*] Verbose: module=algif_aead loaded=no blocked=yes
[*] Verbose: module=af_alg loaded=no blocked=no
[*] Verbose: module=esp4 loaded=no blocked=yes
[*] Verbose: module=esp6 loaded=no blocked=yes
[*] Verbose: module=rxrpc loaded=no blocked=yes
[*] Verbose: module=xfrm_user loaded=no blocked=no
[*] Verbose: module=xfrm_algo loaded=no blocked=no
[*] Verbose: module=af_key loaded=no blocked=no
[+] All clear: No modules from the vulnerable watchlist are currently loaded.
```
### Example:
```
ᐅ check_vuln_modules.sh --json --verbose | jq
{
  "status": "all_clear",
  "found_vulnerable": false,
  "modules": [
    {
      "module": "algif_aead",
      "cve": "CVE-2026-31431",
      "loaded": false,
      "blocked": true
    },
    {
      "module": "af_alg",
      "cve": "CVE-2026-31431",
      "loaded": false,
      "blocked": false
    },<SNIP>
```
