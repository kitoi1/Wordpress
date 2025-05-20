#!/bin/bash

# Author: Kasau (Enhanced for Security)
# Purpose: Secure WordPress Recon & Assessment Script with Safety Checks
# Dependencies: wpscan, gobuster, nikto, jq, curl
# Version: 2.3
# Last Modified: $(date +%Y-%m-%d)

# === CONFIGURATION ===
TARGET="$1"
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
EXTENSIONS="php,html,json,txt"
THREADS=20  # Reduced for less aggressive scanning
WP_API_KEY="Your_WPScan_API_KEY"  # Updated API key
OUTPUT_DIR="./wp_scan_results_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="$OUTPUT_DIR/scan_log.txt"
RATE_LIMIT_DELAY=1  # Seconds between requests

# Security Controls
MAX_SCAN_DURATION=3600  # 1 hour maximum scan duration
PERMITTED_DOMAINS=("example.com" "YourDomain.com")  # Add permitted domains for safety

# === SECURITY CHECKS ===
validate_target() {
    local domain=$(echo "$TARGET" | awk -F[/:] '{print $4}')
    local safe_domain=0
    
    echo "[*] Validating target domain: $domain"
    
    # Check if target is in permitted domains
    for d in "${PERMITTED_DOMAINS[@]}"; do
        if [[ "$domain" == *"$d"* ]]; then
            safe_domain=1
            break
        fi
    done
    
    if [[ "$safe_domain" -eq 0 ]]; then
        echo "[SECURITY ERROR] Target domain not in permitted list!"
        echo "[INFO] Update the PERMITTED_DOMAINS array in the script to include: $domain"
        exit 1
    fi

    # Check if target is live
    echo "[*] Checking if target is reachable..."
    if ! curl -s --head --connect-timeout 10 "$TARGET" >/dev/null; then
        echo "[ERROR] Target appears to be down or unreachable"
        exit 1
    fi
    
    echo "[+] Target validated and is reachable"
}

check_dependencies() {
    echo "[*] Checking for required tools..."
    local missing=0
    for cmd in wpscan gobuster nikto jq curl; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "[ERROR] Missing dependency: $cmd"
            missing=$((missing + 1))
        fi
    done
    
    if [[ "$missing" -gt 0 ]]; then
        echo "[ERROR] Please install missing dependencies"
        exit 1
    fi
    
    echo "[+] All dependencies installed"
}

# === OUTPUT MANAGEMENT ===
init_output() {
    echo "[*] Creating output directory..."
    mkdir -p "$OUTPUT_DIR" || {
        echo "[ERROR] Failed to create output directory"
        exit 1
    }
    
    # Create a secure directory with proper permissions
    chmod 700 "$OUTPUT_DIR"
    
    # Create a new log file and redirect output to it
    touch "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    echo "[+] Output directory created at $OUTPUT_DIR"
}

# === SCANNING FUNCTIONS ===
run_whatweb() {
    echo "[*] Running WhatWeb (Lightweight Scan)..."
    if command -v whatweb &>/dev/null; then
        whatweb --color=never --no-errors "$TARGET" > "$OUTPUT_DIR/whatweb.txt" 2>/dev/null
        local status=$?
        if [ $status -eq 0 ] && [ -s "$OUTPUT_DIR/whatweb.txt" ]; then
            echo "[+] WhatWeb scan completed"
            return 0
        else
            echo "[!] WhatWeb scan had issues (status $status)"
            return 1
        fi
    else
        echo "[!] WhatWeb not found, skipping this step"
        return 1
    fi
}

run_wpscan() {
    echo "[*] Running WPScan (Basic Scan)..."
    if command -v wpscan &>/dev/null; then
        wpscan --url "$TARGET" \
               --api-token "$WP_API_KEY" \
               --random-user-agent \
               --throttle "$RATE_LIMIT_DELAY" \
               --format json \
               --ignore-main-redirect \
               --no-banner \
               --no-update \
               > "$OUTPUT_DIR/wpscan_basic.json" 2>>"$LOG_FILE"
        
        # Check if file exists and has content
        if [ -s "$OUTPUT_DIR/wpscan_basic.json" ]; then
            # Convert JSON to readable text
            jq '.' "$OUTPUT_DIR/wpscan_basic.json" > "$OUTPUT_DIR/wpscan_basic.txt" 2>/dev/null
            echo "[+] WPScan basic scan completed"
            return 0
        else
            echo "[!] WPScan did not produce valid output"
            return 1
        fi
    else
        echo "[!] WPScan not found, skipping this step"
        return 1
    fi
}

enumerate_users() {
    echo "[*] Enumerating Users (Safe Mode)..."
    if command -v wpscan &>/dev/null; then
        wpscan --url "$TARGET" \
               --enumerate u \
               --api-token "$WP_API_KEY" \
               --random-user-agent \
               --throttle "$RATE_LIMIT_DELAY" \
               --no-banner \
               --no-update \
               --format json > "$OUTPUT_DIR/wpscan_users.json" 2>>"$LOG_FILE"
        
        # Check if file exists and has content
        if [ -s "$OUTPUT_DIR/wpscan_users.json" ]; then
            jq '.' "$OUTPUT_DIR/wpscan_users.json" > "$OUTPUT_DIR/wpscan_users.txt" 2>/dev/null
            echo "[+] User enumeration completed"
            return 0
        else
            echo "[!] User enumeration did not produce valid output"
            return 1
        fi
    else
        echo "[!] WPScan not found, skipping this step"
        return 1
    fi
}

enumerate_plugins_themes() {
    echo "[*] Enumerating Vulnerable Plugins/Themes (Safe Mode)..."
    if command -v wpscan &>/dev/null; then
        wpscan --url "$TARGET" \
               --enumerate vp,vt \
               --api-token "$WP_API_KEY" \
               --random-user-agent \
               --throttle "$RATE_LIMIT_DELAY" \
               --no-banner \
               --no-update \
               --format json > "$OUTPUT_DIR/wpscan_vuln.json" 2>>"$LOG_FILE"
        
        # Check if file exists and has content
        if [ -s "$OUTPUT_DIR/wpscan_vuln.json" ]; then
            jq '.' "$OUTPUT_DIR/wpscan_vuln.json" > "$OUTPUT_DIR/wpscan_vuln.txt" 2>/dev/null
            echo "[+] Plugin and theme enumeration completed"
            return 0
        else
            echo "[!] Plugin and theme enumeration did not produce valid output"
            return 1
        fi
    else
        echo "[!] WPScan not found, skipping this step"
        return 1
    fi
}

run_gobuster() {
    echo "[*] Running Gobuster (Reduced Aggressiveness)..."
    if command -v gobuster &>/dev/null; then
        # Make sure we have the wordlist
        if [ ! -f "$WORDLIST" ]; then
            echo "[!] Wordlist not found: $WORDLIST"
            return 1
        fi
        
        gobuster dir -u "$TARGET" \
                    -w "$WORDLIST" \
                    -x "$EXTENSIONS" \
                    -t "$THREADS" \
                    --delay 200ms \
                    --no-error \
                    -o "$OUTPUT_DIR/gobuster.txt" 2>>"$LOG_FILE"
        
        local status=$?
        if [ $status -eq 0 ] && [ -s "$OUTPUT_DIR/gobuster.txt" ]; then
            echo "[+] Gobuster scan completed"
            return 0
        else
            echo "[!] Gobuster scan had issues (status $status)"
            # Create empty file to avoid errors later
            touch "$OUTPUT_DIR/gobuster.txt"
            return 1
        fi
    else
        echo "[!] Gobuster not found, skipping this step"
        return 1
    fi
}

run_nikto() {
    echo "[*] Running Nikto (Basic Scan)..."
    if command -v nikto &>/dev/null; then
        nikto -h "$TARGET" \
              -Tuning x4567890c \
              -nointeractive \
              -output "$OUTPUT_DIR/nikto.txt" \
              -Format txt 2>>"$LOG_FILE"
        
        local status=$?
        if [ $status -eq 0 ] && [ -s "$OUTPUT_DIR/nikto.txt" ]; then
            echo "[+] Nikto scan completed"
            return 0
        else
            echo "[!] Nikto scan had issues (status $status)"
            # Create empty file to avoid errors later
            touch "$OUTPUT_DIR/nikto.txt"
            return 1
        fi
    else
        echo "[!] Nikto not found, skipping this step"
        return 1
    fi
}

security_checks() {
    echo "[*] Performing Basic Security Checks..."
    # Create the output file first to avoid permission issues
    touch "$OUTPUT_DIR/security_checks.txt"
    
    {
        echo "=== HTTP Security Headers ==="
        curl -sI "$TARGET" | grep -iE 'strict-transport-security|x-frame-options|x-xss-protection|x-content-type-options|content-security-policy'
        
        echo -e "\n=== SSL/TLS Check ==="
        curl -sIv --connect-timeout 10 "https://$TARGET" 2>&1 | grep -iE 'SSL|TLS|HTTP/2'
        
        echo -e "\n=== WP-Config Backup Check ==="
        curl -sL --connect-timeout 10 "$TARGET/wp-config.php.bak" | head -n 5
        curl -sL --connect-timeout 10 "$TARGET/wp-config.php~" | head -n 5
        curl -sL --connect-timeout 10 "$TARGET/wp-config.php.backup" | head -n 5
        
        echo -e "\n=== XML-RPC Status Check ==="
        XMLRPC_STATUS=$(curl -sL --connect-timeout 10 -X POST "$TARGET/xmlrpc.php" -d "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" | grep -c "methodResponse")
        if [ "$XMLRPC_STATUS" -gt 0 ]; then
            echo "[VULN] XML-RPC is enabled and responding to requests"
        else
            echo "[OK] XML-RPC appears to be disabled or properly secured"
        fi
        
        echo -e "\n=== REST API Status Check ==="
        curl -sL --connect-timeout 10 "$TARGET/wp-json/" | head -n 20
        
        echo -e "\n=== Robots.txt Check ==="
        curl -sL --connect-timeout 10 "$TARGET/robots.txt"
        
    } > "$OUTPUT_DIR/security_checks.txt" 2>>"$LOG_FILE"
    
    if [ -s "$OUTPUT_DIR/security_checks.txt" ]; then
        echo "[+] Security checks completed"
        return 0
    else
        echo "[!] Security checks had issues"
        return 1
    fi
}

generate_summary() {
    echo "[*] Generating summary report..."
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Create summary file
    {
        echo "WordPress Assessment Summary"
        echo "==========================="
        echo "Target: $TARGET"
        echo "Scan Date: $(date)"
        echo "Duration: $duration seconds"
        echo -e "\n=== Findings Summary ==="
        
        if [ -f "$OUTPUT_DIR/whatweb.txt" ]; then
            echo "WhatWeb: $(wc -l < "$OUTPUT_DIR/whatweb.txt" 2>/dev/null || echo "0") findings"
        else
            echo "WhatWeb: Report not found or incomplete"
        fi
        
        if [ -f "$OUTPUT_DIR/wpscan_basic.json" ]; then
            local wp_issues=$(jq '.version.status + (.plugins | length // 0)' "$OUTPUT_DIR/wpscan_basic.json" 2>/dev/null || echo "Error processing JSON")
            echo "WPScan: $wp_issues potential issues"
        else
            echo "WPScan: Report not found or incomplete"
        fi
        
        if [ -f "$OUTPUT_DIR/gobuster.txt" ]; then
            echo "Gobuster: $(grep -c "Status: 200" "$OUTPUT_DIR/gobuster.txt" 2>/dev/null || echo "0") valid paths found"
        else
            echo "Gobuster: Report not found or incomplete"
        fi
        
        if [ -f "$OUTPUT_DIR/nikto.txt" ]; then
            echo "Nikto: $(grep -c "+" "$OUTPUT_DIR/nikto.txt" 2>/dev/null || echo "0") potential issues found"
        else
            echo "Nikto: Report not found or incomplete"
        fi
        
        if [ -f "$OUTPUT_DIR/security_checks.txt" ]; then
            echo "Security Checks: Completed"
            
            # Check for XML-RPC vulnerability
            if grep -q "\[VULN\] XML-RPC is enabled" "$OUTPUT_DIR/security_checks.txt"; then
                echo "⚠ Warning: XML-RPC is enabled and could be exploited"
            fi
            
            # Extract robots.txt content if available
            echo -e "\n=== Robots.txt Content ==="
            sed -n '/=== Robots.txt Check ===/,/^$/p' "$OUTPUT_DIR/security_checks.txt" | grep -v "=== Robots.txt Check ==="
        else
            echo "Security Checks: Not completed"
        fi
        
        # Add a timestamp for chain of custody
        echo -e "\nReport generated: $(date)"
        echo "SHA256 verification: $(find "$OUTPUT_DIR" -type f -exec sha256sum {} \; 2>/dev/null | sha256sum | cut -d' ' -f1)"
    } > "$OUTPUT_DIR/summary.txt"
    
    echo "[+] Summary report generated at $OUTPUT_DIR/summary.txt"
}

# === MAIN SCRIPT ===
main() {
    BANNER="
  ░█──░█ ░█▀▀█ ░█──░█ ─█▀▀█ ░█▀▀█ ▀▀█▀▀ ▀█▀ ░█─░█
  ░█░█░█ ░█─░█ ░█░█░█ ░█▄▄█ ░█─── ─░█── ░█─ ░█─░█
  ░█▄▀▄█ ░█▄▄█ ░█▄▀▄█ ░█─░█ ░█▄▄█ ─░█── ▄█▄ ─▀▄▄▀
  Secure WordPress Assessment Script | By Kasau | v2.3
"

    echo "$BANNER"

    # Track start time
    start_time=$(date +%s)

    # Initial checks
    if [ -z "$TARGET" ]; then
        echo "Usage: $0 http://target.com"
        echo "Security Note: Always get proper authorization before scanning!"
        exit 1
    fi

    check_dependencies
    validate_target
    init_output

    echo "[INFO] Starting scan at $(date)"
    echo "[INFO] Results will be saved to: $OUTPUT_DIR"
    echo "[SECURITY NOTICE] This scan will:"
    echo "  - Use rate limiting to avoid overwhelming the server"
    echo "  - Respect robots.txt (where supported)"
    echo "  - Only scan permitted domains"
    echo "  - Time out after $MAX_SCAN_DURATION seconds"

    # Run each scan function directly - no more subshells
    echo "[*] Starting scanning sequence..."
    
    # Run all scans sequentially
    run_whatweb
    run_wpscan
    enumerate_users
    enumerate_plugins_themes
    run_gobuster
    run_nikto
    security_checks
    
    # Generate final report
    generate_summary

    echo "[!] Assessment complete. Review all findings in $OUTPUT_DIR"
    echo "[SECURITY REMINDER] 1. Delete sensitive findings when done"
    echo "                    2. Never store raw scan data unencrypted"
    echo "                    3. Follow responsible disclosure procedures"
}

# Execute main function
main
