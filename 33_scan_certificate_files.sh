#!/system/bin/sh
# DROID FORENSIC - Certificate File Scanner
# Scans filesystem for certificate files stored outside Android Keystore
# Detects private keys and highlights immediate security risks
# Usage: sh 33_scan_certificate_files.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/scan_certificate_files.txt"

echo "[*] Scanning for certificate files outside keystore..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  CERTIFICATE FILE SCANNER"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Scanning for certificate/key files stored outside Android Keystore."
    echo "Private keys found on filesystem = CRITICAL security vulnerability"
    echo ""

    # Resolve real path to handle /sdcard -> /storage/emulated/0 symlink
    REAL_OUTPUT_BASE=$(readlink -f "${OUTPUT_DIR}/.." 2>/dev/null || cd "${OUTPUT_DIR}/.." 2>/dev/null && pwd)

    # Initialize counters
    TOTAL_CERT_FILES=0
    PRIVATE_KEY_FILES=0
    CRITICAL_FINDINGS=0

    # Certificate file extensions to search
    CERT_EXTENSIONS="pem crt cer der p12 pfx p7b p7c pkcs12 pkcs7 pkcs8 key priv pub jks bks keystore truststore"
    
    # Certificate-related keywords in filenames
    CERT_KEYWORDS="cert certificate ssl tls ca root intermediate signing client server private public key credential secret token"

    # Directories to scan (prioritized by risk)
    SCAN_DIRS="/data/data /data/app /sdcard /storage /data/local /data/misc /system/etc /vendor/etc /product/etc"

    # Private key indicators (content patterns)
    PRIVATE_KEY_PATTERNS="PRIVATE KEY|ENCRYPTED PRIVATE KEY|RSA PRIVATE|EC PRIVATE|DSA PRIVATE|OPENSSH PRIVATE|PGP PRIVATE|BEGIN PRIVATE|PKCS#8"
    
    # Certificate indicators
    CERT_PATTERNS="BEGIN CERTIFICATE|BEGIN X509|BEGIN TRUSTED"

    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ██████ CRITICAL: PRIVATE KEY FILE SCAN ██████              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Private keys on filesystem are IMMEDIATE security risks!"
    echo "These should ALWAYS be stored in Android Keystore."
    echo ""

    # Function to check if file contains private key
    check_private_key() {
        file="$1"
        content=""
        
        # Read first 4KB of file
        content=$(head -c 4096 "$file" 2>/dev/null)
        
        # Check for PEM-encoded private keys
        if echo "$content" | grep -qE "PRIVATE KEY"; then
            return 0
        fi
        
        # Check for binary PKCS#12/PFX (magic bytes)
        if head -c 4 "$file" 2>/dev/null | od -An -tx1 | grep -q "30 82"; then
            # Could be PKCS#12 or DER certificate - need deeper check
            if echo "$content" | od -An -tx1 | grep -qE "30 82.*02 01 03"; then
                return 0  # PKCS#12 structure
            fi
        fi
        
        return 1
    }

    # Scan for files by extension
    echo "--- Scanning by file extension ---"
    echo ""
    
    for ext in $CERT_EXTENSIONS; do
        for dir in $SCAN_DIRS; do
            if [ -d "$dir" ]; then
                find "$dir" ! -path "${OUTPUT_DIR}/*" -name "*.$ext" -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
                    TOTAL_CERT_FILES=$((TOTAL_CERT_FILES + 1))
                    
                    # Get file details
                    FILE_SIZE=$(ls -la "$file" 2>/dev/null | awk '{print $5}')
                    FILE_PERMS=$(ls -la "$file" 2>/dev/null | awk '{print $1}')
                    FILE_OWNER=$(ls -la "$file" 2>/dev/null | awk '{print $3":"$4}')
                    
                    # Check for private key content
                    if check_private_key "$file"; then
                        PRIVATE_KEY_FILES=$((PRIVATE_KEY_FILES + 1))
                        CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                        echo "████████████████████████████████████████████████████████████"
                        echo "██ [CRITICAL] PRIVATE KEY FOUND ██"
                        echo "████████████████████████████████████████████████████████████"
                        echo "  File: $file"
                        echo "  Size: $FILE_SIZE bytes"
                        echo "  Perms: $FILE_PERMS"
                        echo "  Owner: $FILE_OWNER"
                        echo ""
                        echo "  Key Type Detection:"
                        head -c 2048 "$file" 2>/dev/null | grep -oE "(RSA|EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY" | head -1 | sed 's/^/    /'
                        echo ""
                        echo "  First 5 lines:"
                        head -5 "$file" 2>/dev/null | sed 's/^/    /'
                        echo ""
                        echo "  RISK: Private key exposed on filesystem!"
                        echo "  ACTION: Move to Android Keystore immediately"
                        echo "████████████████████████████████████████████████████████████"
                        echo ""
                    fi
                done
            fi
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CERTIFICATE FILES BY EXTENSION                             │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Detailed scan by extension type
    echo "=== PEM Files (.pem) ==="
    echo "PEM format - Base64 encoded, may contain certs or keys"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" -name "*.pem" -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            echo "  [PEM] $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            # Identify content type
            CONTENT_TYPE=""
            if grep -q "PRIVATE KEY" "$file" 2>/dev/null; then
                CONTENT_TYPE="[PRIVATE KEY - CRITICAL]"
            elif grep -q "CERTIFICATE" "$file" 2>/dev/null; then
                CONTENT_TYPE="[CERTIFICATE]"
            elif grep -q "PUBLIC KEY" "$file" 2>/dev/null; then
                CONTENT_TYPE="[PUBLIC KEY]"
            fi
            echo "    Content: $CONTENT_TYPE"
            echo ""
        done
    done

    echo "=== DER Files (.der, .cer, .crt) ==="
    echo "DER format - Binary encoded certificates"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.der" -o -name "*.cer" -o -name "*.crt" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            echo "  [DER/CER/CRT] $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            # Try to parse with openssl
            SUBJECT=$(openssl x509 -in "$file" -inform DER -noout -subject 2>/dev/null || openssl x509 -in "$file" -inform PEM -noout -subject 2>/dev/null)
            if [ -n "$SUBJECT" ]; then
                echo "    $SUBJECT"
            fi
            echo ""
        done
    done

    echo "=== PKCS#12 Files (.p12, .pfx, .pkcs12) ==="
    echo "PKCS#12 - Container format, often contains private keys!"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.p12" -o -name "*.pfx" -o -name "*.pkcs12" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
            echo "  ██ [HIGH RISK] PKCS#12: $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            echo "    WARNING: PKCS#12 files typically contain private keys!"
            echo "    These should be password-protected and not stored on device"
            echo ""
        done
    done

    echo "=== PKCS#7 Files (.p7b, .p7c, .pkcs7) ==="
    echo "PKCS#7 - Certificate chain format (no private keys)"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.p7b" -o -name "*.p7c" -o -name "*.pkcs7" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            echo "  [P7] $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            echo ""
        done
    done

    echo "=== Java/Bouncy Castle Keystores (.jks, .bks, .keystore) ==="
    echo "Java keystores - may contain private keys"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.jks" -o -name "*.bks" -o -name "*.keystore" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
            echo "  ██ [HIGH RISK] KEYSTORE: $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            echo "    WARNING: Keystores may contain private keys!"
            echo "    Use: keytool -list -keystore $file"
            echo ""
        done
    done

    echo "=== Standalone Key Files (.key, .priv, .private) ==="
    echo "Explicit key files - highest risk"
    echo ""
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.key" -o -name "*.priv" -o -name "*.private" -o -name "*_key" -o -name "*_priv" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
            echo "  ██ [CRITICAL] KEY FILE: $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
            head -3 "$file" 2>/dev/null | sed 's/^/    /'
            echo ""
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ KEYWORD-BASED CERTIFICATE FILE SEARCH                      │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Searching for files with certificate-related names..."
    echo ""

    # Search by filename keywords
    for keyword in cert certificate ssl tls private_key privkey client_cert server_cert ca_cert root_cert; do
        for dir in $SCAN_DIRS; do
            find "$dir" ! -path "${OUTPUT_DIR}/*" -iname "*${keyword}*" -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | grep -vE "\.(apk|dex|jar|so|odex|vdex|art)$" | while read file; do
                echo "  [KEYWORD:$keyword] $file"
                ls -la "$file" 2>/dev/null | sed 's/^/    /'
                
                # Quick content check for private keys
                if head -c 1024 "$file" 2>/dev/null | grep -q "PRIVATE KEY"; then
                    echo "    ██ CONTAINS PRIVATE KEY - CRITICAL ██"
                fi
                echo ""
            done
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CONTENT-BASED PRIVATE KEY DETECTION                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Deep scan for PEM-encoded private keys in any file..."
    echo ""

    # Scan common data directories for private key content
    for dir in /data/data /sdcard /data/local/tmp; do
        if [ -d "$dir" ]; then
            # Search for files containing private key headers
            grep -rl "PRIVATE KEY" "$dir" 2>/dev/null | grep -v "^${OUTPUT_DIR}/\|^${REAL_OUTPUT_BASE}/forensic_" | head -50 | while read file; do
                # Skip binary files and known safe locations
                if file "$file" 2>/dev/null | grep -qE "text|ASCII|PEM"; then
                    CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                    echo "████████████████████████████████████████████████████████████"
                    echo "██ [CRITICAL] PRIVATE KEY CONTENT DETECTED ██"
                    echo "████████████████████████████████████████████████████████████"
                    echo "  File: $file"
                    ls -la "$file" 2>/dev/null | sed 's/^/    /'
                    echo ""
                    echo "  Key header found:"
                    grep -E "BEGIN.*PRIVATE KEY" "$file" 2>/dev/null | head -3 | sed 's/^/    /'
                    echo ""
                fi
            done
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APP-SPECIFIC CERTIFICATE SCAN                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Scanning app data directories for embedded certificates..."
    echo ""

    # Scan each app's data directory
    for app_dir in /data/data/*; do
        if [ -d "$app_dir" ]; then
            APP_NAME=$(basename "$app_dir")
            
            # Find cert files in app directory
            CERT_FILES=$(find "$app_dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.p12" -o -name "*.pfx" -o -name "*.key" -o -name "*.jks" -o -name "*.bks" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_")
            
            if [ -n "$CERT_FILES" ]; then
                echo "═══════════════════════════════════════════════════════════"
                echo "App: $APP_NAME"
                echo "═══════════════════════════════════════════════════════════"
                
                echo "$CERT_FILES" | while read cert_file; do
                    echo "  Found: $cert_file"
                    ls -la "$cert_file" 2>/dev/null | sed 's/^/    /'
                    
                    # Check for private key
                    if head -c 2048 "$cert_file" 2>/dev/null | grep -q "PRIVATE KEY"; then
                        echo "    ██ [CRITICAL] CONTAINS PRIVATE KEY ██"
                    fi
                    echo ""
                done
            fi
        fi
    done 2>/dev/null

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APK EMBEDDED CERTIFICATE SCAN                              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Scanning APKs for embedded certificate/key files..."
    echo "(Limited to first 20 third-party apps)"
    echo ""

    # Check APKs for embedded certs
    pm list packages -3 -f 2>/dev/null | head -20 | while read pkg_line; do
        APK_PATH=$(echo "$pkg_line" | sed 's/package://;s/=.*//')
        PKG_NAME=$(echo "$pkg_line" | sed 's/.*=//')
        
        if [ -f "$APK_PATH" ]; then
            # List files in APK matching cert patterns
            EMBEDDED=$(unzip -l "$APK_PATH" 2>/dev/null | grep -iE "\.(pem|crt|cer|p12|pfx|key|jks|bks|der)$|certificate|private.*key")
            
            if [ -n "$EMBEDDED" ]; then
                echo "═══════════════════════════════════════════════════════════"
                echo "APK: $PKG_NAME"
                echo "Path: $APK_PATH"
                echo "═══════════════════════════════════════════════════════════"
                echo "$EMBEDDED" | sed 's/^/  /'
                
                # Extract and check for private keys
                echo "$EMBEDDED" | grep -iE "\.(pem|key|p12|pfx)$" | awk '{print $NF}' | while read embedded_file; do
                    CONTENT=$(unzip -p "$APK_PATH" "$embedded_file" 2>/dev/null | head -c 1024)
                    if echo "$CONTENT" | grep -q "PRIVATE KEY"; then
                        echo ""
                        echo "  ██ [CRITICAL] $embedded_file CONTAINS PRIVATE KEY ██"
                    fi
                done
                echo ""
            fi
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ASSETS/RAW RESOURCE CERTIFICATE SCAN                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Checking APK assets/res directories for certificates..."
    echo ""

    pm list packages -3 -f 2>/dev/null | head -20 | while read pkg_line; do
        APK_PATH=$(echo "$pkg_line" | sed 's/package://;s/=.*//')
        PKG_NAME=$(echo "$pkg_line" | sed 's/.*=//')
        
        if [ -f "$APK_PATH" ]; then
            # Check assets and res/raw
            ASSETS_CERTS=$(unzip -l "$APK_PATH" 2>/dev/null | grep -E "^.*assets/.*\.(pem|crt|cer|p12|pfx|key|der)|^.*res/raw/.*")
            
            if [ -n "$ASSETS_CERTS" ]; then
                echo "  $PKG_NAME:"
                echo "$ASSETS_CERTS" | sed 's/^/    /'
                echo ""
            fi
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ WORLD-READABLE CERTIFICATE FILES                           │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Certificate files readable by any app (permission vulnerability):"
    echo ""

    for ext in pem crt cer p12 pfx key jks bks der; do
        find /data /sdcard /storage ! -path "${OUTPUT_DIR}/*" -name "*.$ext" -perm -004 -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            echo "  [WORLD-READABLE] $file"
            ls -la "$file" 2>/dev/null | sed 's/^/    /'
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CERTIFICATE FILE PERMISSION ANALYSIS                       │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Analyze permissions on found certificate files
    echo "Files with overly permissive access:"
    echo ""
    
    for dir in $SCAN_DIRS; do
        find "$dir" ! -path "${OUTPUT_DIR}/*" \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.bks" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | while read file; do
            PERMS=$(stat -c "%a" "$file" 2>/dev/null || ls -la "$file" | awk '{print $1}')

            # Check for group/world readable
            if echo "$PERMS" | grep -qE "^.{7}r|^.{4}r"; then
                echo "  [OVERLY PERMISSIVE] $file"
                echo "    Permissions: $PERMS"
                echo "    Recommendation: chmod 600 (owner read/write only)"
                echo ""
            fi
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ██████████████████ SUMMARY ██████████████████              │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    
    # Recount for summary (shell subshell issue with counters)
    TOTAL_PEM=$(find $SCAN_DIRS ! -path "${OUTPUT_DIR}/*" -name "*.pem" -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | wc -l)
    TOTAL_DER=$(find $SCAN_DIRS ! -path "${OUTPUT_DIR}/*" \( -name "*.der" -o -name "*.cer" -o -name "*.crt" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | wc -l)
    TOTAL_P12=$(find $SCAN_DIRS ! -path "${OUTPUT_DIR}/*" \( -name "*.p12" -o -name "*.pfx" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | wc -l)
    TOTAL_KEY=$(find $SCAN_DIRS ! -path "${OUTPUT_DIR}/*" \( -name "*.key" -o -name "*.priv" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | wc -l)
    TOTAL_JKS=$(find $SCAN_DIRS ! -path "${OUTPUT_DIR}/*" \( -name "*.jks" -o -name "*.bks" -o -name "*.keystore" \) -type f 2>/dev/null | grep -v "^${REAL_OUTPUT_BASE}/forensic_" | wc -l)

    PRIV_KEY_COUNT=$(grep -rl "PRIVATE KEY" /data/data /sdcard /data/local/tmp 2>/dev/null | grep -v "^${OUTPUT_DIR}/\|^${REAL_OUTPUT_BASE}/forensic_" | wc -l)
    
    echo "Certificate Files Found:"
    echo "  PEM files (.pem):                    $TOTAL_PEM"
    echo "  DER/CER/CRT files:                   $TOTAL_DER"
    echo "  PKCS#12 files (.p12/.pfx):           $TOTAL_P12"
    echo "  Key files (.key/.priv):              $TOTAL_KEY"
    echo "  Java keystores (.jks/.bks):          $TOTAL_JKS"
    echo ""
    echo "Private Key Exposure:"
    echo "  Files containing private keys:       $PRIV_KEY_COUNT"
    echo ""
    
    TOTAL_RISK=$((TOTAL_P12 + TOTAL_KEY + TOTAL_JKS + PRIV_KEY_COUNT))
    
    if [ "$TOTAL_RISK" -gt 0 ]; then
        echo "████████████████████████████████████████████████████████████"
        echo "██ CRITICAL SECURITY FINDINGS ██"
        echo "████████████████████████████████████████████████████████████"
        echo ""
        echo "High-risk certificate storage detected!"
        echo ""
        echo "IMMEDIATE ACTIONS REQUIRED:"
        echo "  1. Move all private keys to Android Keystore"
        echo "  2. Remove hardcoded certificates from APK assets"
        echo "  3. Set file permissions to 600 (owner only)"
        echo "  4. Encrypt sensitive keystores with strong passwords"
        echo "  5. Implement certificate pinning properly"
        echo ""
        echo "NEVER store private keys on filesystem - use Keystore API!"
    else
        echo "[OK] No obvious private key exposure detected"
        echo ""
        echo "Recommendations:"
        echo "  - Continue using Android Keystore for key storage"
        echo "  - Audit any certificate files for necessity"
        echo "  - Implement certificate pinning for network security"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Certificate file scan saved to: ${OUTPUT_FILE}"
