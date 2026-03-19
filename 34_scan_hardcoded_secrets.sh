#!/system/bin/sh
# DROID FORENSIC - Hardcoded Secrets & Credential Scanner
# Scans for API keys, tokens, passwords, and credentials in files/APKs
# Usage: sh 34_scan_hardcoded_secrets.sh [output_directory]

OUTPUT_DIR="${1:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/scan_hardcoded_secrets.txt"

echo "[*] Scanning for hardcoded secrets and credentials..."

{
    echo "═══════════════════════════════════════════════════════════════"
    echo "  HARDCODED SECRETS & CREDENTIAL SCANNER"
    echo "  Timestamp: $(date)"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Searching for exposed credentials, API keys, tokens, and secrets"
    echo "stored in plaintext on the filesystem or embedded in APKs."
    echo ""

    # Directories to scan
    SCAN_DIRS="/data/data /sdcard /data/local/tmp /data/misc"

    # High-entropy string detection threshold (base64/hex patterns)
    
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ ██████ PRIVATE KEY FILE DETECTION ██████                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # SSH Keys
    echo "=== SSH Private Keys ==="
    for dir in $SCAN_DIRS; do
        find "$dir" \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pem" \) -type f 2>/dev/null | while read file; do
            if grep -q "PRIVATE KEY" "$file" 2>/dev/null; then
                echo "██ [CRITICAL] SSH Private Key: $file"
                ls -la "$file" 2>/dev/null | sed 's/^/  /'
                head -2 "$file" 2>/dev/null | sed 's/^/  /'
                echo ""
            fi
        done
    done

    # AWS/Cloud credentials
    echo "=== Cloud Provider Credentials ==="
    for dir in $SCAN_DIRS; do
        find "$dir" \( -name "credentials" -o -name "*.aws" -o -name "config" -o -name "*.gcp" -o -name "*.azure" \) -type f 2>/dev/null | while read file; do
            if grep -qiE "aws_access_key|aws_secret|AKIA|gcp_|azure_" "$file" 2>/dev/null; then
                echo "██ [CRITICAL] Cloud Credentials: $file"
                ls -la "$file" 2>/dev/null | sed 's/^/  /'
                grep -iE "aws_access_key|aws_secret|AKIA|gcp_|azure_" "$file" 2>/dev/null | head -5 | sed 's/^/  /'
                echo ""
            fi
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ API KEY & TOKEN DETECTION                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Common API key patterns
    API_PATTERNS="api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret|app[_-]?secret"

    echo "=== Files Containing API Keys/Tokens ==="
    for dir in $SCAN_DIRS; do
        if [ -d "$dir" ]; then
            grep -rilE "$API_PATTERNS" "$dir" 2>/dev/null | grep -vE "\.(apk|dex|odex|so|jar)$" | head -30 | while read file; do
                echo "[API KEY] $file"
                grep -iE "$API_PATTERNS" "$file" 2>/dev/null | head -5 | sed 's/^/  /'
                echo ""
            done
        fi
    done

    # Specific service API key patterns
    echo ""
    echo "=== Service-Specific API Keys ==="
    
    # Google API keys
    echo "--- Google API Keys (AIza pattern) ---"
    for dir in $SCAN_DIRS; do
        grep -rl "AIza[0-9A-Za-z_-]\{35\}" "$dir" 2>/dev/null | head -10 | while read file; do
            echo "██ [HIGH] Google API Key: $file"
            grep -oE "AIza[0-9A-Za-z_-]{35}" "$file" 2>/dev/null | head -3 | sed 's/^/  Key: /'
            echo ""
        done
    done

    # Firebase
    echo "--- Firebase Keys ---"
    for dir in $SCAN_DIRS; do
        grep -rlE "firebase.*api.*key|\.firebaseio\.com" "$dir" 2>/dev/null | head -10 | while read file; do
            echo "[MEDIUM] Firebase Config: $file"
            grep -iE "firebase|\.firebaseio\.com" "$file" 2>/dev/null | head -3 | sed 's/^/  /'
            echo ""
        done
    done

    # AWS Access Keys
    echo "--- AWS Access Keys (AKIA pattern) ---"
    for dir in $SCAN_DIRS; do
        grep -rl "AKIA[0-9A-Z]\{16\}" "$dir" 2>/dev/null | head -10 | while read file; do
            echo "██ [CRITICAL] AWS Access Key: $file"
            grep -oE "AKIA[0-9A-Z]{16}" "$file" 2>/dev/null | head -3 | sed 's/^/  Key: /'
            echo ""
        done
    done

    # Stripe Keys
    echo "--- Stripe API Keys ---"
    for dir in $SCAN_DIRS; do
        grep -rlE "sk_live_[0-9a-zA-Z]{24}|pk_live_[0-9a-zA-Z]{24}" "$dir" 2>/dev/null | head -10 | while read file; do
            echo "██ [CRITICAL] Stripe Key: $file"
            grep -oE "(sk|pk)_live_[0-9a-zA-Z]{24}" "$file" 2>/dev/null | head -3 | sed 's/^/  Key: /'
            echo ""
        done
    done

    # Twilio
    echo "--- Twilio Credentials ---"
    for dir in $SCAN_DIRS; do
        grep -rlE "twilio|AC[a-z0-9]{32}" "$dir" 2>/dev/null | head -10 | while read file; do
            if grep -qE "AC[a-z0-9]{32}" "$file" 2>/dev/null; then
                echo "[HIGH] Twilio SID: $file"
                grep -oE "AC[a-z0-9]{32}" "$file" 2>/dev/null | head -1 | sed 's/^/  SID: /'
                echo ""
            fi
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ PASSWORD & CREDENTIAL DETECTION                            │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Password patterns
    PASSWORD_PATTERNS="password[[:space:]]*[=:][[:space:]]*[\"']?[^\"'[:space:]]+|passwd[[:space:]]*[=:][[:space:]]*[\"']?[^\"'[:space:]]+|pwd[[:space:]]*[=:][[:space:]]*[\"']?[^\"'[:space:]]+"

    echo "=== Hardcoded Passwords ==="
    for dir in $SCAN_DIRS; do
        if [ -d "$dir" ]; then
            grep -rilE "password\s*[=:]|passwd\s*[=:]|pwd\s*[=:]" "$dir" 2>/dev/null | grep -vE "\.(apk|dex|odex|so|jar|xml)$" | head -30 | while read file; do
                MATCHES=$(grep -iE "password\s*[=:]|passwd\s*[=:]" "$file" 2>/dev/null | grep -v "password.*null\|password.*empty\|password.*\"\"\|password.*''" | head -5)
                if [ -n "$MATCHES" ]; then
                    echo "██ [CRITICAL] Hardcoded Password: $file"
                    echo "$MATCHES" | sed 's/^/  /'
                    echo ""
                fi
            done
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ CONFIGURATION FILE SECRETS                                 │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Config files
    echo "=== Configuration Files with Potential Secrets ==="
    
    CONFIG_PATTERNS="*.json|*.xml|*.yml|*.yaml|*.properties|*.conf|*.config|*.ini|*.env"
    
    for dir in $SCAN_DIRS; do
        find "$dir" \( -name "*.json" -o -name "*.xml" -o -name "*.yml" -o -name "*.yaml" -o -name "*.properties" -o -name "*.conf" -o -name "*.config" -o -name "*.ini" -o -name "*.env" \) -type f 2>/dev/null | head -50 | while read file; do
            # Check for sensitive content
            if grep -qiE "password|secret|api_key|token|credential|private" "$file" 2>/dev/null; then
                echo "[CONFIG] $file"
                grep -iE "password|secret|api_key|token|credential|private" "$file" 2>/dev/null | grep -v "password.*null\|password.*empty" | head -5 | sed 's/^/  /'
                echo ""
            fi
        done
    done

    # SharedPreferences
    echo ""
    echo "=== SharedPreferences with Credentials ==="
    find /data/data -name "*.xml" -path "*/shared_prefs/*" -type f 2>/dev/null | while read file; do
        if grep -qiE "password|token|secret|key|credential|session|auth" "$file" 2>/dev/null; then
            APP_NAME=$(echo "$file" | sed 's|/data/data/||;s|/.*||')
            echo "[SHARED_PREFS] $APP_NAME"
            echo "  File: $file"
            grep -iE "password|token|secret|key|credential|session|auth" "$file" 2>/dev/null | head -5 | sed 's/^/  /'
            echo ""
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ DATABASE CREDENTIAL SCAN                                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # SQLite databases with potential credentials
    echo "=== SQLite Databases with Credential Tables ==="
    find /data/data -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null | head -30 | while read db; do
        # Check for credential-related tables
        TABLES=$(sqlite3 "$db" ".tables" 2>/dev/null)
        if echo "$TABLES" | grep -qiE "user|account|credential|auth|login|session|token"; then
            APP_NAME=$(echo "$db" | sed 's|/data/data/||;s|/.*||')
            echo "[DATABASE] $APP_NAME"
            echo "  File: $db"
            echo "  Interesting tables: $(echo "$TABLES" | grep -iE "user|account|credential|auth|login|session|token" | tr '\n' ' ')"
            
            # Try to dump credential-looking columns
            for table in $(echo "$TABLES" | tr ' ' '\n' | grep -iE "user|account|credential|auth|login"); do
                SCHEMA=$(sqlite3 "$db" ".schema $table" 2>/dev/null)
                if echo "$SCHEMA" | grep -qiE "password|token|secret|key"; then
                    echo "  Table $table has credential columns!"
                fi
            done
            echo ""
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ JWT TOKEN DETECTION                                        │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # JWT tokens (eyJ pattern)
    echo "=== JWT Tokens ==="
    for dir in $SCAN_DIRS; do
        grep -rl "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\." "$dir" 2>/dev/null | head -20 | while read file; do
            echo "[JWT] $file"
            grep -oE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" "$file" 2>/dev/null | head -3 | while read jwt; do
                echo "  Token: ${jwt:0:50}..."
                # Decode header
                HEADER=$(echo "$jwt" | cut -d. -f1 | base64 -d 2>/dev/null)
                echo "  Header: $HEADER"
            done
            echo ""
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ APK EMBEDDED SECRETS SCAN                                  │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Scanning APK files for embedded secrets..."
    echo "(Limited to 15 third-party apps)"
    echo ""

    pm list packages -3 -f 2>/dev/null | head -15 | while read pkg_line; do
        APK_PATH=$(echo "$pkg_line" | sed 's/package://;s/=.*//')
        PKG_NAME=$(echo "$pkg_line" | sed 's/.*=//')
        
        if [ -f "$APK_PATH" ]; then
            # Extract strings from DEX
            SECRETS_FOUND=""
            
            # Check for API keys in strings
            DEX_STRINGS=$(unzip -p "$APK_PATH" classes.dex 2>/dev/null | strings 2>/dev/null)
            
            # Google API Key
            if echo "$DEX_STRINGS" | grep -q "AIza[0-9A-Za-z_-]\{35\}"; then
                SECRETS_FOUND="$SECRETS_FOUND GOOGLE_API_KEY"
            fi
            
            # AWS Key
            if echo "$DEX_STRINGS" | grep -q "AKIA[0-9A-Z]\{16\}"; then
                SECRETS_FOUND="$SECRETS_FOUND AWS_KEY"
            fi
            
            # Firebase
            if echo "$DEX_STRINGS" | grep -q "\.firebaseio\.com"; then
                SECRETS_FOUND="$SECRETS_FOUND FIREBASE"
            fi
            
            # Hardcoded URLs with credentials
            if echo "$DEX_STRINGS" | grep -qE "https?://[^:]+:[^@]+@"; then
                SECRETS_FOUND="$SECRETS_FOUND URL_WITH_CREDS"
            fi
            
            # Private key
            if echo "$DEX_STRINGS" | grep -q "PRIVATE KEY"; then
                SECRETS_FOUND="$SECRETS_FOUND PRIVATE_KEY"
            fi
            
            if [ -n "$SECRETS_FOUND" ]; then
                echo "═══════════════════════════════════════════════════════════"
                echo "██ APP: $PKG_NAME"
                echo "═══════════════════════════════════════════════════════════"
                echo "  Secrets detected:$SECRETS_FOUND"
                
                # Show actual values
                if echo "$SECRETS_FOUND" | grep -q "GOOGLE_API_KEY"; then
                    echo "  Google API Key:"
                    echo "$DEX_STRINGS" | grep -oE "AIza[0-9A-Za-z_-]{35}" | head -1 | sed 's/^/    /'
                fi
                
                if echo "$SECRETS_FOUND" | grep -q "AWS_KEY"; then
                    echo "  AWS Access Key:"
                    echo "$DEX_STRINGS" | grep -oE "AKIA[0-9A-Z]{16}" | head -1 | sed 's/^/    /'
                fi
                
                if echo "$SECRETS_FOUND" | grep -q "PRIVATE_KEY"; then
                    echo "  ██ CRITICAL: Private key embedded in APK!"
                fi
                
                echo ""
            fi
        fi
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ BUILD CONFIG & DEBUG SECRETS                               │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Look for BuildConfig with secrets
    echo "=== BuildConfig Files ==="
    find /data/data -name "BuildConfig.class" -o -name "*BuildConfig*" 2>/dev/null | head -10

    # Debug/development files
    echo ""
    echo "=== Debug/Development Files ==="
    for dir in $SCAN_DIRS; do
        find "$dir" \( -name "debug*" -o -name "*.debug" -o -name "dev_*" -o -name "test_*" \) -type f 2>/dev/null | head -20 | while read file; do
            if grep -qiE "password|secret|key|token" "$file" 2>/dev/null; then
                echo "[DEBUG FILE] $file"
                grep -iE "password|secret|key|token" "$file" 2>/dev/null | head -3 | sed 's/^/  /'
                echo ""
            fi
        done
    done

    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│ SUMMARY                                                    │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""

    # Count findings
    PRIV_KEY_COUNT=$(grep -rl "PRIVATE KEY" /data/data /sdcard 2>/dev/null | wc -l)
    API_KEY_COUNT=$(grep -rlE "AIza|AKIA|sk_live" /data/data /sdcard 2>/dev/null | wc -l)
    PASSWORD_COUNT=$(grep -rilE "password\s*[=:]" /data/data /sdcard 2>/dev/null | grep -v ".apk\|.dex\|.so" | wc -l)
    JWT_COUNT=$(grep -rl "eyJ[A-Za-z0-9_-]*\.eyJ" /data/data /sdcard 2>/dev/null | wc -l)

    echo "Findings Summary:"
    echo "  Private keys exposed:        $PRIV_KEY_COUNT"
    echo "  API keys detected:           $API_KEY_COUNT"
    echo "  Files with passwords:        $PASSWORD_COUNT"
    echo "  JWT tokens found:            $JWT_COUNT"
    echo ""

    TOTAL_CRITICAL=$((PRIV_KEY_COUNT + API_KEY_COUNT))
    
    if [ "$TOTAL_CRITICAL" -gt 0 ]; then
        echo "████████████████████████████████████████████████████████████"
        echo "██ CRITICAL: SECRETS EXPOSED ON FILESYSTEM ██"
        echo "████████████████████████████████████████████████████████████"
        echo ""
        echo "Immediate actions required:"
        echo "  1. Rotate all exposed API keys immediately"
        echo "  2. Move private keys to Android Keystore"
        echo "  3. Remove hardcoded credentials from source code"
        echo "  4. Use secure credential storage (EncryptedSharedPreferences)"
        echo "  5. Implement proper secrets management"
    else
        echo "[OK] No critical secrets exposure detected in scanned areas"
    fi
    echo ""

} > "${OUTPUT_FILE}" 2>&1

echo "[+] Hardcoded secrets scan saved to: ${OUTPUT_FILE}"
