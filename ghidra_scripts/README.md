# Trellis for Ghidra

**iOS Security Analysis Toolkit for Ghidra**

Trellis is a comprehensive iOS binary security analysis toolkit for Ghidra. It analyzes iOS binaries for security-relevant function usage and generates detailed reports.

## Features

- **Cryptographic Analysis**: Detect CCCrypt, CCHmac, SecKey, PBKDF2, and CryptoKit operations with security checks for weak algorithms, hardcoded keys/IVs, ECB mode, and weak key derivation parameters
- **TLS/SSL Analysis**: Identify URLSession delegates, certificate validation issues, pinning implementations, and weak protocol versions
- **Keychain Analysis**: Find insecure accessibility levels, iCloud sync issues, and missing biometric protection
- **Jailbreak Detection**: Map jailbreak detection techniques including file path checks, fork detection, dylib enumeration, and string-table fallback for Swift binaries
- **Anti-Debug Detection**: Identify ptrace, sysctl, getppid, and other anti-debugging techniques
- **Storage Security**: Analyze NSUserDefaults, file writes, plist storage for sensitive data
- **WebView Security**: Detect JavaScript bridges, loadHTMLString XSS risks, loadRequest content loading, and WKScriptMessageHandler issues
- **Deep Link Analysis**: URL scheme handlers, Universal Links, SwiftUI onOpenURL, input validation, and dangerous destination flow warnings
- **SQLite Security**: SQL injection risks, unencrypted databases, and SQLCipher usage
- **Logging Analysis**: Detect sensitive data in NSLog, os_log, and print statements with severity tiering
- **Endpoint Discovery**: Extract and analyze API endpoints and network URLs
- **Deserialization**: NSKeyedUnarchiver and NSCoding vulnerability detection
- **String-Table Scanning**: Detect hardcoded passwords, API keys, HTTP cleartext URLs, and embedded credentials directly from the binary's string table
- **Biometric Authentication**: Detect insecure client-side-only LAContext biometric checks
- **Runtime Manipulation**: Detect hardcoded credential comparisons, client-side authentication checks, and validation logic that can be bypassed
- **Enhanced Detection**: ARM64 backward-slice parameter extraction, caller-name heuristic checks, ObjC selector matching via `objc_msgSend`, and string cross-referencing
- **Swift Support**: Automatic Swift symbol demangling
- **Report Generation**: Markdown reports saved to a user-chosen directory
- **Frida Script Generation**: Generate ready-to-use instrumentation scripts (generic and findings-driven)

## Installation

1. Copy the entire `ghidra_scripts/` directory to your Ghidra scripts location:
   - **Option A**: Copy to `~/ghidra_scripts/` (user scripts directory)
   - **Option B**: Add this directory to Ghidra's Script Directories via `Window > Script Manager > Manage Script Directories`

2. The directory structure should be:
   ```
   ghidra_scripts/
   ├── TrellisAnalyze.py          # Main analysis script
   ├── TrellisFrida.py            # Frida script generator
   ├── trellis_ghidra/            # Trellis module
   │   ├── __init__.py
   │   ├── ghidra_api.py          # Ghidra API wrapper
   │   ├── analysis/              # Analysis modules
   │   │   ├── finder.py
   │   │   ├── calltree.py
   │   │   ├── extractor.py
   │   │   ├── security_checks.py
   │   │   ├── security_checks_crypto.py
   │   │   ├── security_checks_tls.py
   │   │   ├── security_checks_keychain.py
   │   │   └── security_checks_jailbreak.py
   │   ├── signatures/            # Signature loading
   │   │   └── __init__.py
   │   └── generators/            # Frida script generators
   └── README.md
   ```

3. Ensure PyYAML is installed for signature loading.

## Usage

### Running the Analysis

1. Open an iOS binary (IPA/Mach-O) in Ghidra
2. Let Ghidra complete auto-analysis
3. Open the Script Manager (`Window > Script Manager`)
4. Find `TrellisAnalyze.py` under the `iOS Security` category
5. Run the script
6. When prompted, choose an output directory for reports

Alternatively, use the menu: `Tools > Trellis > Analyze All`

### Generating Frida Scripts

1. Open the same binary in Ghidra
2. Run `TrellisFrida.py` from Script Manager, or use `Tools > Trellis > Generate Frida Scripts`
3. Choose a tracer type:

   **Generic API Hooks (Traditional):**
   - **All Tracers** — crypto, keychain, TLS, and more
   - **Crypto Tracer** — hooks for CommonCrypto functions found in the binary
   - **Keychain Tracer** — hooks for SecItem* keychain operations
   - **TLS Tracer** — hooks for SecTrust* certificate validation
   - **Custom — All Found Functions** — hooks for every security-relevant function found

   **Findings-Driven Hooks (Recommended):**
   - **All Tracers (Findings-Driven)** — generate for all categories
   - **Crypto Findings** — hooks only at call sites with detected crypto issues
   - **Keychain Findings** — hooks only at call sites with detected keychain issues
   - **Anti-Debug Findings** — hooks at detected anti-debug call sites
   - And more per-category options

4. Choose an output directory when prompted
5. Run the generated `.js` files with Frida:
   ```bash
   frida -U -f com.example.app -l trellis-crypto-26-02-20-130000.js
   ```

**Note:** Findings-driven mode requires running TrellisAnalyze first to generate findings JSON files.

### Understanding Reports

Reports are saved to the directory you select at launch, with timestamps:
- `Trellis-Crypto-25-02-19-143022.md`
- `Trellis-Keychain-25-02-19-143022.md`
- etc.

Each report contains:
- **Summary**: Finding counts by severity
- **Security Findings**: Detailed issues with evidence, impact, and recommendations
- **Functions Analyzed**: List of security-relevant functions found

### Severity Levels

| Severity | Meaning |
|----------|---------|
| 🔴 CRITICAL | Immediate security risk, easily exploitable |
| 🟠 HIGH | Significant vulnerability |
| 🟡 MEDIUM | Security concern requiring review |
| 🔵 LOW | Minor issue or best practice violation |
| ⚪ INFO | Informational finding |

## Security Categories

### Crypto
Analyzes CommonCrypto and Security framework usage:
- `CCCrypt`, `CCCryptorCreate`, `CCHmac`, PBKDF2
- `SecKeyEncrypt`, `SecKeyDecrypt`
- Weak algorithm detection (DES, 3DES, MD5, RC4, SHA-1)
- Hardcoded key/IV detection
- ECB mode warnings
- Weak PBKDF2 parameters

### CryptoKit
Analyzes Swift CryptoKit framework:
- AES-GCM, ChaChaPoly, HKDF operations
- Hardcoded key and nonce detection
- Weak HKDF salt analysis

### Networking/TLS
Analyzes TLS configuration:
- URLSession delegate implementations
- `SecTrustEvaluate` / `SecTrustEvaluateWithError`
- Certificate pinning detection
- Deprecated API usage
- Weak TLS version and ATS bypass detection

### Keychain
Analyzes Keychain Services:
- `SecItemAdd`, `SecItemUpdate`, `SecItemCopyMatching`
- Accessibility attribute analysis
- iCloud sync detection
- Biometric protection checks

### Jailbreak
Identifies jailbreak detection techniques:
- File path checks (`/Applications/Cydia.app`, etc.)
- Fork detection
- Dylib enumeration
- URL scheme checks (`cydia://`)
- String-table fallback for Swift binaries

### Anti-Debug
Identifies anti-debugging techniques:
- `ptrace` PT_DENY_ATTACH usage
- `sysctl` process info queries
- `getppid` parent process ID checks
- Exception-based debug detection

### Storage
Analyzes data storage patterns:
- NSUserDefaults sensitive data storage
- Insecure file writes and permissions
- Plist data exposure
- Temporary file risks

### WebView
Analyzes WebView security:
- JavaScript bridges (WKScriptMessageHandler)
- `loadHTMLString` XSS risks
- `loadRequest` content loading
- JavaScript injection via `evaluateJavaScript`

### Deep Links
Analyzes URL handling:
- `application:openURL:` handlers
- Universal Links
- SwiftUI `onOpenURL`
- Input validation and dangerous destination flows

### SQLite
Analyzes database security:
- SQL injection via `sqlite3_exec`
- Unencrypted storage (no SQLCipher)
- FMDB format string injection

### Logging
Detects sensitive data logging:
- NSLog, os_log, Swift print
- Sensitive keyword detection (password, token, key)

### Biometric
Analyzes biometric authentication:
- Client-side-only LAContext checks (HIGH — trivially bypassable)
- `canEvaluatePolicy` availability checks (INFO)
- `evaluateAccessControl` with SecAccessControl (INFO — more secure)

### Runtime Manipulation
Detects runtime bypass vulnerabilities:
- Hardcoded credential comparisons (`isEqualToString:` with static strings)
- Client-side authentication checks
- Hardcoded validation values
- Numeric auth value extraction in auth context

### String-Table Scan
- Hardcoded passwords, API keys, HTTP cleartext URLs
- Jailbreak indicator paths and dylib names
- Cross-references strings with security-critical call sites

## Directory Structure

```
ghidra_scripts/
├── TrellisAnalyze.py          # Main analysis script
├── TrellisFrida.py            # Frida script generator
├── trellis_ghidra/            # Trellis module
│   ├── ghidra_api.py          # Ghidra API wrapper
│   ├── analysis/              # Analysis modules
│   │   ├── finder.py          # Function finder (with ObjC selector matching)
│   │   ├── calltree.py        # Call tree builder
│   │   ├── extractor.py       # Parameter extractor (with ARM64 backward slice)
│   │   ├── findings_storage.py # Findings JSON serialization
│   │   ├── security_checks.py # Base security classes
│   │   ├── security_checks_crypto.py
│   │   ├── security_checks_cryptokit.py
│   │   ├── security_checks_tls.py
│   │   ├── security_checks_networking.py
│   │   ├── security_checks_keychain.py
│   │   ├── security_checks_jailbreak.py
│   │   ├── security_checks_antidebug.py
│   │   ├── security_checks_storage.py
│   │   ├── security_checks_deserialization.py
│   │   ├── security_checks_webview.py
│   │   ├── security_checks_deeplinks.py
│   │   ├── security_checks_sqlite.py
│   │   ├── security_checks_logging.py
│   │   ├── security_checks_endpoints.py
│   │   ├── security_checks_strings.py   # String-table credential scanner
│   │   ├── security_checks_biometric.py # Biometric auth checker
│   │   ├── security_checks_runtime.py   # Runtime manipulation checker
│   │   └── swift_demangle.py  # Swift demangling
│   ├── signatures/            # YAML signature databases
│   │   ├── crypto.yaml
│   │   ├── networking.yaml
│   │   ├── keychain.yaml
│   │   ├── biometric.yaml
│   │   ├── runtime.yaml
│   │   └── ...
│   └── generators/            # Frida script generators
│       └── frida/
│           ├── base.py        # Generic hook generation
│           ├── findings.py    # Findings-driven generation
│           ├── crypto.py
│           ├── keychain.py
│           └── ...
└── README.md
```

## Extending Trellis

### Adding New Signatures

Add new function signatures to the YAML files in `trellis_ghidra/signatures/`:

```yaml
functions:
  - name: MySecurityFunction
    library: Security
    parameters:
      - name: key
        type: void*
      - name: keyLength
        type: size_t
    return:
      type: int
    security_notes:
      - Check for hardcoded key
```

### Creating Custom Security Checkers

1. Create a new file `security_checks_mycheck.py`
2. Inherit from `SecurityChecker`
3. Implement `check_call_site()`

```python
from .security_checks import SecurityChecker, SecurityFinding, Severity

class MySecurityChecker(SecurityChecker):
    def check_call_site(self, function_sig, call_site, extracted_info):
        findings = []
        # Your analysis logic here
        return findings
```

4. Add to `analysis/__init__.py`
5. Register in `TrellisAnalyze.py`'s `get_security_checker()`

## Troubleshooting

### "Module not found" Errors

Ensure the `trellis_ghidra` directory is in the same location as `TrellisAnalyze.py`.

### No Functions Found

- Verify the binary is an iOS/macOS Mach-O file
- Ensure Ghidra has completed auto-analysis
- Check that the binary imports the relevant frameworks

### Decompilation Errors

Some functions may fail to decompile. The script handles this gracefully and reports which functions couldn't be analyzed.

## Credits

- iOS security research patterns from public sources
- Swift demangling based on standard Swift ABI documentation

## License

MIT License
