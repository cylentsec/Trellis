# Trellis

**Trellis is an iOS application security analysis toolkit designed to bridge static and dynamic analysis.**

[![Ghidra](https://img.shields.io/badge/Ghidra-11.0%2B-green)](https://ghidra-sre.org/)
[![Frida](https://img.shields.io/badge/Frida-17.0%2B-orange)](https://frida.re/)

Trellis provides static analysis of iOS binaries to detect security-relevant function usage and generates static analysis reports. It also generates Frida scripts for dynamic instrumentation. It runs as a Ghidra script for interactive analysis. The goal of the security analysis is to provide a good balance between eliminating false-positives and false-negatives. Memory addresses and offsets are provided in report findings to aid the analyst's investigation.

**Trellis is not designed to provide findings ready to be copied and pasted into an iOS app pentest report. It's designed to perform triage and provide the iOS security analyst with a map of what to investigate and where to find it. Static analysis report findings should be combined with Frida script dynamic analysis for a full investigation.**

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
- **Logging Analysis**: Detect sensitive data in NSLog, os_log, and print statements with severity tiering to reduce noise
- **Endpoint Discovery**: Extract and analyze API endpoints and network URLs
- **Deserialization**: NSKeyedUnarchiver and NSCoding vulnerability detection
- **String-Table Scanning**: Detect hardcoded passwords, API keys, HTTP cleartext URLs, and embedded credentials directly from the binary's string table (no decompiler required)
- **Biometric Authentication**: Detect insecure client-side-only LAContext biometric checks that are trivially bypassable
- **Runtime Manipulation**: Detect hardcoded credential comparisons, client-side authentication checks, and validation logic that can be bypassed via Frida hooking
- **Enhanced Detection**: ARM64 backward-slice parameter extraction fallback, caller-name heuristic checks, ObjC selector matching via `objc_msgSend`, and string cross-referencing with security-critical call sites
- **Swift Support**: Automatic Swift symbol demangling
- **Report Generation**: Markdown reports saved to a user-chosen directory
- **Frida Script Generation**: Generate ready-to-use instrumentation scripts

## Installation

This has been tested only on Kali Linux. While I'm sure it will work on other Linux distros and macOS, the others will not be supported here.

1. Install Ghidra if not already installed.
2. Create an alias in `~/.zshrc` to start Ghidra with Python support:

   ```bash
   ghidra=/usr/share/ghidra/support/pyghidraRun
   ```
3. Source your alias: `source ~/.zshrc`
4. Start Ghidra from the terminal to create the Python virtual environment: `ghidra`
5. Note the Ghidra version path in the terminal output.
6. Ensure PyYAML is available in Ghidra's Python environment: (replace the version with the version found in step 5)

   ```bash
   ~/.config/ghidra/ghidra_<version>/venv/bin/pip install pyyaml
   ```
7. Open the binary you want to analyze and allow Ghidra to finish the analysis
8. Click on Window -> Script Manager, then click the Manage Script Directories button. Next, click the plus button, and choose the path: `/path/to/Trellis/ghidra_scripts`
9. In the Script Manager window, find the `iOS Security` folder and ensure that both scripts are checked.

You should now see two options under the `Tools` -> `Trellis` menu, `Analyze All` and `Generate Frida Scripts`.

## Usage

### Running the Analysis

**Critical! The iOS app binary MUST be decrypted. If you extracted the app binary from a production build of an iOS IPA file, it's probably encrypted. See [frida-decrypt](https://github.com/cylentsec/frida-decrypt) if you need a decryption tool.**

1. Open an iOS binary (IPA/Mach-O) in Ghidra
2. Let Ghidra complete auto-analysis
3. In the Ghidra menu, click `Tools` -> `Trellis`, and select either `Analyze All` or `Generate Frida Scripts` as desired
4. Run the script
5. When prompted, choose an output directory for reports or Frida scripts

### Analysis Categories

| Category | Description |
|----------|-------------|
| **crypto** | CommonCrypto functions (CCCrypt, CCHmac, PBKDF2, etc.) |
| **cryptokit** | Swift CryptoKit framework (AES-GCM, ChaChaPoly, HKDF, etc.) |
| **networking** | Network/TLS configuration and security concerns |
| **tls_delegate** | TLS delegate implementation and certificate validation |
| **keychain** | Keychain Services (SecItemAdd, SecItemCopyMatching, etc.) |
| **jailbreak** | Jailbreak detection (file checks, fork, URL schemes) |
| **antidebug** | Anti-debugging techniques (ptrace, sysctl, getppid) |
| **storage** | Data storage patterns (NSUserDefaults, file writes, plists) |
| **deserialization** | Object deserialization vulnerabilities (NSCoding, etc.) |
| **webview** | WebView security (JavaScript bridges, content loading) |
| **deeplinks** | Deep link and URL scheme handling security |
| **sqlite** | SQLite database security (SQL injection, encryption) |
| **logging** | Sensitive data logging (NSLog, os_log, print, etc.) |
| **endpoints** | API endpoint discovery and security analysis |
| **biometric** | Biometric authentication (Touch ID/Face ID) security |
| **runtime** | Runtime manipulation vulnerabilities (client-side auth, hardcoded comparisons) |
| **insecure_storage** | Insecure data storage patterns (NSUserDefaults, plist files, etc.) |
| **string_scan** | String-table scan for hardcoded credentials, API keys, HTTP URLs |

### Understanding Reports

Reports are saved to the directory you select at launch, with timestamps:

- `Trellis-Crypto-25-02-19-143022.md`
- `Trellis-Keychain-25-02-19-143022.md`
- `Trellis-StringScan-25-02-19-143022.md`

Each report contains:

- **Summary**: Finding counts by severity
- **Security Findings**: Detailed issues with evidence, impact, and recommendations
- **Functions Analyzed**: List of security-relevant functions found

### Severity Levels

| Severity | Emoji | Meaning |
|----------|-------|---------|
| CRITICAL | 🔴 | Immediate security risk, easily exploitable |
| HIGH | 🟠 | Significant vulnerability |
| MEDIUM | 🟡 | Security concern requiring review |
| LOW | 🔵 | Minor issue or best practice violation |
| INFO | ⚪ | Informational finding |

## Security Checks

### Crypto Category

- **Weak Algorithms**: DES, 3DES, RC4, MD5, SHA-1 usage
- **ECB Mode**: Insecure block cipher mode
- **Hardcoded Keys/IVs**: Keys from constant data sections
- **NULL IV**: Missing initialization vector for CBC mode
- **Weak PBKDF2**: Low iteration count (<10,000 = CRITICAL, <100,000 = HIGH), SHA-1 PRF, hardcoded salt, short derived key length

### CryptoKit Category

- **Hardcoded Keys**: AES-GCM/ChaChaPoly keys from constant data
- **Hardcoded Nonces**: Static IVs causing nonce reuse
- **Weak HKDF Salt**: Empty or zero salt in key derivation
- **SymmetricKey Creation**: Hardcoded symmetric key data

### Networking/TLS Category

- **Trust Evaluation**: Missing SecTrustEvaluate calls
- **Unconditional Trust**: Delegates accepting all certificates
- **Deprecated APIs**: Using old SecTrustEvaluate vs WithError variant
- **Certificate Pinning**: Presence or absence of pinning
- **Weak TLS Version**: SSL 3.0, TLS 1.0, TLS 1.1 minimum versions
- **ATS Bypass**: NSAllowsArbitraryLoads detection
- **HTTP URLs**: Insecure HTTP endpoint usage

### Keychain Category

- **Insecure Accessibility**: kSecAttrAccessibleAlways usage
- **iCloud Sync**: Sensitive data with synchronization enabled
- **Missing Biometrics**: No access control for sensitive items
- **Data Exposure**: Broad queries returning all items

### Jailbreak Category

- **File Checks**: Cydia, Substrate, and jailbreak tool paths
- **Fork Detection**: Using fork() to detect sandbox escape
- **Dylib Enumeration**: Checking for injected libraries
- **String-Table Fallback**: Scans string table for jailbreak paths, URL schemes, and dylib names when parameter extraction fails (common with Swift)

### Anti-Debug Category

- **ptrace**: PT_DENY_ATTACH usage
- **sysctl**: Process info queries for debugger detection
- **getppid**: Parent process ID checks
- **Exception Handlers**: Signal-based debug detection

### Storage Category

- **NSUserDefaults**: Sensitive data in user defaults
- **File Writes**: Insecure file permissions and locations
- **Plist Storage**: Property list data exposure
- **Temporary Files**: Sensitive data in temp directories

### Deserialization Category

- **NSKeyedUnarchiver**: Insecure unarchiving without secure coding
- **NSCoding**: Legacy serialization vulnerabilities
- **Class Restrictions**: Missing requiresSecureCoding checks

### WebView Category

- **JavaScript Bridges**: WKScriptMessageHandler exposure
- **Insecure Content**: Mixed content and HTTP loading
- **JavaScript Injection**: evaluateJavaScript with user data
- **File Access**: Local file system access via WebView
- **loadHTMLString XSS**: Detects loadHTMLString:baseURL: with nil baseURL (HIGH) or dynamic HTML (MEDIUM)
- **loadRequest**: WebView loading external content without content validation

### Deep Links Category

- **URL Scheme Handlers**: application:openURL: implementations
- **Universal Links**: userActivity handling
- **Input Validation**: Missing URL parameter sanitization
- **Dangerous Destinations**: Warns when URL data may flow into WebView loading, JavaScript execution, or file operations

### SQLite Category

- **SQL Injection**: sqlite3_exec with dynamic queries
- **Unencrypted Storage**: Plain SQLite without SQLCipher
- **FMDB Format Strings**: Format specifier SQL injection
- **Database Location**: Insecure temp/cache storage

### Logging Category

- **NSLog**: Base findings at INFO severity to reduce noise; promoted to HIGH when sensitive keywords detected
- **os_log**: Missing privacy modifiers
- **Swift Print**: Debug print statements in release builds
- **Sensitive Keywords**: Password, token, key detection in logs (HIGH severity)

### Endpoints Category

- **Debug Endpoints**: /debug, /test, localhost URLs
- **API Keys in URLs**: Hardcoded credentials in query strings
- **HTTP Endpoints**: Unencrypted API communications
- **WebSocket Security**: ws:// vs wss:// usage

### String-Table Scan

- **Hardcoded Passwords**: High-entropy strings with special characters (CRITICAL)
- **API Keys/Tokens**: AWS keys, hex/base64 key patterns, key=value formats (HIGH)
- **HTTP Cleartext URLs**: Unencrypted HTTP URLs (MEDIUM), with sensitive paths like /auth/, /payment/ (HIGH)
- **Jailbreak Indicators**: Known jailbreak paths, URL schemes, and dylib names found in string table

### Biometric Category

- **Client-Side Biometric**: LAContext.evaluatePolicy without Keychain binding (HIGH — trivially bypassable)
- **Biometric Availability**: canEvaluatePolicy checks (INFO)
- **Access Control**: evaluateAccessControl with SecAccessControl (INFO — more secure pattern)

### Runtime Manipulation Category

- **Hardcoded Credentials**: `isEqualToString:` comparisons against static strings in auth functions (CRITICAL)
- **Client-Side Auth Checks**: String comparison in authentication context with unresolved parameters (MEDIUM)
- **Hardcoded Validation Values**: Static comparison values in validation functions (HIGH)
- **Numeric Auth Values**: `integerValue`/`intValue`/`boolValue` in authentication context (MEDIUM)

## Frida Script Generation

Trellis provides two modes for Frida script generation:

### 1. Generic API Hooks (Traditional)

Generate comprehensive hooks for entire API surfaces:

```python
from trellis_ghidra.generators import generate_crypto_tracer, generate_keychain_tracer

# Generate crypto tracer script
script = generate_crypto_tracer(found_functions)

# Save to file
with open("crypto_hooks.js", "w") as f:
    f.write(script)
```

### 2. Findings-Driven Hooks (NEW - Recommended)

**Generate targeted hooks for specific security findings identified during static analysis.**

This mode creates address-specific hooks that only monitor the exact call sites where issues were detected, dramatically reducing noise and enabling runtime verification of static analysis results.

**Workflow:**

1. **Run TrellisAnalyze** on your binary → Generates Markdown report + findings JSON
2. **Run TrellisFrida** → Select "{Category} Findings" option
3. **Deploy** generated script to device
4. **Verify** findings at runtime with intelligent verification logic

**Example Output:**

```javascript
🟡 [FINDING #3 TRIGGERED] 🟡
  Severity: MEDIUM
  Issue: Missing Keychain Accessibility Attribute
  Function: SecItemAdd
  Ghidra: 0x1001141bc
  Description: Keychain item stored without explicit accessibility level
  Evidence (from static analysis):
    kSecAttrAccessible: not set (defaults to kSecAttrAccessibleWhenUnlocked)
  
  // Runtime verification:
  [✓] FINDING CONFIRMED: kSecAttrAccessible NOT set at runtime
  
  Runtime arguments:
    [0] = 0x102345678 (query dict)
  
  Backtrace:
    0x102345678 (Ghidra: 0x1001141bc) storeString:forKey:
    ...
```

**Available Findings-Driven Options:**
- All Tracers (Findings-Driven) - Generate for all categories
- Crypto Findings
- Keychain Findings
- TLS Findings
- Anti-Debug Findings
- Jailbreak Findings
- WebView Findings
- Deeplinks Findings
- Storage Findings
- Deserialization Findings

**Benefits:**
- **Targeted**: Hooks only problematic call sites (e.g., 8 calls vs 100+)
- **Verified**: Runtime verification confirms or refutes static findings
- **Cross-referenced**: Direct links between Frida output → Ghidra addresses → code
- **Low noise**: Only alerts on verified security issues
- **Actionable**: Each alert includes finding metadata and recommendations

**Run with Frida:**

```bash
frida -U -f com.example.app -l trellis-keychain-findings-*.js
```

**Implementation Details:**

See `FINDINGS_DRIVEN_IMPLEMENTATION.md` for complete architecture documentation.

## Project Structure

```
Trellis-Ghidra/
├── ghidra_scripts/
│   ├── TrellisAnalyze.py          # Main analysis script
│   ├── TrellisFrida.py            # Frida script generator
│   ├── README.md                   # Detailed Ghidra usage
│   └── trellis_ghidra/            # Trellis module
│       ├── ghidra_api.py          # Ghidra API wrapper
│       ├── analysis/              # Analysis modules
│       │   ├── finder.py          # Function finder
│       │   ├── calltree.py        # Call tree builder
│       │   ├── extractor.py       # Parameter extractor
│       │   ├── findings_storage.py # NEW: Findings JSON serialization
│       │   ├── security_checks.py # Base security classes
│       │   ├── security_checks_crypto.py
│       │   ├── security_checks_cryptokit.py
│       │   ├── security_checks_tls.py
│       │   ├── security_checks_networking.py
│       │   ├── security_checks_keychain.py
│       │   ├── security_checks_jailbreak.py
│       │   ├── security_checks_antidebug.py
│       │   ├── security_checks_storage.py
│       │   ├── security_checks_deserialization.py
│       │   ├── security_checks_webview.py
│       │   ├── security_checks_deeplinks.py
│       │   ├── security_checks_sqlite.py
│       │   ├── security_checks_logging.py
│       │   ├── security_checks_endpoints.py
│       │   ├── security_checks_strings.py   # String-table credential scanner
│       │   ├── security_checks_biometric.py # Biometric auth checker
│       │   ├── security_checks_runtime.py   # Runtime manipulation checker
│       │   └── swift_demangle.py  # Swift demangling
│       ├── signatures/            # YAML signature databases
│       │   ├── crypto.yaml
│       │   ├── networking.yaml
│       │   ├── keychain.yaml
│       │   ├── biometric.yaml
│       │   ├── runtime.yaml
│       │   └── ...
│       └── generators/            # Frida script generators
│           └── frida/
│               ├── base.py        # Generic hook generation
│               ├── findings.py    # NEW: Findings-driven generation
│               ├── crypto.py
│               ├── keychain.py
│               └── ...
├── FINDINGS_DRIVEN_IMPLEMENTATION.md  # NEW: Architecture docs
└── README.md                          # This file
```

## Requirements

- **Ghidra**: 11.0 or later (requires Python 3 support via PyGhidra)
- **Python 3**: PyYAML for signature loading (`pip3 install pyyaml`)
- **Frida**: 17.0+ for generated scripts (on target device)

## Troubleshooting

### "Module not found" Errors

Ensure the `trellis_ghidra` directory is in the same location as `TrellisAnalyze.py`.

### No Functions Found

- Verify the binary is an iOS/macOS Mach-O file **and is decrypted**
- Ensure Ghidra has completed auto-analysis
- Check that the binary imports the relevant frameworks

### PyYAML Not Available

Install PyYAML for your Python 3 environment: `pip3 install pyyaml`. Ensure Ghidra's PyGhidra is configured to use the same Python installation.

## Example Workflow

1. **Load binary** in Ghidra and let analysis complete
2. **Run** `TrellisAnalyze.py` from Script Manager
3. **Review** the report in the output directory you selected
4. **Look for** CRITICAL/HIGH findings
5. **Generate** Frida script for runtime validation
6. **Test** with `frida -U -f <bundle_id> -l <script.js>`

## Development

### Python 3 — Not Jython

Ghidra historically used Jython (Python 2.7 on the JVM) for scripting. Starting with Ghidra 11.0, Python 3 support was added via **PyGhidra** (CPython 3), and Jython support is effectively deprecated.

This project targets Python 3 exclusively — it uses `dataclasses`, `pathlib`, type hints, and other Python 3 features throughout. Do not add `from __future__` imports or other Python 2 compatibility patterns.

### Adding New Signatures

Edit the YAML files in `ghidra_scripts/trellis_ghidra/signatures/`:

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

1. Create a new file `security_checks_mycheck.py` in `analysis/`
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

1. Register in `TrellisAnalyze.py`'s `get_security_checker()`

## License

Trellis is licensed under the [Business Source License 1.1](LICENSE) with a Commons Clause restriction.

- **Non-production use** is freely permitted with attribution.
- **Commercial use or selling** the software is not permitted without a commercial license from Cylent Security LLC.
- On **March 22, 2031**, the license automatically converts to the Apache License 2.0.
- **Attribution required**: All permitted uses must display `Powered by Trellis — https://github.com/cylentsec/Trellis`.
- **Contributors**: By submitting a pull request you agree to the Contributor License Agreement embedded in the [LICENSE](LICENSE) file, granting Cylent Security LLC relicensing and copyright rights over your contribution.

Copyright (c) Cylent Security LLC
