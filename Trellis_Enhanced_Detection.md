# Trellis Enhanced Detection Techniques

Trellis uses four complementary techniques to maximize detection coverage when analyzing iOS binaries in Ghidra. These techniques form a layered fallback chain: the decompiler is tried first, then ARM64 backward slicing, then caller-name heuristics, with ObjC selector matching and string cross-referencing operating in parallel to catch what import scanning misses.

---

## 1. ARM64 Backward-Slice Parameter Extraction

### What It Does

When Ghidra's decompiler fails to resolve the parameter values passed to a security-critical function (common with Swift-to-C bridged calls), Trellis falls back to scanning raw ARM64 instructions backward from the call site. It looks for instruction patterns that load immediate values or addresses into the ARM64 argument registers `x0`–`x7`.

### Why It's Needed

iOS apps written in Swift frequently call CommonCrypto C functions like `CCCrypt`, `CCKeyDerivationPBKDF`, and `CCHmac`. The Swift-to-C bridge introduces thunks and wrappers that the Ghidra decompiler often cannot trace through. When this happens, the decompiler reports all parameters as variables or unknowns — and Trellis cannot determine the encryption algorithm, key size, iteration count, or other values needed to identify a vulnerability.

The backward slice recovers these values directly from the machine code, bypassing the decompiler entirely.

### How It Works

The ARM64 calling convention passes the first 8 arguments in registers `x0`–`x7` (or their 32-bit halves `w0`–`w7`). Before a `BL` (branch-with-link) call instruction, the compiler must load these registers with the argument values. Trellis scans up to 20 instructions backward from the call site, looking for three patterns:

**Pattern 1 — Immediate loads (`MOV`/`MOVZ`/`ORR`):**
These load a constant integer directly into a register. For example, `MOV x2, #0` means the `alg` parameter to `CCCrypt` is `kCCAlgorithmAES128` (value 0), while `MOV x2, #1` means `kCCAlgorithmDES`.

**Pattern 2 — Address construction (`ADRP` + `ADD`):**
ARM64 loads 64-bit addresses in two steps. `ADRP` loads a page-aligned base, then `ADD` adds the page offset. Together they form a pointer to data in the binary — often a hardcoded string like an encryption key, file path, or URL. Trellis reconstructs the full address and attempts to read the string at that location.

**Pattern 3 — Register clobbering detection:**
If a register is written by `LDR` (memory load), `BL` (function call), or similar instructions, Trellis marks it as clobbered and stops searching further back for that register. This prevents incorrect resolution from stale values.

The scan processes instructions newest-first (backward from the call), so the first write to each register wins — this correctly handles cases where a register is set multiple times before the call.

### Source Code

**File:** `ghidra_scripts/trellis_ghidra/analysis/extractor.py`

**Register mapping:**

```python
# ARM64 calling convention: x0-x7 for first 8 arguments
_ARM64_ARG_REGISTERS = {
    "x0": 0, "x1": 1, "x2": 2, "x3": 3,
    "x4": 4, "x5": 5, "x6": 6, "x7": 7,
    # 32-bit variants (lower half of x registers)
    "w0": 0, "w1": 1, "w2": 2, "w3": 3,
    "w4": 4, "w5": 5, "w6": 6, "w7": 7,
}

_BACKWARD_SLICE_DEPTH = 20
```

**Core backward slice logic (simplified):**

```python
def _backward_slice_arm64(program, call_address, num_params):
    results = {}        # param_index -> (value, value_type)
    resolved_regs = set()
    adrp_pending = {}   # reg_name -> page_base (waiting for ADD)

    instructions = program.get_instructions_before(
        call_address, _BACKWARD_SLICE_DEPTH
    )

    for insn in instructions:
        mnemonic = insn.getMnemonicString().lower()
        dest_name = insn.getRegister(0).getName().lower()

        # Only care about argument registers
        if dest_name not in _ARM64_ARG_REGISTERS:
            continue
        param_idx = _ARM64_ARG_REGISTERS[dest_name]

        # Skip already-resolved registers (first write wins in backward scan)
        if dest_name in resolved_regs:
            continue

        # Pattern: MOV Xn, #imm / MOVZ Xn, #imm
        if mnemonic in ("mov", "movz", "orr"):
            val = _try_get_scalar_value(insn.getOpObjects(1)[0])
            if val is not None:
                resolved_regs.add(dest_name)
                results[param_idx] = (val, 'int')

        # Pattern: ADRP Xn, #page_addr
        elif mnemonic == "adrp":
            val = _try_get_scalar_value(insn.getOpObjects(1)[0])
            if dest_name in adrp_pending:
                full_addr = val + adrp_pending[dest_name]
                resolved_regs.add(dest_name)
                results[param_idx] = (full_addr, 'string_addr')

        # Pattern: ADD Xn, Xn, #offset (completes ADRP+ADD)
        elif mnemonic == "add":
            adrp_pending[dest_name] = val  # Store offset, wait for ADRP

    return results
```

**Integration point — fallback in `extract_call_info()`:**

```python
def extract_call_info(program, call_site, signature):
    info = ExtractedCallInfo(...)

    # Try decompiler first
    high_func, call_pcode = _find_call_pcode(program, call_site.call_instruction_address)
    # ... extract params from decompiler pcode ...

    # Fallback: ARM64 backward slice for unresolved parameters
    unresolved_count = sum(
        1 for p in info.parameters
        if p.value_if_constant is None and not p.variable_name
    )
    if unresolved_count > 0:
        slice_results = _backward_slice_arm64(
            program, call_site.call_instruction_address,
            len(signature.parameters)
        )
        for param_idx, (value, value_type) in slice_results.items():
            param = info.parameters[param_idx]
            if param.value_if_constant is None and not param.variable_name:
                if value_type == 'int':
                    param.value_if_constant = value
                elif value_type == 'string_addr':
                    string_val = program.read_string_at(value)
                    if string_val:
                        param.value_as_string = string_val

    return info
```

### Practical Impact

Without backward slicing, a `CCCrypt` call in a Swift app would produce a finding like:

> "CCCrypt called — algorithm: unknown, mode: unknown, key: unknown"

With backward slicing, it can produce:

> "CCCrypt called — algorithm: DES (0x1) [CRITICAL], mode: ECB (0x2) [HIGH], key: 0x100045a20 pointing to hardcoded data [CRITICAL]"

---

## 2. Caller-Name Heuristic Checks

### What It Does

When both the decompiler and backward slicing fail to resolve parameter values, Trellis examines the name of the *calling* function for security-relevant keywords. If the caller's name contains terms like "encrypt", "jailbreak", or "auth", the call site is flagged for manual review even though the exact parameters are unknown.

### Why It's Needed

Some call sites resist all automated parameter extraction — the values may come from complex computed expressions, runtime allocations, or deeply nested function chains. Dropping these entirely would create false negatives. The caller-name heuristic provides a safety net: it cannot tell you *what* crypto algorithm is used, but it can tell you that a crypto call is happening inside a function whose name strongly implies a security context.

This heuristic is applied across multiple security domains:

- **Crypto:** Functions containing "encrypt", "decrypt", "crypto", "pbkdf", "derive", "hash", "AES", etc.
- **Jailbreak:** Functions containing "jailbreak", "detect", "tamper", "integrity", "frida", "cydia", "substrate", etc.
- **Anti-debug:** Similar keyword lists for debugging-related contexts.

### How It Works

Each security checker defines a keyword list and a matching function. The heuristic only fires as a fallback — after the primary checks (with resolved parameters) produce no findings. This two-stage design keeps the false-positive rate low: the function was already matched against a security-relevant API signature (e.g., `CCCrypt`, `stat`, `dlopen`), so the only question is whether the context confirms it.

For jailbreak detection, the heuristic also filters out known third-party library prefixes (`_CRYPTO_`, `_SSL_`, `_sqlite3_`, `_curl_`, etc.) to avoid flagging library-internal calls to `stat()` or `dlopen()` that have nothing to do with jailbreak detection.

### Source Code

**File:** `ghidra_scripts/trellis_ghidra/analysis/security_checks_crypto.py`

```python
_CRYPTO_CALLER_KEYWORDS = [
    "encrypt", "decrypt", "crypto", "cryptography", "cipher",
    "pbkdf", "derive", "hash", "digest",
    "RNEncryptor", "RNDecryptor", "SymmetricKey",
    "AES", "DES", "Blowfish", "RC4",
]

def _caller_suggests_crypto(caller_name):
    """Check if the caller function name suggests crypto context."""
    if not caller_name:
        return False
    lower = caller_name.lower()
    for kw in _CRYPTO_CALLER_KEYWORDS:
        if kw.lower() in lower:
            return True
    return False
```

**Fallback in the crypto checker:**

```python
class CryptoSecurityChecker(SecurityChecker):
    def check_call_site(self, function_sig, call_site, extracted_info):
        findings = []

        if func_name in ["CCCrypt", "CCCryptorCreate"]:
            if has_params:
                findings.extend(self._check_cccrypt(...))
            # Caller-name heuristic fallback when params unresolved
            if not findings:
                findings.extend(self._check_crypto_caller_heuristic(
                    function_sig, call_site, extracted_info,
                    "symmetric encryption"
                ))
```

**The heuristic finding generator:**

```python
def _check_crypto_caller_heuristic(self, function_sig, call_site,
                                    extracted_info, crypto_context):
    caller_name = call_site.caller_name
    if _caller_suggests_crypto(caller_name):
        findings.append(SecurityFinding(
            severity=Severity.MEDIUM,
            issue_type="Crypto Call — Manual Review Required",
            description="{} call in crypto-related function "
                        "(parameters unresolved)".format(function_sig.name),
            evidence={
                "caller": caller_name,
                "crypto_context": crypto_context,
                "note": "Parameter values could not be extracted; "
                        "manual review needed"
            },
            recommendation="Use Frida to hook {} at runtime and "
                           "inspect actual parameters".format(function_sig.name)
        ))
```

**File:** `ghidra_scripts/trellis_ghidra/analysis/security_checks_jailbreak.py`

```python
_JAILBREAK_CALLER_KEYWORDS = [
    # Compound patterns (high confidence)
    "jailbreak", "jailbroken", "JailbreakDetection",
    "rootDetect", "deviceIntegrity", "isCompromised",
    # Broader single-word patterns
    "detect", "injected", "dyld", "dylib",
    "disable", "gdb", "debugger",
    "tamper", "integrity", "sandbox",
    "hook", "tweak", "substrate",
    "cydia", "frida", "cycript",
]

# False positive filter: skip known library internals
KNOWN_LIBRARY_PREFIXES = {
    "_CRYPTO_", "_SSL_", "_EVP_", "_sqlite3_",
    "_curl_", "_xml_", "_FIR", ...
}

def _caller_is_known_library(caller_name):
    for prefix in KNOWN_LIBRARY_PREFIXES:
        if caller_name.startswith(prefix):
            return True
    return False
```

### Practical Impact

A Swift function named `$s7MyApp20SecurityManagerC17checkJailbreakStatusSbyF` calls `stat()` but the decompiler can't resolve the path argument. Without the heuristic, this call is silently ignored. With it, Trellis emits:

> "stat() called in jailbreak detection context (caller: checkJailbreakStatus) — manual review recommended"

---

## 3. ObjC Selector Matching via objc_msgSend

### What It Does

Trellis finds Objective-C method calls that are dispatched through `objc_msgSend` by searching the binary's string table for selector strings that match known security-relevant signatures, then following cross-references to locate the actual call sites.

### Why It's Needed

In Objective-C, method calls are not compiled to direct function calls. Instead, every method invocation goes through the runtime dispatcher `objc_msgSend(receiver, selector, ...)`. The selector (e.g., `evaluatePolicy:localizedReason:reply:`) is stored as a string in the binary's `__objc_methnames` section. Traditional import scanning only finds symbols in the import table — it cannot see which ObjC methods are actually called.

This is critical for security analysis because many iOS security APIs are ObjC methods:

- `evaluatePolicy:localizedReason:reply:` — biometric authentication (LAContext)
- `SecItemAdd` / `SecItemCopyMatching` — Keychain access
- `loadHTMLString:baseURL:` — WebView content loading
- `dataTaskWithRequest:completionHandler:` — network requests

### How It Works

Trellis's `find_functions()` pipeline runs three discovery stages in sequence:

1. **Import scanning** — finds symbols in the Mach-O import table
2. **Internal function scanning** — matches function symbols (including Swift demangled names)
3. **ObjC selector scanning** — searches the string table for selector strings

The ObjC selector scanner:

1. Filters the signature database to entries containing `:` (the ObjC selector separator)
2. Iterates all defined strings in the binary
3. For each string that exactly matches a known selector, queries Ghidra for all cross-references to that string's address
4. Each xref represents a call site where `objc_msgSend` is invoked with that selector

### Source Code

**File:** `ghidra_scripts/trellis_ghidra/analysis/finder.py`

```python
def _find_objc_selectors(program, db, already_found_addresses):
    """
    Find ObjC selectors dispatched via objc_msgSend by string-table search.

    ObjC methods like `evaluatePolicy:localizedReason:reply:` are not
    standalone functions — they're dispatched via objc_msgSend with the
    selector as a string argument.
    """
    found = []

    # Only search for signatures that look like ObjC selectors (contain ':')
    objc_signatures = {
        sig.name: sig for sig in db.functions.values()
        if ':' in sig.name
    }

    if not objc_signatures:
        return found

    # Search the string table for selector strings
    for address, string_value in program.get_defined_strings():
        if not string_value or ':' not in string_value:
            continue

        # Check for exact match against our signatures
        if string_value in objc_signatures:
            signature = objc_signatures[string_value]

            # Find xrefs to this string — these are objc_msgSend call sites
            refs = program.get_references_to(address)

            for ref in refs:
                if ref.from_address in already_found_addresses:
                    continue

                func = program.get_function_containing(ref.from_address)

                found.append(FoundFunction(
                    name=signature.name,
                    address=ref.from_address,
                    signature=signature,
                    symbol_type="objc_selector",
                    ghidra_function=func,
                ))
                already_found_addresses.add(ref.from_address)

    return found
```

**Integration in the main discovery pipeline:**

```python
def find_functions(program, db):
    # Stage 1: Find imported functions
    imports = _find_imported_functions(program, db)

    # Stage 2: Find internal functions (including Swift demangled)
    internals = _find_internal_functions(program, db)

    # Track already-found addresses to avoid duplicates
    found_addresses = set(f.address for f in imports + internals)

    # Stage 3: Find ObjC selectors via string-table search
    objc_found = _find_objc_selectors(program, db, found_addresses)

    all_found = imports + internals + objc_found
    all_found.sort(key=lambda f: f.address)
    return all_found
```

### Practical Impact

Without ObjC selector matching, Trellis would miss every `LAContext.evaluatePolicy` call in ObjC-heavy apps — meaning insecure biometric authentication would go undetected. With it, Trellis can locate every call site where biometric auth occurs and check whether it's properly bound to the Keychain (secure) or just a client-side boolean check (trivially bypassable).

---

## 4. String Cross-Referencing with Security-Critical Call Sites

### What It Does

After Trellis's string-table scanner identifies suspicious strings (hardcoded passwords, API keys, HTTP URLs), the cross-reference engine uses Ghidra's xref database to determine which functions reference each string. This links generic string findings to specific security contexts — turning "found a suspicious string" into "found a hardcoded password used in an encryption function."

### Why It's Needed

String scanning inherently produces many candidates that need context to evaluate. A high-entropy string might be an encryption key, a UI animation identifier, or a test fixture. A cleartext HTTP URL might point to a debug endpoint or a production payment gateway. Without context, every finding requires manual triage.

Cross-referencing solves this by answering the question: "Where in the code is this string actually used?" If a hardcoded string is referenced by a function named `encryptUserData`, it's almost certainly an encryption key. If an HTTP URL is referenced by a function named `processPayment`, it's a critical finding.

### How It Works

The cross-reference engine runs after the initial string scan is complete. For each CRITICAL or HIGH severity string finding, it:

1. Queries Ghidra for all references to the string's address
2. Resolves each reference to its containing function
3. Matches the function names against three keyword categories:
   - **Crypto keywords:** encrypt, decrypt, cipher, key, hash, AES, etc.
   - **Auth keywords:** login, auth, password, credential, verify, session, etc.
   - **Payment keywords:** payment, billing, purchase, card, stripe, etc.
4. Generates new, higher-context findings when matches are found

The three keyword categories produce three distinct finding types:

- **"Hardcoded Password Used in Crypto Operation"** — a password string referenced by an encryption function
- **"Hardcoded Credential in Auth Function"** — a credential string referenced by an authentication function
- **"Cleartext HTTP in Payment Flow"** — an HTTP URL referenced by a payment processing function

### Source Code

**File:** `ghidra_scripts/trellis_ghidra/analysis/security_checks_strings.py`

```python
def cross_reference_findings(self):
    """
    Enrich existing string findings with cross-reference analysis.

    Uses Ghidra's xrefs to determine WHICH FUNCTIONS reference each
    suspicious string. This links hardcoded passwords to crypto call
    sites, HTTP URLs to auth functions, etc.
    """
    xref_findings = []

    for finding in self._findings:
        # Only cross-reference CRITICAL and HIGH findings
        if finding.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue

        # Get xrefs to the string address
        refs = self.program.get_references_to(finding.location)

        # Collect referencing function names
        referencing_functions = []
        for ref in refs:
            func = self.program.get_function_containing(ref.from_address)
            if func:
                referencing_functions.append(func.name)

        # Match against security-domain keyword lists
        crypto_callers = self._match_function_keywords(
            referencing_functions, _CRYPTO_FUNCTION_KEYWORDS
        )
        auth_callers = self._match_function_keywords(
            referencing_functions, _AUTH_FUNCTION_KEYWORDS
        )
        payment_callers = self._match_function_keywords(
            referencing_functions, _PAYMENT_FUNCTION_KEYWORDS
        )

        # Generate cross-reference findings
        if crypto_callers and "Hardcoded Password" in finding.issue_type:
            xref_findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded Password Used in Crypto Operation",
                description="Hardcoded password string is referenced by "
                            "crypto function(s)",
                evidence={
                    "string_value": finding.evidence.get("value"),
                    "crypto_functions": ", ".join(crypto_callers[:3]),
                    "total_references": str(len(referencing_functions)),
                },
                impact="All installations share the same key — data "
                       "encrypted by one user can be decrypted by any "
                       "attacker who extracts this string",
            ))

        if auth_callers and "Hardcoded Password" in finding.issue_type:
            xref_findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Hardcoded Credential in Auth Function",
                evidence={
                    "string_value": finding.evidence.get("value"),
                    "auth_functions": ", ".join(auth_callers[:3]),
                },
                impact="Attacker can extract credentials from the binary",
            ))

        if payment_callers and "HTTP" in finding.issue_type:
            xref_findings.append(SecurityFinding(
                severity=Severity.CRITICAL,
                issue_type="Cleartext HTTP in Payment Flow",
                evidence={
                    "url": finding.evidence.get("url"),
                    "payment_functions": ", ".join(payment_callers[:3]),
                },
                impact="Payment data transmitted over cleartext HTTP — "
                       "trivially interceptable via MITM",
            ))

    return xref_findings
```

**Keyword matching helper:**

```python
@staticmethod
def _match_function_keywords(func_names, keywords):
    """Return function names that contain any of the given keywords."""
    matched = []
    for name in func_names:
        lower = name.lower()
        for kw in keywords:
            if kw.lower() in lower:
                matched.append(name)
                break
    return matched
```

### Practical Impact

A string scan might find `"S3cr3tK3y!2024"` in the binary and flag it as a potential hardcoded password. Without cross-referencing, the analyst must manually search the binary to determine whether it's actually used for encryption or just a test string.

With cross-referencing, Trellis reports:

> "**Hardcoded Password Used in Crypto Operation** — String `S3cr3tK3y!2024` is referenced by `encryptionManager_encryptData` (1 of 3 references). All installations share the same key."

This immediately tells the analyst: this is a confirmed critical finding, not a false positive.

---

## 5. Interprocedural Call-Chain Analysis for Secret Sinks

### What It Does

When Trellis detects a hardcoded secret string in the binary (via the string-table scanner) and a sensitive crypto/keychain/network sink function (via import scanning), the interprocedural call-chain analyzer determines whether the secret *flows* to the sink — even when they are in different functions connected through intermediate library calls.

### Why It's Needed

iOS apps commonly use wrapper libraries for cryptographic operations. A developer writes `RNEncryptor.encryptData(data, password: "@daloq3as$qweasdlasasjdnj")` in their view controller, but the actual `CCCrypt` call happens deep inside the RNEncryptor library. The hardcoded password and the crypto sink are separated by one or more function call boundaries:

```
textFieldShouldReturn  (references "@daloq3as$qweasdlasasjdnj")
    └── RNEncryptor.encryptData
            └── initWithOperation:settings:key:IV:error:
                    └── CCCryptorCreate  (crypto sink)
```

Single-hop cross-referencing (checking only the sink's direct caller) misses this entirely — the direct caller is an RNEncryptor internal function that doesn't reference the password string. The secret and the sink only connect through the call chain.

### How It Works

The analyzer uses three strategies in sequence, each designed to handle a different call-graph topology.

**Step 1 — Build caches (once per analysis run):**

- **Secret-ref cache:** For every CRITICAL/HIGH string finding from the string-table scanner, query Ghidra's cross-references to find which functions reference that string. Build a lookup table: `function_address → [(secret_address, secret_value), ...]`.
- **Crypto-selector cache:** Scan the binary's string table for ObjC selector strings that indicate crypto operations (e.g., `encryptData:withSettings:password:error:`, `initWithPassword:`, `SecItemAdd`). Store their addresses.

**Step 2 — Strategy 1: BFS call-chain traversal (direct calls):**

For each unresolved sink call, start BFS from the sink's direct caller:

1. Check if the current function is in the secret-ref cache → if yes, we found a match
2. If depth < max (3 hops), query `get_callers()` for this function and add each caller to the BFS queue
3. Track visited functions to avoid cycles
4. Record the full call chain for each match

This catches secrets flowing through direct `BL`/`B` call chains (C functions calling C functions).

**Step 3 — Strategy 2: Forward selector search (ObjC dispatch):**

The BFS strategy has a fundamental limitation: `get_callers()` only finds direct branch instructions. In Objective-C, method calls go through `objc_msgSend(receiver, selectorString, ...)` — the runtime dispatcher. The compiler emits a `BL _objc_msgSend` instruction with the selector loaded as a string argument, not a direct call to the target method. This means `get_callers()` on `RNEncryptor.encryptData:...` returns nothing useful — it sees calls to `_objc_msgSend`, not calls to the encryption method.

The forward selector search reverses the direction: instead of walking up from the sink, it checks each function in the secret-ref cache (functions that reference a known secret) to see if that same function *also* references a crypto-related ObjC selector string. If a function references both the secret AND a crypto selector, the secret flows to crypto code via `objc_msgSend` dispatch.

For the DVIA-v2 encryption key:

```
textFieldShouldReturn:
  ├── references string "@daloq3as$qweasdlasasjdnj"  ← secret (in cache)
  └── references selector "encryptData:withSettings:password:error:"  ← crypto selector
      (dispatched via objc_msgSend to RNEncryptor)
```

Both references are in the same function → CRITICAL finding.

**Step 4 — Strategy 3: Decompiler string scan (last resort):**

If strategies 1 and 2 find nothing, decompile the sink's direct caller and regex-search the pseudocode for string literals that look like secrets (high entropy, special characters).

**Step 5 — Report with evidence:**

Matched findings include the detection method and context (call chain for BFS, selector name for forward search), enabling the analyst to verify the data flow.

### Source Code

**File:** `ghidra_scripts/trellis_ghidra/analysis/security_checks_secret_sinks.py`

**Cache construction:**

```python
def _build_secret_ref_cache(self):
    """Build lookup: function_address → [(secret_addr, secret_value), ...]"""
    cache = {}
    for secret_addr, secret_value in self._secret_strings.items():
        refs = self.program.get_references_to(secret_addr)
        for ref in refs:
            func = self.program.get_function_containing(ref.from_address)
            if func:
                if func.address not in cache:
                    cache[func.address] = []
                cache[func.address].append((secret_addr, secret_value))
    return cache
```

**BFS traversal:**

```python
_MAX_CALL_CHAIN_DEPTH = 3

def _find_secret_in_call_chain(self, start_func):
    """BFS up the call chain, checking each function for secret refs."""
    if not hasattr(self, '_secret_ref_cache'):
        self._secret_ref_cache = self._build_secret_ref_cache()

    results = []
    visited = set()
    queue = [(start_func.address, 0, [start_func.name])]
    visited.add(start_func.address)

    while queue:
        func_addr, depth, chain = queue.pop(0)

        # Check if this function references any secret
        if func_addr in self._secret_ref_cache:
            for secret_addr, secret_value in self._secret_ref_cache[func_addr]:
                display_chain = list(reversed(chain))
                results.append((secret_addr, secret_value, display_chain))

        if depth >= _MAX_CALL_CHAIN_DEPTH:
            continue

        # Walk up: find callers of this function
        callers = self.program.get_callers(func_addr)
        for ref in callers:
            caller_func = self.program.get_function_containing(ref.from_address)
            if caller_func and caller_func.address not in visited:
                visited.add(caller_func.address)
                queue.append((
                    caller_func.address,
                    depth + 1,
                    chain + [caller_func.name]
                ))

    return results
```

**Forward selector search:**

```python
_CRYPTO_SELECTORS = [
    'encryptData:', 'decryptData:', 'encryptData:with', 'decryptData:with',
    'RNEncryptor', 'RNDecryptor',
    'initWithOperation:settings:key:', 'initWithPassword:',
    'CCCrypt', 'CCCryptorCreate', 'CCKeyDerivation',
    'SecItemAdd', 'SecItemUpdate',
]

def _forward_selector_search(self, function_sig, call_site, config):
    """Check if secret-holding functions also reference crypto selectors."""
    for func_addr, secrets in self._secret_ref_cache.items():
        for sel_addr, sel_name in self._crypto_selector_addrs:
            refs = self.program.get_references_to(sel_addr)
            for ref in refs:
                ref_func = self.program.get_function_containing(ref.from_address)
                if ref_func and ref_func.address == func_addr:
                    # Function references BOTH a secret AND a crypto selector
                    for secret_addr, secret_value in secrets:
                        findings.append(SecurityFinding(
                            severity=Severity.CRITICAL,
                            issue_type="Hardcoded Secret Flows to Crypto Sink",
                            evidence={
                                "secret_value": secret_value[:50],
                                "crypto_selector": sel_name,
                                "detection_method": "forward_selector_search",
                            },
                        ))
```

**Integration in the xref fallback (three strategies in sequence):**

```python
def _xref_fallback(self, function_sig, call_site, config):
    caller_func = self.program.get_function_containing(
        call_site.call_instruction_address
    )

    # Strategy 1: BFS up the call chain (direct BL/B calls)
    matched = self._find_secret_in_call_chain(caller_func)
    # ... generate findings from matched ...

    # Strategy 2: Forward selector search (bridges objc_msgSend)
    if not findings:
        findings.extend(self._forward_selector_search(
            function_sig, call_site, config
        ))

    # Strategy 3: Decompiler string scan (last resort)
    if not findings:
        findings.extend(self._decompiler_string_scan(
            function_sig, call_site, config, caller_func
        ))
```

### Performance

The secret-ref cache and crypto-selector cache are built once per analysis run. The BFS is bounded by `_MAX_CALL_CHAIN_DEPTH = 3` and a visited-set. The forward selector search iterates secret-holding functions × crypto selectors and checks xrefs, but both sets are small (tens of functions, tens of selectors). The entire analysis completes in seconds.

### Practical Impact

Without interprocedural analysis, the hardcoded encryption key `@daloq3as$qweasdlasasjdnj` is flagged by the string scanner as a suspicious password, but the secret sinks module reports 0 findings — it cannot connect the key to the `CCCryptorCreate` call through the RNEncryptor wrapper.

The BFS alone also cannot bridge this gap because `get_callers()` doesn't see ObjC message dispatch. The forward selector search solves this:

> **Hardcoded Secret Flows to Crypto Sink** — Function `textFieldShouldReturn` references both hardcoded secret `@daloq3as$qweasdlasasjdnj` and crypto selector `encryptData:withSettings:password:error:`. Detection method: forward_selector_search.

---

## How the Techniques Work Together

The five techniques form a detection pipeline:

```
Binary Analysis Pipeline
========================

1. find_functions()
   ├── Import scanning          → finds C functions (CCCrypt, ptrace, etc.)
   ├── Internal symbol scanning → finds Swift functions (demangled matching)
   └── ObjC selector matching   → finds ObjC methods (via string table + xrefs)

2. extract_call_info()
   ├── Decompiler extraction    → tries Ghidra's P-code analysis first
   └── ARM64 backward slice     → fallback for unresolved Swift-to-C params

3. Security checkers
   ├── Parameter-based checks   → checks specific values (algorithm, mode, etc.)
   └── Caller-name heuristics   → fallback when no params resolved

4. String cross-referencing
   ├── String table scan        → finds suspicious strings (passwords, keys, URLs)
   └── Xref enrichment          → links strings to crypto/auth/payment functions

5. Interprocedural secret-sink analysis
   ├── Secret-ref cache         → maps functions to known secret strings
   ├── BFS call-chain traversal → walks callers up to 3 hops (direct BL/B calls)
   └── Forward selector search  → bridges objc_msgSend by matching secret + crypto selector in same function
```

Each layer catches what the previous one missed, producing comprehensive coverage without requiring any single technique to be perfect.
