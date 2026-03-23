# Trellis Crypto Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:58:52
**Category**: Cryptographic function usage and potential vulnerabilities
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 20 |
| Total Findings | 5 |
| Critical | 1 |
| High | 0 |
| Medium | 4 |
| Low | 0 |
| Info | 0 |

---

## Security Findings

### 🔴 CRITICAL (1)

#### Critically Low PBKDF2 Iterations (Decompiler)

**Description**: PBKDF2 caller contains integer 200 — likely iteration count (minimum 10000 recommended)

**Location**: `0x10020e384` (Offset: `0x20e384`)

**Function**: `CCKeyDerivationPBKDF`

**Evidence**:
- rounds_candidate: `200`
- minimum_recommended: `100000`
- caller: `initWithPassword:salt:rounds:`
- detection_method: `decompiler_fallback`

**Impact**: Low iteration count allows brute-force key recovery in seconds

**Recommendation**: Use at least 10000 iterations (OWASP recommends 100000+)

---

### 🟡 MEDIUM (4)

#### Crypto Call — Manual Review Required

**Description**: CCCryptorCreate call in crypto-related function (parameters unresolved)

**Location**: `0x10020eba0` (Offset: `0x20eba0`)

**Function**: `CCCryptorCreate`

**Evidence**:
- caller: `createEncryptor`
- crypto_context: `symmetric encryption`
- note: `Parameter values could not be extracted from decompiler; manual review needed to determine algorithm, key, rounds, etc.`

**Impact**: Crypto implementation may use weak parameters (algorithm, key size, iteration count) but static analysis could not confirm

**Recommendation**: Use Frida to hook CCCryptorCreate at runtime and inspect actual parameters, or analyze the caller function in Ghidra decompiler

---

#### Crypto Call — Manual Review Required

**Description**: CCCryptorCreate call in crypto-related function (parameters unresolved)

**Location**: `0x10020f2f8` (Offset: `0x20f2f8`)

**Function**: `CCCryptorCreate`

**Evidence**:
- caller: `___33-[CBLSymmetricKey_decryptStream:]_block_invoke`
- crypto_context: `symmetric encryption`
- note: `Parameter values could not be extracted from decompiler; manual review needed to determine algorithm, key, rounds, etc.`

**Impact**: Crypto implementation may use weak parameters (algorithm, key size, iteration count) but static analysis could not confirm

**Recommendation**: Use Frida to hook CCCryptorCreate at runtime and inspect actual parameters, or analyze the caller function in Ghidra decompiler

---

#### Crypto Call — Manual Review Required

**Description**: CCKeyDerivationPBKDF call in crypto-related function (parameters unresolved)

**Location**: `0x100183a14` (Offset: `0x183a14`)

**Function**: `CCKeyDerivationPBKDF`

**Evidence**:
- caller: `$$closure_#1_(Swift.UnsafePointer<Swift.UInt8>)_->_Swift.Int32_in_closure_#1_...`
- crypto_context: `key derivation`
- note: `Parameter values could not be extracted from decompiler; manual review needed to determine algorithm, key, rounds, etc.`

**Impact**: Crypto implementation may use weak parameters (algorithm, key size, iteration count) but static analysis could not confirm

**Recommendation**: Use Frida to hook CCKeyDerivationPBKDF at runtime and inspect actual parameters, or analyze the caller function in Ghidra decompiler

---

#### Crypto Call — Manual Review Required

**Description**: CCCrypt call in crypto-related function (parameters unresolved)

**Location**: `0x10020f044` (Offset: `0x20f044`)

**Function**: `CCCrypt`

**Evidence**:
- caller: `decryptData:`
- crypto_context: `symmetric encryption`
- note: `Parameter values could not be extracted from decompiler; manual review needed to determine algorithm, key, rounds, etc.`

**Impact**: Crypto implementation may use weak parameters (algorithm, key size, iteration count) but static analysis could not confirm

**Recommendation**: Use Frida to hook CCCrypt at runtime and inspect actual parameters, or analyze the caller function in Ghidra decompiler

---

## Functions Analyzed

### `CCCryptorFinal`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x172`
- **Type**: import

### `CCHmacInit`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x173`
- **Type**: import

### `CCHmac`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x175`
- **Type**: import

### `CCCryptorRelease`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x179`
- **Type**: import

### `CCHmacFinal`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17a`
- **Type**: import

### `CCCryptorCreate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17c`
- **Type**: import

### `CCKeyDerivationPBKDF`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17e`
- **Type**: import

### `CCHmacUpdate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17f`
- **Type**: import

### `CCCryptorUpdate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x181`
- **Type**: import

### `CCCrypt`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x184`
- **Type**: import

### `CCCryptorFinal`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab20`
- **Type**: symbol
- **Call Sites**: 3

| Caller | Address |
|--------|--------|
| `finishWithError:` | `0x1000fc05c` |
| `___33-[CBLSymmetricKey_decryptStream:]_block_invoke` | `0x10020f40c` |
| `___34-[CBLSymmetricKey_createEncryptor]_block_invoke` | `0x10020ed7c` |

### `CCHmacInit`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab2c`
- **Type**: symbol
- **Call Sites**: 2

| Caller | Address |
|--------|--------|
| `initWithSettings:encryptionKey:HMACKey:IV:handler:` | `0x10011faac` |
| `consumeHeaderFromData:` | `0x1000662b4` |

### `CCHmac`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab44`
- **Type**: symbol
- **Call Sites**: 7

| Caller | Address |
|--------|--------|
| `_CBLHMACSHA1` | `0x1001c5f2c` |
| `_CBLHMACSHA256` | `0x1001c6054` |
| `_PRF` | `0x10012cf04` |
| `_PRF` | `0x10012cf24` |
| `_PRF` | `0x10012cf44` |
| `_PRF` | `0x10012cf64` |
| `_PRF` | `0x10012cf84` |

### `CCCryptorRelease`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab74`
- **Type**: symbol
- **Call Sites**: 4

| Caller | Address |
|--------|--------|
| `dealloc` | `0x1000fbdb4` |
| `___33-[CBLSymmetricKey_decryptStream:]_block_invoke` | `0x10020f418` |
| `___33-[CBLSymmetricKey_decryptStream:]_block_invoke` | `0x10020f4b0` |
| `___34-[CBLSymmetricKey_createEncryptor]_block_invoke` | `0x10020ed88` |

### `CCHmacFinal`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab80`
- **Type**: symbol
- **Call Sites**: 2

| Caller | Address |
|--------|--------|
| `___21-[RNDecryptor_finish]_block_invoke` | `0x1000665d0` |
| `___21-[RNEncryptor_finish]_block_invoke` | `0x100120b3c` |

### `CCCryptorCreate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036ab98`
- **Type**: symbol
- **Call Sites**: 3

| Caller | Address |
|--------|--------|
| `initWithOperation:settings:key:IV:error:` | `0x1000fbc60` |
| `createEncryptor` | `0x10020eba0` |
| `___33-[CBLSymmetricKey_decryptStream:]_block_invoke` | `0x10020f2f8` |
- **Findings**: 2 issue(s)

### `CCKeyDerivationPBKDF`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036abb0`
- **Type**: symbol
- **Call Sites**: 3

| Caller | Address |
|--------|--------|
| `initWithPassword:salt:rounds:` | `0x10020e384` |
| `$$closure_#1_(Swift.UnsafePointer<Swift.UInt8>)_->_Swift.Int32_in_closure_#1_(Swift.UnsafeMutablePointer<Swift.UInt8>)_->_Swift.Int32_in_DVIA_v2.BrokenCryptographyPinDetailsViewController.pbkdf2(password:_Swift.String,salt:_Foundation.Data,keyByteCount:_Swift.Int,rounds:_Swift.Int)_->_Foundation.Data?` | `0x100183a14` |
| `keyForPassword:salt:settings:` | `0x10012be30` |
- **Findings**: 2 issue(s)

### `CCHmacUpdate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036abbc`
- **Type**: symbol
- **Call Sites**: 5

| Caller | Address |
|--------|--------|
| `consumeHeaderFromData:` | `0x10006634c` |
| `___27-[RNDecryptor_decryptData:]_block_invoke` | `0x100065458` |
| `___23-[RNEncryptor_addData:]_block_invoke` | `0x100120618` |
| `___23-[RNEncryptor_addData:]_block_invoke` | `0x100120740` |
| `___21-[RNEncryptor_finish]_block_invoke` | `0x100120ac8` |

### `CCCryptorUpdate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036abd4`
- **Type**: symbol
- **Call Sites**: 3

| Caller | Address |
|--------|--------|
| `addData:error:` | `0x1000fbeec` |
| `___33-[CBLSymmetricKey_decryptStream:]_block_invoke` | `0x10020f344` |
| `___34-[CBLSymmetricKey_createEncryptor]_block_invoke` | `0x10020ed30` |

### `CCCrypt`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036abf8`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decryptData:` | `0x10020f044` |
- **Findings**: 1 issue(s)

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
