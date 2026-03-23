# Trellis Keychain Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:58:58
**Category**: Keychain/secrets storage patterns and security issues
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 18 |
| Total Findings | 8 |
| Critical | 0 |
| High | 0 |
| Medium | 8 |
| Low | 0 |
| Info | 0 |

---

## Security Findings

### 🟡 MEDIUM (8)

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1001141bc` (Offset: `0x1141bc`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x10020ea58` (Offset: `0x20ea58`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1001a7aa8` (Offset: `0x1a7aa8`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1002f50dc` (Offset: `0x2f50dc`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x100318b04` (Offset: `0x318b04`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1002f4fac` (Offset: `0x2f4fac`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1001c04d4` (Offset: `0x1c04d4`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

#### Missing Keychain Accessibility Attribute

**Description**: Keychain item stored without explicit accessibility level

**Location**: `0x1001c0534` (Offset: `0x1c0534`)

**Function**: `SecItemAdd`

**Evidence**:
- kSecAttrAccessible: `not set (defaults to kSecAttrAccessibleWhenUnlocked)`

**Impact**: Developer may be unaware of keychain protection levels, using defaults

**Recommendation**: Explicitly set kSecAttrAccessible to an appropriate protection level

---

## Functions Analyzed

### `SecIdentityCopyCertificate`

- **Library**: Security.framework
- **Address**: `0xf8`
- **Type**: import

### `SecCertificateCopyData`

- **Library**: Security.framework
- **Address**: `0xfb`
- **Type**: import

### `SecItemUpdate`

- **Library**: Security.framework
- **Address**: `0x101`
- **Type**: import

### `SecItemCopyMatching`

- **Library**: Security.framework
- **Address**: `0x106`
- **Type**: import

### `SecKeyIsAlgorithmSupported`

- **Library**: Security.framework
- **Address**: `0x10a`
- **Type**: import

### `SecItemAdd`

- **Library**: Security.framework
- **Address**: `0x10f`
- **Type**: import

### `SecItemDelete`

- **Library**: Security.framework
- **Address**: `0x115`
- **Type**: import

### `SecKeyCopyExternalRepresentation`

- **Library**: Security.framework
- **Address**: `0x11f`
- **Type**: import

### `SecKeyVerifySignature`

- **Library**: Security.framework
- **Address**: `0x122`
- **Type**: import

### `SecIdentityCopyCertificate`

- **Library**: Security.framework
- **Address**: `0x10036a568`
- **Type**: symbol
- **Call Sites**: 3

| Caller | Address |
|--------|--------|
| `_findIdentity` | `0x1001a7e88` |
| `SSLIdentityDigest` | `0x10021caa8` |
| `description` | `0x1001c8fe0` |

### `SecCertificateCopyData`

- **Library**: Security.framework
- **Address**: `0x10036a58c`
- **Type**: symbol
- **Call Sites**: 5

| Caller | Address |
|--------|--------|
| `checkSSLServerTrust:forHost:port:` | `0x1001b80ec` |
| `_CBLCheckSSLServerTrust` | `0x1001dbc88` |
| `_MYGetCertificateDigestSHA1` | `0x1001a82d8` |
| `connection` | `0x10013bd9c` |
| `_MYGetCertificateDigestSHA256` | `0x1001a8370` |

### `SecItemUpdate`

- **Library**: Security.framework
- **Address**: `0x10036a5d4`
- **Type**: symbol
- **Call Sites**: 2

| Caller | Address |
|--------|--------|
| `storeString:forKey:` | `0x100114138` |
| `updateValueData:forKey:` | `0x1002f51e0` |

### `SecItemCopyMatching`

- **Library**: Security.framework
- **Address**: `0x10036a610`
- **Type**: symbol
- **Call Sites**: 7

| Caller | Address |
|--------|--------|
| `stringForKey:` | `0x100113da8` |
| `loadTokens` | `0x1001c0270` |
| `initWithKeychainItemNamed:error:` | `0x10020e720` |
| `_MYGetOrCreateAnonymousIdentity` | `0x1001a77c8` |
| `_findIdentity` | `0x1001a7f28` |
| `_MYFindIdentity` | `0x1001a8234` |
| `dataForKey:` | `0x1002f4a78` |

### `SecKeyIsAlgorithmSupported`

- **Library**: Security.framework
- **Address**: `0x10036a640`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `verifySignedData:withSignature:withPublicKey:isECDSA:` | `0x100319130` |

### `SecItemAdd`

- **Library**: Security.framework
- **Address**: `0x10036a67c`
- **Type**: symbol
- **Call Sites**: 8

| Caller | Address |
|--------|--------|
| `storeString:forKey:` | `0x1001141bc` |
| `saveKeychainItemNamed:error:` | `0x10020ea58` |
| `_MYGetOrCreateAnonymousIdentity` | `0x1001a7aa8` |
| `setThisDeviceData:forKey:` | `0x1002f50dc` |
| `publicKeyFromData:` | `0x100318b04` |
| `setData:forKey:` | `0x1002f4fac` |
| `saveTokens:error:` | `0x1001c04d4` |
| `saveTokens:error:` | `0x1001c0534` |
- **Findings**: 8 issue(s)

### `SecItemDelete`

- **Library**: Security.framework
- **Address**: `0x10036a6c4`
- **Type**: symbol
- **Call Sites**: 8

| Caller | Address |
|--------|--------|
| `storeString:forKey:` | `0x100113f80` |
| `storeString:forKey:` | `0x1001140a4` |
| `deleteKeychainItemNamed:error:` | `0x10020e89c` |
| `_MYGetOrCreateAnonymousIdentity` | `0x1001a7b00` |
| `_MYDeleteAnonymousIdentity` | `0x1001a8498` |
| `removeObjectForKey:` | `0x1002f5234` |
| `removePublicKeyReference:` | `0x100318c4c` |
| `_deleteTokens` | `0x1001c060c` |

### `SecKeyCopyExternalRepresentation`

- **Library**: Security.framework
- **Address**: `0x10036a73c`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `connection` | `0x10013c508` |

### `SecKeyVerifySignature`

- **Library**: Security.framework
- **Address**: `0x10036a760`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `verifySignedData:withSignature:withPublicKey:isECDSA:` | `0x100319158` |

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
