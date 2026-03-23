# Trellis Secret_Sinks Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 18:01:13
**Category**: Hardcoded secrets flowing into crypto/keychain/network sinks
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 55 |
| Total Findings | 1 |
| Critical | 1 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

---

## Security Findings

### 🔴 CRITICAL (1)

#### Hardcoded Secret Flows to Crypto Sink

**Description**: Function references both hardcoded secret and crypto selector 'decryptData:withPassword:error:'

**Location**: `0x1001978e8` (Offset: `0x1978e8`)

**Function**: `textFieldShouldReturn`

**Evidence**:
- sink: `decryptData:withPassword:error:`
- sink_type: `Crypto operation (ObjC dispatch)`
- secret_value: `@daloq3as$qweasdlasasjdnj`
- secret_address: `0x100389440`
- crypto_selector: `decryptData:withPassword:error:`
- detection_method: `forward_selector_search`

**Impact**: Hardcoded secret is passed to crypto operation via ObjC message dispatch

**Recommendation**: Derive keys from user input at runtime or use iOS Keychain for secret storage

---

## Functions Analyzed

### `SecItemUpdate`

- **Library**: Security.framework
- **Address**: `0x101`
- **Type**: import

### `SecItemAdd`

- **Library**: Security.framework
- **Address**: `0x10f`
- **Type**: import

### `CCHmac`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x175`
- **Type**: import

### `CCCryptorCreate`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17c`
- **Type**: import

### `CCKeyDerivationPBKDF`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x17e`
- **Type**: import

### `CCCrypt`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x184`
- **Type**: import

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001a2940`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `connect` | `0x1001a2940` |
- **Findings**: 1 issue(s)

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001a2e64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___28-[CBLBlipReplicator_connect]_block_invoke` | `0x1001a2e64` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001ba7d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `start` | `0x1001ba7d4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001baa0c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___25-[CBLChangeTracker_start]_block_invoke` | `0x1001baa0c` |

### `addValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001bfe20`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `authorizeURLRequest:` | `0x1001bfe20` |

### `addValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c2a24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithMethod:URL:body:onCompletion:` | `0x1001c2a24` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c2dc4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compressBody` | `0x1001c2dc4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c3edc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `willSendRequest:redirectResponse:` | `0x1001c3edc` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c4e10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithMethod:URL:body:onCompletion:` | `0x1001c4e10` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c9488`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithURL:database:onCompletion:` | `0x1001c9488` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001c94a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithURL:database:onCompletion:` | `0x1001c94a4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001cc3fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `openForURLRequest:` | `0x1001cc3fc` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001d10e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createTaskInURLSession:` | `0x1001d10e8` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001db19c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `authorizeURLRequest:` | `0x1001db19c` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001db7ec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `authorizeURLRequest:` | `0x1001db7ec` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1001e08d0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___67-[CBLCookieStorage(NSURLRequestResponse)_addCookieHeaderToRequest:]_block_invoke` | `0x1001e08d0` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1002067f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithDbURL:database:revisions:attachments:onDocument:onCompletion:` | `0x1002067f4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100206810`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithDbURL:database:revisions:attachments:onDocument:onCompletion:` | `0x100206810` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100223160`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `prepare` | `0x100223160` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100229470`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_setOa_parameters:]` | `0x100229470` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100229538`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_setHTTPBodyWithString:]` | `0x100229538` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1002295e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_attachFileWithName:filename:contentType:data:]` | `0x1002295e8` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1002295f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_attachFileWithName:filename:contentType:data:]` | `0x1002295f4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100229834`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_attachFileWithName:filename:contentType:data:]` | `0x100229834` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10022e098`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createTaskInURLSession:` | `0x10022e098` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10022e104`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createTaskInURLSession:` | `0x10022e104` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1002408c0`
- **Type**: symbol

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1002408f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setValue:forHTTPHeaderField:` | `0x1002408f4` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10024094c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setObject:forKeyedSubscript:` | `0x10024094c` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100240aa0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `URLRequest` | `0x100240aa0` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100240c20`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `newHTTPRequest` | `0x100240c20` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100242004`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithURLRequest:` | `0x100242004` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10024d8bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___30-[PSWebSocketServer_pumpInput]_block_invoke` | `0x10024d8bc` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100287e90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `httpResponseForMethod:URI:` | `0x100287e90` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100304244`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `submitURLWithCompletionHandler:` | `0x100304244` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10032a360`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___77-[FConfigRemoteAPIClient_fetchConfigWithRequest:withEndpoint:withCompletion:]_block_invoke` | `0x10032a360` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100361e78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `baseRequest` | `0x100361e78` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100361e90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `baseRequest` | `0x100361e90` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x100362050`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `requestPostUrl:payload:compression:` | `0x100362050` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1003620c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `requestPostUrl:payload:compression:` | `0x1003620c8` |

### `SecItemUpdate`

- **Library**: Security.framework
- **Address**: `0x10036a5d4`
- **Type**: symbol
- **Call Sites**: 2

| Caller | Address |
|--------|--------|
| `storeString:forKey:` | `0x100114138` |
| `updateValueData:forKey:` | `0x1002f51e0` |

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

### `CCCrypt`

- **Library**: libcommonCrypto.dylib
- **Address**: `0x10036abf8`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decryptData:` | `0x10020f044` |

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x10048b458`
- **Type**: objc_selector

### `setValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1004c4468`
- **Type**: objc_selector

### `addValue:forHTTPHeaderField:`

- **Library**: Foundation.framework
- **Address**: `0x1004c5068`
- **Type**: objc_selector

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
