# Trellis Runtime Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 18:00:13
**Category**: Runtime manipulation vulnerabilities (client-side auth, hardcoded comparisons)
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 377 |
| Total Findings | 11 |
| Critical | 0 |
| High | 0 |
| Medium | 11 |
| Low | 0 |
| Info | 0 |

---

## Security Findings

### 🟡 MEDIUM (11)

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x1001bf5d4` (Offset: `0x1bf5d4`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `continueAsyncLoginWithURL:continuation:`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: caseInsensitiveCompare: called in authentication function (parameters unresolved)

**Location**: `0x1001bfa50` (Offset: `0x1bfa50`)

**Function**: `caseInsensitiveCompare:`

**Evidence**:
- comparison_method: `caseInsensitiveCompare:`
- caller: `___69-[CBLOpenIDConnectAuthorizer_continueAsyncLoginWithURL:continuation:]_bl...`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10022bad4` (Offset: `0x22bad4`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `verifyDigest:`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10023f840` (Offset: `0x23f840`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `checkAuthentication:user:`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x100241848` (Offset: `0x241848`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `credentialForAuthHeader:`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x100241874` (Offset: `0x241874`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `credentialForAuthHeader:`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10027a8f8` (Offset: `0x27a8f8`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `isAuthenticated`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10027a954` (Offset: `0x27a954`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `isAuthenticated`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10027a958` (Offset: `0x27a958`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `isAuthenticated`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10027aaa4` (Offset: `0x27aaa4`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `isAuthenticated`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

#### Client-Side Authentication Check

**Description**: isEqualToString: called in authentication function (parameters unresolved)

**Location**: `0x10027aef8` (Offset: `0x27aef8`)

**Function**: `isEqualToString:`

**Evidence**:
- comparison_method: `isEqualToString:`
- caller: `isAuthenticated`
- note: `String comparison in auth context — likely comparing against hardcoded or locally-stored credential`

**Impact**: Client-side authentication can be bypassed by hooking the comparison method to always return true

**Recommendation**: Implement server-side authentication; client should only send credentials, not validate them locally

---

## Functions Analyzed

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100082100`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10013499c`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10019edfc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compileMapFunction:language:` | `0x10019edfc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10019efa8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compileReduceFunction:language:` | `0x10019efa8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10019f214`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compileFilterFunction:language:` | `0x10019f214` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001a4694`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001a46e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x1001a46e4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001a4720`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x1001a4720` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001a6078`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___31-[CBL_RevisionList_sortByDocID]_block_invoke` | `0x1001a6078` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001a8c58`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `hasSameSettingsAs:` | `0x1001a8c58` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001aadf0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `receivedResponseHeaders:` | `0x1001aadf0` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001aaed8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serverIsSyncGatewayVersion:` | `0x1001aaed8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001ae21c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___36-[CBLRestPuller_pullRemoteRevision:]_block_invoke` | `0x1001ae21c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001b3c80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `beginReplicating` | `0x1001b3c80` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001b4828`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x1001b4828` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001b493c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x1001b493c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001b4b84`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `processInbox:` | `0x1001b4b84` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001b7948`
- **Type**: symbol

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001b8ecc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_AllLogDomains` | `0x1001b8ecc` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001b9544`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___InitLogging_block_invoke` | `0x1001b9544` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001bf5d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `continueAsyncLoginWithURL:continuation:` | `0x1001bf5d4` |
- **Findings**: 1 issue(s)

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001bfa50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___69-[CBLOpenIDConnectAuthorizer_continueAsyncLoginWithURL:continuation:]_block_invoke_2` | `0x1001bfa50` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001c17c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setMapBlock:reduceBlock:version:` | `0x1001c17c4` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001c75e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___CBLSanitizeHTTPHeaderFields_block_invoke` | `0x1001c75e0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001cb8e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_runningInAppExtension` | `0x1001cb8e8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001ce00c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___49-[CBLSyncConnection(Pull)_handleIncomingChanges:]_block_invoke` | `0x1001ce00c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001ce108`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___49-[CBLSyncConnection(Pull)_handleIncomingChanges:]_block_invoke` | `0x1001ce108` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001cfdc8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___62-[CBLSyncConnection(Pull)_requestAttachment:named:onComplete:]_block_invoke.234` | `0x1001cfdc8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001cfe80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___62-[CBLSyncConnection(Pull)_requestAttachment:named:onComplete:]_block_invoke.234` | `0x1001cfe80` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001d0814`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___42-[CBLSyncConnection(Pull)_insertRevisions]_block_invoke_2` | `0x1001d0814` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001d0aec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___42-[CBLSyncConnection(Pull)_insertRevisions]_block_invoke_2` | `0x1001d0aec` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001d2288`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___71-[CBLDatabase(Attachments)_registerAttachmentBodies:forRevision:error:]_block_invoke` | `0x1001d2288` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001d22b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___71-[CBLDatabase(Attachments)_registerAttachmentBodies:forRevision:error:]_block_invoke` | `0x1001d22b8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d2df4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___95-[CBLDatabase(Attachments)_processAttachmentsForRevision:ancestry:allowStubAttachments:status:]_block_invoke` | `0x1001d2df4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d2ed8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___95-[CBLDatabase(Attachments)_processAttachmentsForRevision:ancestry:allowStubAttachments:status:]_block_invoke` | `0x1001d2ed8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d59dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `usingProxyForURL:` | `0x1001d59dc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001d7694`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startedPart:` | `0x1001d7694` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d7704`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startedPart:` | `0x1001d7704` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d7d08`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `registerAttachments` | `0x1001d7d08` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d7e28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `registerAttachments` | `0x1001d7e28` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d8964`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithName:info:status:` | `0x1001d8964` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001d8a40`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithName:info:status:` | `0x1001d8a40` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001d9654`
- **Type**: symbol

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001d9a40`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `containsAllTerms:` | `0x1001d9a40` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001daf5c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithConsumerKey:consumerSecret:token:tokenSecret:signatureMethod:` | `0x1001daf5c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001daf78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithConsumerKey:consumerSecret:token:tokenSecret:signatureMethod:` | `0x1001daf78` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001dbbf0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLCheckSSLServerTrust` | `0x1001dbbf0` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001dbc94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLCheckSSLServerTrust` | `0x1001dbc94` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001dbe2c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLCheckSSLServerTrust` | `0x1001dbe2c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001dbe44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLCheckSSLServerTrust` | `0x1001dbe44` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001dbe68`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLCheckSSLServerTrust` | `0x1001dbe68` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001dc154`
- **Type**: symbol

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001dd4a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadCurrentRevisionFrom:` | `0x1001dd4a4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001dd97c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `propertiesToInsert:error:` | `0x1001dd97c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001deb3c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___34-[CBLCookieStorage_cookiesForURL:]_block_invoke` | `0x1001deb3c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001defac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `deleteCookiesNamed:` | `0x1001defac` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001df380`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `deleteCookie:outIndex:` | `0x1001df380` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001df3d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `deleteCookie:outIndex:` | `0x1001df3d8` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1001df4c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `deleteCookie:outIndex:` | `0x1001df4c8` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1001e0184`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isExpiredCookie:` | `0x1001e0184` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001e0318`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isDomainMatchedBetweenCookie:andUrl:` | `0x1001e0318` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001e03c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isPathMatchedBetweenCookie:andUrl:` | `0x1001e03c8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001e1a6c`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001e35ac`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001e363c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x1001e363c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001e68c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_dbChanged:` | `0x1001e68c4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001e6958`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_dbChanged:` | `0x1001e6958` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001ec9b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___22-[CBLLiveQuery_update]_block_invoke` | `0x1001ec9b4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001ed5dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `indexPathForDocument:` | `0x1001ed5dc` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001eee5c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `indexPathForElementWithModelIdentifier:inView:` | `0x1001eee5c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f1070`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `matchValue:forKey:` | `0x1001f1070` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f14ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `matchValue:forKey:` | `0x1001f14ac` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f14e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `matchValue:forKey:` | `0x1001f14e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f1520`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `matchValue:forKey:` | `0x1001f1520` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f15a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startArray` | `0x1001f15a8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1001f213c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAttributes:ofDir:error:` | `0x1001f213c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f2ebc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `upgradeDatabaseNamed:atPath:andClose:error:` | `0x1001f2ebc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f3060`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `upgradeDatabaseNamed:atPath:andClose:error:` | `0x1001f3060` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f31ec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `upgradeDatabaseNamed:atPath:andClose:error:` | `0x1001f31ec` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001f3348`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `upgradeV1DatabaseNamed:atPath:error:` | `0x1001f3348` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001fb3a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLGeoJSONBoundingBox` | `0x1001fb3a0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1001fb3dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLGeoJSONBoundingBox` | `0x1001fb3dc` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100202ee4`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100202fa4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x100202fa4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100202fd0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x100202fd0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002039c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___45-[CBLSyncListenerImpl_blipConnectionDidOpen:]_block_invoke_2` | `0x1002039c8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002039e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___45-[CBLSyncListenerImpl_blipConnectionDidOpen:]_block_invoke_2` | `0x1002039e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100205804`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `readResponseHeader` | `0x100205804` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10020896c`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002089a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x1002089a0` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100209928`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10020b564`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b564` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10020b5a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b5a0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10020b618`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b618` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10020f968`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_$equal` | `0x10020f968` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100210ab8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSDictionary(MYUtils)_my_compactDescription]` | `0x100210ab8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100213134`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSError(MYUtils)_my_hasDomain:code:]` | `0x100213134` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100213f30`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSURL(MYUtilities)_my_isHTTPS]` | `0x100213f30` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021404c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSURL(MYUtilities)_my_baseURL]` | `0x10021404c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100214e48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupBackgrounding` | `0x100214e48` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100214e64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupBackgrounding` | `0x100214e64` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100215628`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `fileAccessChanged:` | `0x100215628` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100216e8c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addKeyPredicate:` | `0x100216e8c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100216f48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addKeyPredicate:` | `0x100216f48` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100217898`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `lookForDocTypeEqualityTest:` | `0x100217898` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100218264`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `rewriteKeyPath:` | `0x100218264` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100218b0c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_sortMatchesExpression` | `0x100218b0c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10021a690`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021a738`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToConsumer:` | `0x10021a738` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021a770`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToConsumer:` | `0x10021a770` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021bfac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `changedKeys` | `0x10021bfac` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021c0d0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `changedKeys` | `0x10021c0d0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021c0e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `changedKeys` | `0x10021c0e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021c5e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithManager:port:` | `0x10021c5e8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021d4c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `openWithOptions:error:` | `0x10021d4c4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021f030`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x10021f030` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021f070`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x10021f070` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021f298`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x10021f298` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10021f310`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dbChanged:` | `0x10021f310` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100221b4c`
- **Type**: symbol

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100221bd4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x100221bd4` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100221d00`
- **Type**: symbol

### `compare:`

- **Library**: Foundation
- **Address**: `0x10022204c`
- **Type**: symbol

### `compare:`

- **Library**: Foundation
- **Address**: `0x10022389c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_normalize` | `0x10022389c` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002238e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_normalize` | `0x1002238e8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10022401c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___74-[CBLArrayDiff_initWithBeforeArray:afterArray:detectMoves:itemComparator:]_block_invoke` | `0x10022401c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100225798`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225840`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToRequestParameter:` | `0x100225840` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225878`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToRequestParameter:` | `0x100225878` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225d24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225d24` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225d5c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225d5c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225d98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225d98` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225dd4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225dd4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225e40`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225e40` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225ea4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225ea4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225ed4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225ed4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100225eec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHTTPResponseBody:` | `0x100225eec` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100226280`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isValid` | `0x100226280` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002262ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isValid` | `0x1002262ac` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100226ba4`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100226c50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToToken:` | `0x100226c50` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100226c88`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqualToToken:` | `0x100226c88` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10022779c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___47-[CBLSyncConnection(Checkpoints)_getCheckpoint]_block_invoke` | `0x10022779c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100228f38`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_parameters]` | `0x100228f38` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100228f58`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_parameters]` | `0x100228f58` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100228f84`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_parameters]` | `0x100228f84` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10022900c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_oa_parameters]` | `0x10022900c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002293b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_setOa_parameters:]` | `0x1002293b8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002293d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableURLRequest(OAParameterAdditions)_setOa_parameters:]` | `0x1002293d8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100229a44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLQueryRowValueIsEntireDoc` | `0x100229a44` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100229e24`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100229f6c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compareForArrayDiff:` | `0x100229f6c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10022bad4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `verifyDigest:` | `0x10022bad4` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100234d44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___56-[CBLWebSocketChangeTracker_webSocket:didFailWithError:]_block_invoke` | `0x100234d44` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002390b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_setError:` | `0x1002390b4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002390c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_setError:` | `0x1002390c8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10023f840`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkAuthentication:user:` | `0x10023f840` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100240770`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `useTLS` | `0x100240770` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100240790`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `useTLS` | `0x100240790` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100241704`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `redirect` | `0x100241704` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100241730`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `redirect` | `0x100241730` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100241848`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `credentialForAuthHeader:` | `0x100241848` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100241874`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `credentialForAuthHeader:` | `0x100241874` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002423cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `close` | `0x1002423cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100245c10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `failWithError:` | `0x100245c10` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100247674`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isWebSocketRequest:` | `0x100247674` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002476c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isWebSocketRequest:` | `0x1002476c4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024770c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isWebSocketRequest:` | `0x10024770c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100247750`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isWebSocketRequest:` | `0x100247750` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100247e54`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `writeHandshakeRequest` | `0x100247e54` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100247e88`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `writeHandshakeRequest` | `0x100247e88` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100248cc4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `readBytes:maxLength:error:` | `0x100248cc4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100248d34`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `readBytes:maxLength:error:` | `0x100248d34` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024a530`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `pmdConfigureWithExtensionsHeaderComponents:` | `0x10024a530` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024a554`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `pmdConfigureWithExtensionsHeaderComponents:` | `0x10024a554` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024a5b0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `pmdConfigureWithExtensionsHeaderComponents:` | `0x10024a5b0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024a618`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `pmdConfigureWithExtensionsHeaderComponents:` | `0x10024a618` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024a640`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `pmdConfigureWithExtensionsHeaderComponents:` | `0x10024a640` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10024b70c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithHost:port:SSLCertificates:` | `0x10024b70c` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002599dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `winnerWithDocID:oldWinner:oldDeleted:newRev:` | `0x1002599dc` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x10025df60`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___39-[CBL_SQLiteViewStorage_updateIndexes:]_block_invoke` | `0x10025df60` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x10025e498`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___39-[CBL_SQLiteViewStorage_updateIndexes:]_block_invoke` | `0x10025e498` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10025e78c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___39-[CBL_SQLiteViewStorage_updateIndexes:]_block_invoke` | `0x10025e78c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10025e918`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___39-[CBL_SQLiteViewStorage_updateIndexes:]_block_invoke` | `0x10025e918` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027859c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compileFromProperties:language:` | `0x10027859c` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1002794dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithRequest:` | `0x1002794dc` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100279544`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithRequest:` | `0x100279544` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a698`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `supportsMethod:atPath:` | `0x10027a698` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a6b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `supportsMethod:atPath:` | `0x10027a6b8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a704`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `expectsRequestBodyFromMethod:atPath:` | `0x10027a704` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a724`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `expectsRequestBodyFromMethod:atPath:` | `0x10027a724` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a8f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isAuthenticated` | `0x10027a8f8` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a954`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isAuthenticated` | `0x10027a954` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027a958`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isAuthenticated` | `0x10027a958` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027aaa4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isAuthenticated` | `0x10027aaa4` |
- **Findings**: 1 issue(s)

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027aef8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isAuthenticated` | `0x10027aef8` |
- **Findings**: 1 issue(s)

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x10027b99c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseRangeRequest:withContentLength:satisfiableRange:` | `0x10027b99c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027bf98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `replyToHTTPRequest` | `0x10027bf98` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027bfb4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `replyToHTTPRequest` | `0x10027bfb4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027cb98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `sendResponseHeadersAndBody` | `0x10027cb98` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10027dad4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `filePathForURI:allowDirectory:` | `0x10027dad4` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x10027ee98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `socket:didReadData:withTag:` | `0x10027ee98` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028005c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `shouldDie` | `0x10028005c` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100280094`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `shouldDie` | `0x100280094` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002800c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `shouldDie` | `0x1002800c4` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1002800fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `shouldDie` | `0x1002800fc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028793c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `remoteURL` | `0x10028793c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100287954`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `remoteURL` | `0x100287954` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002885ec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[CBLHTTPResponse_initWithRouter:forConnection:]_block_invoke.31` | `0x1002885ec` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100288604`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[CBLHTTPResponse_initWithRouter:forConnection:]_block_invoke.31` | `0x100288604` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028861c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[CBLHTTPResponse_initWithRouter:forConnection:]_block_invoke.31` | `0x10028861c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100288670`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[CBLHTTPResponse_initWithRouter:forConnection:]_block_invoke.31` | `0x100288670` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002891c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onFinished` | `0x1002891c8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028abdc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getQueryOptions` | `0x10028abdc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028abfc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getQueryOptions` | `0x10028abfc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028ac1c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getQueryOptions` | `0x10028ac1c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028b1f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseChangesMode` | `0x10028b1f8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028b218`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseChangesMode` | `0x10028b218` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028b238`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseChangesMode` | `0x10028b238` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028b8e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `route` | `0x10028b8e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028b8fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `route` | `0x10028b8fc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10028ba8c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `route` | `0x10028ba8c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002944cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `update:docID:body:deleting:allowConflict:createdRev:error:` | `0x1002944cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002970cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serverForURL:` | `0x1002970cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100297128`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serverForURL:` | `0x100297128` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100297140`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serverForURL:` | `0x100297140` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x100297338`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `handlesURL:` | `0x100297338` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002a3464`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getInterfaceAddress4:address6:fromDescription:port:` | `0x1002a3464` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002a347c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getInterfaceAddress4:address6:fromDescription:port:` | `0x1002a347c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ac6b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `lookupHost:port:error:` | `0x1002ac6b4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ac6cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `lookupHost:port:error:` | `0x1002ac6cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002af4cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `socketDidDisconnect:withError:` | `0x1002af4cc` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002b2dc8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x1002b2dc8` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002b89a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `stringValueForCrashReport:withTextFormat:` | `0x1002b89a0` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002b8ac0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `stringValueForCrashReport:withTextFormat:` | `0x1002b8ac0` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002b8d18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `stringValueForCrashReport:withTextFormat:` | `0x1002b8d18` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002b8ef8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `stringValueForCrashReport:withTextFormat:` | `0x1002b8ef8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002cbfc0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_paymentTransactionAPI:userParams:eventFrameSource:callback:` | `0x1002cbfc0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002cc058`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_paymentTransactionAPI:userParams:eventFrameSource:callback:` | `0x1002cc058` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002cc0a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_paymentTransactionAPI:userParams:eventFrameSource:callback:` | `0x1002cc0a4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ceea4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1002ceea4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ceebc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1002ceebc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ceed0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1002ceed0` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1002cf0e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadWatchDisableWatchConnectivity` | `0x1002cf0e0` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1002cf208`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadWatchDebug` | `0x1002cf208` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002d3398`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialTimestampWithApiKey:withStartUpTime:` | `0x1002d3398` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002d504c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setCookieWithType:value:` | `0x1002d504c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002d5424`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setCookies:` | `0x1002d5424` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002d5504`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setCookies:` | `0x1002d5504` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002d7a08`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `respondsToSelector:` | `0x1002d7a08` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002daf78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startWithVersion:withKillSwitchConfig:` | `0x1002daf78` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002db21c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isCurrentDate:betweenStart:andEnd:` | `0x1002db21c` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002db234`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isCurrentDate:betweenStart:andEnd:` | `0x1002db234` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002db470`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIfPerformKillOrNag:withCurrentDate:` | `0x1002db470` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002e25b0`
- **Type**: symbol

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002e2618`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compare:` | `0x1002e2618` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002e26bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `compare:` | `0x1002e26bc` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002e8bb8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[FlurryNetworkMonitor_onqueue_populateMetrics:]_block_invoke` | `0x1002e8bb8` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002e8c24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___48-[FlurryNetworkMonitor_onqueue_populateMetrics:]_block_invoke` | `0x1002e8c24` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002e9e70`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___97-[FConfigImpl_fetchConfigWithCompletion:withQueue:withEndpoint:withIncludePublisherSegmentation:]_block_invoke_3` | `0x1002e9e70` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1002eae78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___34-[FConfigImpl_unregisterObserver:]_block_invoke_2` | `0x1002eae78` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002ee5cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `notifyObserversOfActivationCompleteForConfigNamespace:` | `0x1002ee5cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002f5e60`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___137-[FConfigEngine_fetchedMergedConfigWithDefaultConfig:withLastFetchedConfig:withEndpoint:withCompletion:withIncludePublisherSegmentation:]_block_invoke_3` | `0x1002f5e60` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002f5e98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___137-[FConfigEngine_fetchedMergedConfigWithDefaultConfig:withLastFetchedConfig:withEndpoint:withCompletion:withIncludePublisherSegmentation:]_block_invoke_3` | `0x1002f5e98` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002f6780`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___98-[FConfigEngine_checkForBackgroundResponseWithDefaultConfig:withLastFetchedConfig:withCompletion:]_block_invoke_3` | `0x1002f6780` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002fa8e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:` | `0x1002fa8e0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002fa93c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:` | `0x1002fa93c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1002faac4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:` | `0x1002faac4` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1002fdd08`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003013a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x1003013a0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100301458`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x100301458` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10030148c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x10030148c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003014c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x1003014c4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100302a44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `allObjectsForNamespace:` | `0x100302a44` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100302bb4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createConfigItemWithKey:withValue:withLocalizedValues:withType:` | `0x100302bb4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100302c4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createConfigItemWithKey:withValue:withLocalizedValues:withType:` | `0x100302c4c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100308af4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_dataProviderDidUpdate:` | `0x100308af4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100308b10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_dataProviderDidUpdate:` | `0x100308b10` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10030934c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getCarrierInstance` | `0x10030934c` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10030a764`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_complete` | `0x10030a764` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10030ab90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_isRegistered:` | `0x10030ab90` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10030ad18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_removeObserver:` | `0x10030ad18` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003128cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1003128cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003128e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1003128e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003128f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIsFlurryUserInfo:` | `0x1003128f8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100319d64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isPushReceived` | `0x100319d64` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100319db8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isPushOpened` | `0x100319db8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10031aca4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `populateEndEventFields:` | `0x10031aca4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10031c238`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_doRecordFlurryTransaction:userParams:statusCallback:` | `0x10031c238` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003233d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `respondsToSelector:` | `0x1003233d8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003233f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `respondsToSelector:` | `0x1003233f0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100323ae8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryMsg:` | `0x100323ae8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100323afc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryMsg:` | `0x100323afc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100323b10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryMsg:` | `0x100323b10` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100325538`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___66-[FlurryDataSenderIndex_removeBlockInfoWithIdentifier:forDataKey:]_block_invoke` | `0x100325538` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100325570`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___66-[FlurryDataSenderIndex_removeBlockInfoWithIdentifier:forDataKey:]_block_invoke` | `0x100325570` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003257f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupForCurrentDataKey:` | `0x1003257f8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100325838`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupForCurrentDataKey:` | `0x100325838` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100326e4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isOpenFile:` | `0x100326e4c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10032bac8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseConfig:` | `0x10032bac8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10032bafc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseConfig:` | `0x10032bafc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10032bb68`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseConfig:` | `0x10032bb68` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10032d1a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `encoded2TransactionDictionary` | `0x10032d1a4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003310b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryUserInfo:` | `0x1003310b4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003310c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryUserInfo:` | `0x1003310c8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100331214`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `didReceiveUserInfo:` | `0x100331214` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100331240`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `didReceiveUserInfo:` | `0x100331240` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100331264`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `didReceiveUserInfo:` | `0x100331264` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100332f48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `shouldDropMessage:` | `0x100332f48` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100333a4c`
- **Type**: symbol

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100333abc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isEqual:` | `0x100333abc` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10033628c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_dataProviderDidUpdate:` | `0x10033628c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033b5e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setGender:` | `0x10033b5e4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033b60c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setGender:` | `0x10033b60c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033bc7c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `refreshFlushStatusForMessage:prependingMessages:appendingMessages:` | `0x10033bc7c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033c11c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `refreshFlushStatusForMessage:prependingMessages:appendingMessages:` | `0x10033c11c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033c1f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `refreshFlushStatusForMessage:prependingMessages:appendingMessages:` | `0x10033c1f4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033c3fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `refreshFlushStatusForMessage:prependingMessages:appendingMessages:` | `0x10033c3fc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033c7bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x10033c7bc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10033c808`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x10033c808` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003417b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isFlurryReachabilityEqual:` | `0x1003417b4` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1003430bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_sendDataIfPossible` | `0x1003430bc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100344df8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_finishTransferWithFileName:` | `0x100344df8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10034c294`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `string2Base64UTF8String:` | `0x10034c294` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10034c908`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `base64EncodedString2UTF8String:` | `0x10034c908` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10034cf38`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___68-[FlurryNetworkReachabilityDataProvider_isNetworkLikelyNotReachable]_block_invoke` | `0x10034cf38` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10034f848`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `nextHitNumberForTrackingId:clientId:` | `0x10034f848` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100353048`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `batchByTimeGap:maxHits:` | `0x100353048` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x1003530cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `batchByTimeGap:maxHits:` | `0x1003530cc` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100353258`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `batchBySessionSplit:maxHits:` | `0x100353258` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10035326c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `batchBySessionSplit:maxHits:` | `0x10035326c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003534f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `hitsForDispatch` | `0x1003534f0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100353a68`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___40-[GAIBatchingDispatcher_hitsForDispatch]_block_invoke` | `0x100353a68` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100353ce0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `nextPendingHits` | `0x100353ce0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100354968`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dispatchWithCompletionHandler:` | `0x100354968` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100355590`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIAdCampaignAttributionWithHitParameters:` | `0x100355590` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x10036038c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `symbolFromStackFrame:` | `0x10036038c` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003603c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `symbolFromStackFrame:` | `0x1003603c4` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1003619c0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `encodeParameters:` | `0x1003619c0` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100365b34`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_send:` | `0x100365b34` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100365b50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_send:` | `0x100365b50` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100365c74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_send:` | `0x100365c74` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100365c90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_send:` | `0x100365c90` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x100366d5c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `idfa` | `0x100366d5c` |

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x10036f9c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$caseInsensitiveCompare:` | `0x10036f9c8` |

### `compare:`

- **Library**: Foundation
- **Address**: `0x10036fd08`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$compare:` | `0x10036fd08` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1003739e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$isEqual:` | `0x1003739e8` |

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x100373a28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$isEqualToString:` | `0x100373a28` |

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100456e28`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10045d830`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10046db08`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004711d0`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100472b78`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100474f70`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x10047bd50`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10047c9b0`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10047d918`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x10047df58`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004820d0`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100483680`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100484ff8`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100486578`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x100486620`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x1004867c8`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100487108`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x100487578`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004999e0`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x1004a0c68`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x1004a7708`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004b67d8`
- **Type**: objc_selector

### `caseInsensitiveCompare:`

- **Library**: Foundation
- **Address**: `0x1004cd0c8`
- **Type**: objc_selector

### `compare:`

- **Library**: Foundation
- **Address**: `0x1004cd198`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004ce0d0`
- **Type**: objc_selector

### `isEqualToString:`

- **Library**: Foundation
- **Address**: `0x1004ce0e0`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004d6eb0`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004ea348`
- **Type**: objc_selector

### `isEqual:`

- **Library**: Foundation
- **Address**: `0x1004ea580`
- **Type**: objc_selector

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
