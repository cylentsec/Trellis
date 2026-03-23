# Trellis Deeplinks Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:59:24
**Category**: Deep link and URL scheme handling security
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 19 |
| Total Findings | 10 |
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 0 |
| Info | 6 |

---

## Security Findings

### 🟡 MEDIUM (4)

#### Deep Link Entry Point

**Description**: Deep link handler found: application:openURL:options:

**Location**: `0x100152f94` (Offset: `0x152f94`)

**Function**: `application:openURL:options:`

**Evidence**:
- handler: `application:openURL:options:`
- modern_api: `True`
- dangerous_destinations: `evaluateJavaScript:, evaluateJavaScript:completionHandler:, loadData:MIMEType:textEncodingName:baseURL:, loadFileURL:, loadFileURL:allowingReadAccessToURL:...`

**Impact**: Deep link handlers receive untrusted URL input from other apps. If URL data flows into WebView loading, JavaScript execution, or file operations, it can lead to XSS, local file access, or code injection.

**Recommendation**: Validate URL scheme, host, and all parameters. Never pass URL data directly to loadHTMLString, evaluateJavaScript, or file I/O functions.

---

#### External URL Opening

**Description**: App opens external URLs

**Location**: `0x100171eb8` (Offset: `0x171eb8`)

**Function**: `openURL:options:completionHandler:`

**Evidence**:
- function: `openURL:options:completionHandler:`
- can_launch_apps: `True`

**Impact**: Can launch other apps or open web content.

**Recommendation**: Validate URL schemes before opening. Consider user confirmation.

---

#### External URL Opening

**Description**: App opens external URLs

**Location**: `0x1002dbcf0` (Offset: `0x2dbcf0`)

**Function**: `openURL:options:completionHandler:`

**Evidence**:
- function: `openURL:options:completionHandler:`
- can_launch_apps: `True`

**Impact**: Can launch other apps or open web content.

**Recommendation**: Validate URL schemes before opening. Consider user confirmation.

---

#### External URL Opening

**Description**: App opens external URLs

**Location**: `0x100303a74` (Offset: `0x303a74`)

**Function**: `openURL:options:completionHandler:`

**Evidence**:
- function: `openURL:options:completionHandler:`
- can_launch_apps: `True`

**Impact**: Can launch other apps or open web content.

**Recommendation**: Validate URL schemes before opening. Consider user confirmation.

---

### ⚪ INFO (6)

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x1001413b0` (Offset: `0x1413b0`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x100142634` (Offset: `0x142634`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x10014302c` (Offset: `0x14302c`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x100144224` (Offset: `0x144224`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x100171d58` (Offset: `0x171d58`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

#### URL Scheme Check

**Description**: App checks if URL schemes are available

**Location**: `0x10036f988` (Offset: `0x36f988`)

**Function**: `canOpenURL:`

**Evidence**:
- function: `canOpenURL:`
- purpose: `scheme_detection`

**Impact**: Can be used for app detection or jailbreak checks.

**Recommendation**: Ensure LSApplicationQueriesSchemes is properly configured.

---

## Functions Analyzed

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x1001413b0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$jailbreakTest4Tapped` | `0x1001413b0` |
- **Findings**: 1 issue(s)

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x100142634`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isJailbroken` | `0x100142634` |
- **Findings**: 1 issue(s)

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x10014302c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `jailbreakTest3` | `0x10014302c` |
- **Findings**: 1 issue(s)

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x100144224`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$jailbreakTest5Tapped` | `0x100144224` |
- **Findings**: 1 issue(s)

### `application:openURL:options:`

- **Library**: UIKit.framework
- **Address**: `0x100152f94`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `application:openURL:options:` | `0x100152f94` |
- **Findings**: 1 issue(s)

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x100171d58`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadWebView` | `0x100171d58` |
- **Findings**: 1 issue(s)

### `openURL:options:completionHandler:`

- **Library**: UIKit.framework
- **Address**: `0x100171eb8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadWebView` | `0x100171eb8` |
- **Findings**: 1 issue(s)

### `openURL:options:completionHandler:`

- **Library**: UIKit.framework
- **Address**: `0x1002dbcf0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___121-[FConfigKillSwitch_showAlertWithType:withDismissButtonText:withTitleText:withMessageText:withPrimaryButtonText:withURL:]_block_invoke_2` | `0x1002dbcf0` |
- **Findings**: 1 issue(s)

### `openURL:options:completionHandler:`

- **Library**: UIKit.framework
- **Address**: `0x100303a74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___58-[FlurryGDPRUtil_requestPrivacyLinkWithCompletionHandler:]_block_invoke_2` | `0x100303a74` |
- **Findings**: 1 issue(s)

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x10036f988`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$canOpenURL:` | `0x10036f988` |
- **Findings**: 1 issue(s)

### `openURL:options:completionHandler:`

- **Library**: UIKit.framework
- **Address**: `0x1004c3fa8`
- **Type**: objc_selector

### `canOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x1004cd0b8`
- **Type**: objc_selector

### `application:openURL:options:`

- **Library**: UIKit.framework
- **Address**: `0x1004d89e8`
- **Type**: objc_selector

### `application:handleOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x1004d8c38`
- **Type**: objc_selector

### `application:handleOpenURL:`

- **Library**: UIKit.framework
- **Address**: `0x1004d8c50`
- **Type**: objc_selector

### `application:openURL:options:`

- **Library**: UIKit.framework
- **Address**: `0x1004d8c98`
- **Type**: objc_selector

### `application:openURL:options:`

- **Library**: UIKit.framework
- **Address**: `0x1004d8cb0`
- **Type**: objc_selector

### `application:continueUserActivity:restorationHandler:`

- **Library**: UIKit.framework
- **Address**: `0x1004d9118`
- **Type**: objc_selector

### `application:continueUserActivity:restorationHandler:`

- **Library**: UIKit.framework
- **Address**: `0x1004d9130`
- **Type**: objc_selector

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
