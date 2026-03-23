# Trellis Logging Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:59:43
**Category**: Sensitive data logging detection (NSLog, os_log, etc.)
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 4 |
| Total Findings | 306 |
| Critical | 0 |
| High | 1 |
| Medium | 14 |
| Low | 0 |
| Info | 291 |

---

## Security Findings

### 🟠 HIGH (1)

#### Sensitive Data in Log

**Description**: Potential sensitive data 'iv' found in log message

**Location**: `0x1002b3bcc` (Offset: `0x2b3bcc`)

**Function**: `asl_log`

**Evidence**:
- keyword: `iv`
- context: `[PLCrashReporter] Failure occured deleting live crash report: %s`

**Impact**: 'iv' related data may be leaked to device logs

**Recommendation**: Remove sensitive data from logs or use privacy modifiers

---

### 🟡 MEDIUM (14)

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b3b10` (Offset: `0x2b3b10`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b3bcc` (Offset: `0x2b3bcc`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002cb0c4` (Offset: `0x2cb0c4`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002cb708` (Offset: `0x2cb708`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002cad70` (Offset: `0x2cad70`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002cadc8` (Offset: `0x2cadc8`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002c2cb8` (Offset: `0x2c2cb8`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002cb03c` (Offset: `0x2cb03c`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b9418` (Offset: `0x2b9418`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b9598` (Offset: `0x2b9598`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b41bc` (Offset: `0x2b41bc`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b4260` (Offset: `0x2b4260`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1000a4368` (Offset: `0xa4368`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

#### Deprecated ASL Logging

**Description**: asl_log call detected - deprecated API

**Location**: `0x1002b2e74` (Offset: `0x2b2e74`)

**Function**: `asl_log`

**Evidence**:
- api: `asl_log`

**Impact**: ASL is deprecated; logs may have inconsistent behavior

**Recommendation**: Migrate to os_log unified logging

---

### ⚪ INFO (291)

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1001b907c` (Offset: `0x1b907c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f38a4` (Offset: `0x2f38a4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f38ec` (Offset: `0x2f38ec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100210fa0` (Offset: `0x210fa0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100211004` (Offset: `0x211004`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dfad8` (Offset: `0x2dfad8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e3b24` (Offset: `0x2e3b24`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032b928` (Offset: `0x32b928`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10012f9b4` (Offset: `0x12f9b4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031b9d8` (Offset: `0x31b9d8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033fb94` (Offset: `0x33fb94`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b9fc` (Offset: `0x34b9fc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e7ae0` (Offset: `0x2e7ae0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f3cac` (Offset: `0x2f3cac`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031bb94` (Offset: `0x31bb94`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030bbe4` (Offset: `0x30bbe4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030bc28` (Offset: `0x30bc28`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030bccc` (Offset: `0x30bccc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b324` (Offset: `0x30b324`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b4d8` (Offset: `0x30b4d8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b550` (Offset: `0x30b550`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032fe0c` (Offset: `0x32fe0c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347c6c` (Offset: `0x347c6c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347c8c` (Offset: `0x347c8c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347ce8` (Offset: `0x347ce8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347d4c` (Offset: `0x347d4c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347d6c` (Offset: `0x347d6c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347dc0` (Offset: `0x347dc0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347e08` (Offset: `0x347e08`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347e24` (Offset: `0x347e24`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347e48` (Offset: `0x347e48`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dfe18` (Offset: `0x2dfe18`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100323ddc` (Offset: `0x323ddc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100263d3c` (Offset: `0x263d3c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100263e58` (Offset: `0x263e58`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100263eb0` (Offset: `0x263eb0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264038` (Offset: `0x264038`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264048` (Offset: `0x264048`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002efda8` (Offset: `0x2efda8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030be3c` (Offset: `0x30be3c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10035bdb8` (Offset: `0x35bdb8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031be94` (Offset: `0x31be94`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10035be14` (Offset: `0x35be14`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10035be70` (Offset: `0x35be70`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002cfef8` (Offset: `0x2cfef8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100330058` (Offset: `0x330058`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003300e0` (Offset: `0x3300e0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10035bec8` (Offset: `0x35bec8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347f9c` (Offset: `0x347f9c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d02dc` (Offset: `0x2d02dc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030fffc` (Offset: `0x30fffc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e3ff8` (Offset: `0x2e3ff8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033412c` (Offset: `0x33412c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032f188` (Offset: `0x32f188`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100327288` (Offset: `0x327288`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003272d0` (Offset: `0x3272d0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b218` (Offset: `0x30b218`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b270` (Offset: `0x30b270`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033f39c` (Offset: `0x33f39c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030f2bc` (Offset: `0x30f2bc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030f2d8` (Offset: `0x30f2d8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030f454` (Offset: `0x30f454`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030f498` (Offset: `0x30f498`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100323340` (Offset: `0x323340`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d34f4` (Offset: `0x2d34f4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d3574` (Offset: `0x2d3574`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b3fc` (Offset: `0x34b3fc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032f38c` (Offset: `0x32f38c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003074e8` (Offset: `0x3074e8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031f4c8` (Offset: `0x31f4c8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100323474` (Offset: `0x323474`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100307698` (Offset: `0x307698`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d37ec` (Offset: `0x2d37ec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f3738` (Offset: `0x2f3738`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10026371c` (Offset: `0x26371c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002cf9f4` (Offset: `0x2cf9f4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031b818` (Offset: `0x31b818`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b940` (Offset: `0x34b940`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030f828` (Offset: `0x30f828`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ceb58` (Offset: `0x2ceb58`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10019e940` (Offset: `0x19e940`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f2a84` (Offset: `0x2f2a84`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100312aac` (Offset: `0x312aac`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033aa60` (Offset: `0x33aa60`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356b58` (Offset: `0x356b58`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356bec` (Offset: `0x356bec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356c08` (Offset: `0x356c08`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100312be4` (Offset: `0x312be4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030adbc` (Offset: `0x30adbc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033ad24` (Offset: `0x33ad24`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100262d0c` (Offset: `0x262d0c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f2e38` (Offset: `0x2f2e38`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356ce4` (Offset: `0x356ce4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356d70` (Offset: `0x356d70`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100356d94` (Offset: `0x356d94`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033ee4c` (Offset: `0x33ee4c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003070a8` (Offset: `0x3070a8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100262e38` (Offset: `0x262e38`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100262e7c` (Offset: `0x262e7c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033ae94` (Offset: `0x33ae94`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002eefb4` (Offset: `0x2eefb4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100312edc` (Offset: `0x312edc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100313124` (Offset: `0x313124`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1001f2ea4` (Offset: `0x1f2ea4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1001f3290` (Offset: `0x1f3290`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033f084` (Offset: `0x33f084`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032704c` (Offset: `0x32704c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100327094` (Offset: `0x327094`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347a04` (Offset: `0x347a04`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347a88` (Offset: `0x347a88`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347b0c` (Offset: `0x347b0c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100347b90` (Offset: `0x347b90`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b074` (Offset: `0x34b074`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b15c` (Offset: `0x34b15c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034b1b8` (Offset: `0x34b1b8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030e158` (Offset: `0x30e158`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031a404` (Offset: `0x31a404`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033e1ec` (Offset: `0x33e1ec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a32c` (Offset: `0x30a32c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033a444` (Offset: `0x33a444`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003425d4` (Offset: `0x3425d4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d6538` (Offset: `0x2d6538`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d65f0` (Offset: `0x2d65f0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032e518` (Offset: `0x32e518`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003265a0` (Offset: `0x3265a0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100316540` (Offset: `0x316540`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033a610` (Offset: `0x33a610`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100306a60` (Offset: `0x306a60`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033e794` (Offset: `0x33e794`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003166c4` (Offset: `0x3166c4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032e704` (Offset: `0x32e704`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003267b0` (Offset: `0x3267b0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031aaa0` (Offset: `0x31aaa0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003428f0` (Offset: `0x3428f0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033a860` (Offset: `0x33a860`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034596c` (Offset: `0x34596c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd830` (Offset: `0x2dd830`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd9a8` (Offset: `0x2dd9a8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd9ec` (Offset: `0x2dd9ec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dda74` (Offset: `0x2dda74`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ddab8` (Offset: `0x2ddab8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ddae8` (Offset: `0x2ddae8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100329a8c` (Offset: `0x329a8c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003219f4` (Offset: `0x3219f4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100335d14` (Offset: `0x335d14`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100309b8c` (Offset: `0x309b8c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033db84` (Offset: `0x33db84`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ddc0c` (Offset: `0x2ddc0c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ddc90` (Offset: `0x2ddc90`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100329c78` (Offset: `0x329c78`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100321d04` (Offset: `0x321d04`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100321dec` (Offset: `0x321dec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030dc58` (Offset: `0x30dc58`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033dcd4` (Offset: `0x33dcd4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100311e90` (Offset: `0x311e90`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100339dd0` (Offset: `0x339dd0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100339e18` (Offset: `0x339e18`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032226c` (Offset: `0x32226c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031a02c` (Offset: `0x31a02c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100339ee8` (Offset: `0x339ee8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100339f30` (Offset: `0x339f30`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100335ff4` (Offset: `0x335ff4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a018` (Offset: `0x30a018`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a10c` (Offset: `0x30a10c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032113c` (Offset: `0x32113c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100321258` (Offset: `0x321258`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003112a0` (Offset: `0x3112a0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003491e4` (Offset: `0x3491e4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034d314` (Offset: `0x34d314`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003191d8` (Offset: `0x3191d8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100321400` (Offset: `0x321400`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032151c` (Offset: `0x32151c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003113ec` (Offset: `0x3113ec`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030d560` (Offset: `0x30d560`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030d618` (Offset: `0x30d618`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031df38` (Offset: `0x31df38`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003195d0` (Offset: `0x3195d0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100265614` (Offset: `0x265614`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100265698` (Offset: `0x265698`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100311604` (Offset: `0x311604`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100311678` (Offset: `0x311678`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd6a0` (Offset: `0x2dd6a0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003358a4` (Offset: `0x3358a4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003457d0` (Offset: `0x3457d0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd758` (Offset: `0x2dd758`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002fd7e8` (Offset: `0x2fd7e8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002657e8` (Offset: `0x2657e8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033d8ac` (Offset: `0x33d8ac`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033d8f4` (Offset: `0x33d8f4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033d9c0` (Offset: `0x33d9c0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033da10` (Offset: `0x33da10`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033dad0` (Offset: `0x33dad0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd7d8` (Offset: `0x2dd7d8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348980` (Offset: `0x348980`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003489c0` (Offset: `0x3489c0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10013496c` (Offset: `0x13496c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002cca80` (Offset: `0x2cca80`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100334aa8` (Offset: `0x334aa8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100334afc` (Offset: `0x334afc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034ca1c` (Offset: `0x34ca1c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348b38` (Offset: `0x348b38`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348b78` (Offset: `0x348b78`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034cac0` (Offset: `0x34cac0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031cbcc` (Offset: `0x31cbcc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030cf04` (Offset: `0x30cf04`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030cf44` (Offset: `0x30cf44`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100334c88` (Offset: `0x334c88`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310c54` (Offset: `0x310c54`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002cccd4` (Offset: `0x2cccd4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031cde8` (Offset: `0x31cde8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002fcf08` (Offset: `0x2fcf08`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dd2d4` (Offset: `0x2dd2d4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310e28` (Offset: `0x310e28`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d0f20` (Offset: `0x2d0f20`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310ebc` (Offset: `0x310ebc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100349008` (Offset: `0x349008`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1000f0f20` (Offset: `0xf0f20`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1000f0f48` (Offset: `0xf0f48`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1000f116c` (Offset: `0xf116c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003110bc` (Offset: `0x3110bc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d1094` (Offset: `0x2d1094`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002fd188` (Offset: `0x2fd188`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d411c` (Offset: `0x2d411c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310100` (Offset: `0x310100`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100300190` (Offset: `0x300190`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100330254` (Offset: `0x330254`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031022c` (Offset: `0x31022c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034824c` (Offset: `0x34824c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003482c8` (Offset: `0x3482c8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348368` (Offset: `0x348368`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003483a4` (Offset: `0x3483a4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031c2bc` (Offset: `0x31c2bc`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100211a90` (Offset: `0x211a90`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100334258` (Offset: `0x334258`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d42c4` (Offset: `0x2d42c4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264264` (Offset: `0x264264`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264340` (Offset: `0x264340`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264350` (Offset: `0x264350`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002644d4` (Offset: `0x2644d4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100264584` (Offset: `0x264584`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10026463c` (Offset: `0x26463c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10026464c` (Offset: `0x26464c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1001bc33c` (Offset: `0x1bc33c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310354` (Offset: `0x310354`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002cc3e4` (Offset: `0x2cc3e4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031c4c4` (Offset: `0x31c4c4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310448` (Offset: `0x310448`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100134598` (Offset: `0x134598`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100134650` (Offset: `0x134650`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e4668` (Offset: `0x2e4668`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100330764` (Offset: `0x330764`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310544` (Offset: `0x310544`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003485f4` (Offset: `0x3485f4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348670` (Offset: `0x348670`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100348710` (Offset: `0x348710`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034874c` (Offset: `0x34874c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002d0cac` (Offset: `0x2d0cac`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f45f0` (Offset: `0x2f45f0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003406c4` (Offset: `0x3406c4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031c6c0` (Offset: `0x31c6c0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100310750` (Offset: `0x310750`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030469c` (Offset: `0x30469c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002dcbb8` (Offset: `0x2dcbb8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003287a0` (Offset: `0x3287a0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100304814` (Offset: `0x304814`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10013485c` (Offset: `0x13485c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003109ac` (Offset: `0x3109ac`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100334920` (Offset: `0x334920`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1003408c8` (Offset: `0x3408c8`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e4a14` (Offset: `0x2e4a14`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10020cf7c` (Offset: `0x20cf7c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030b0a0` (Offset: `0x30b0a0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100262d64` (Offset: `0x262d64`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100304404` (Offset: `0x304404`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a1a4` (Offset: `0x30a1a4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a49c` (Offset: `0x30a49c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a570` (Offset: `0x30a570`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a618` (Offset: `0x30a618`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10030a6c0` (Offset: `0x30a6c0`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031f520` (Offset: `0x31f520`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100320f6c` (Offset: `0x320f6c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032a9e4` (Offset: `0x32a9e4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10033a924` (Offset: `0x33a924`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10034d528` (Offset: `0x34d528`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10019ed7c` (Offset: `0x19ed7c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002ce904` (Offset: `0x2ce904`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002e3448` (Offset: `0x2e3448`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x1002f31b4` (Offset: `0x2f31b4`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10031c784` (Offset: `0x31c784`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x10032866c` (Offset: `0x32866c`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

#### NSLog in Production

**Description**: NSLog call detected - logs are visible in device console

**Location**: `0x100346d70` (Offset: `0x346d70`)

**Function**: `NSLog`

**Evidence**:
- api: `NSLog`

**Impact**: NSLog output can be read by any app or attacker with device access

**Recommendation**: Use os_log with privacy modifiers or remove in production builds

---

## Functions Analyzed

### `NSLog`

- **Library**: Foundation.framework
- **Address**: `0xa5`
- **Type**: import

### `asl_log`

- **Library**: libsystem_asl.dylib
- **Address**: `0x1bf`
- **Type**: import

### `NSLog`

- **Library**: Foundation.framework
- **Address**: `0x10036a184`
- **Type**: symbol
- **Call Sites**: 291

| Caller | Address |
|--------|--------|
| `__Logv` | `0x1001b907c` |
| `requestSuccessComplete:withResponse:` | `0x1002f38a4` |
| `requestSuccessComplete:withResponse:` | `0x1002f38ec` |
| `__AssertFailed` | `0x100210fa0` |
| `__AssertFailed` | `0x100211004` |
| `dictionaryRepresentation` | `0x1002dfad8` |
| `build` | `0x1002e3b24` |
| `onqueue_fetchAndSendTimeZone` | `0x10032b928` |
| `logsDirectory` | `0x10012f9b4` |
| `recordTransaction:statusCallback:` | `0x10031b9d8` |
| `setData:` | `0x10033fb94` |
| `lastBootTime` | `0x10034b9fc` |
| `dictionaryRepresentation` | `0x1002e7ae0` |
| `retransmitNotSentBlocks` | `0x1002f3cac` |
| `recordFlurryTransaction:userParams:statusCallback:` | `0x10031bb94` |
| `openContextFile` | `0x10030bbe4` |
| `openContextFile` | `0x10030bc28` |
| `_edit_context` | `0x10030bccc` |
| `_make_readonly` | `0x10030b324` |
| `_acquire_lock` | `0x10030b4d8` |

*...and 271 more call sites*
- **Findings**: 291 issue(s)

### `asl_log`

- **Library**: libsystem_asl.dylib
- **Address**: `0x10036aebc`
- **Type**: symbol
- **Call Sites**: 14

| Caller | Address |
|--------|--------|
| `generateLiveReportWithThread:error:` | `0x1002b3b10` |
| `generateLiveReportWithThread:error:` | `0x1002b3bcc` |
| `dealloc` | `0x1002cb0c4` |
| `initWithAsyncSafeRepresentation:` | `0x1002cb708` |
| `init` | `0x1002cad70` |
| `init` | `0x1002cadc8` |
| `dealloc` | `0x1002c2cb8` |
| `initWithServerPort:mask:behavior:flavor:` | `0x1002cb03c` |
| `formatStackFrame:frameIndex:report:lp64:` | `0x1002b9418` |
| `formatStackFrame:frameIndex:report:lp64:` | `0x1002b9598` |
| `initWithBundle:configuration:` | `0x1002b41bc` |
| `initWithBundle:configuration:` | `0x1002b4260` |
| `logMessage:` | `0x1000a4368` |
| `_image_add_callback` | `0x1002b2e74` |
- **Findings**: 15 issue(s)

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
