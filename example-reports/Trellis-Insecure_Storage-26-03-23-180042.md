# Trellis Insecure_Storage Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 18:00:42
**Category**: Insecure data storage patterns (NSUserDefaults, plist files, etc.)
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 436 |
| Total Findings | 143 |
| Critical | 0 |
| High | 45 |
| Medium | 4 |
| Low | 0 |
| Info | 94 |

---

## Security Findings

### 🟠 HIGH (45)

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006b94c` (Offset: `0x6b94c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10002bb34` (Offset: `0x2bb34`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006bab8` (Offset: `0x6bab8`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006bbe8` (Offset: `0x6bbe8`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006bcf8` (Offset: `0x6bcf8`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000bbeec` (Offset: `0xbbeec`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000bc10c` (Offset: `0xbc10c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000ac074` (Offset: `0xac074`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100123204` (Offset: `0x123204`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10012334c` (Offset: `0x12334c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10009a914` (Offset: `0x9a914`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100082e18` (Offset: `0x82e18`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100083020` (Offset: `0x83020`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100083328` (Offset: `0x83328`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100083630` (Offset: `0x83630`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100062db8` (Offset: `0x62db8`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100036fb0` (Offset: `0x36fb0`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10011e38c` (Offset: `0x11e38c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000698e0` (Offset: `0x698e0`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000699f4` (Offset: `0x699f4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100069b10` (Offset: `0x69b10`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100069c14` (Offset: `0x69c14`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100069d70` (Offset: `0x69d70`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100069edc` (Offset: `0x69edc`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x100069ff4` (Offset: `0x69ff4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006a10c` (Offset: `0x6a10c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000412ac` (Offset: `0x412ac`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000f140c` (Offset: `0xf140c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10009d4a4` (Offset: `0x9d4a4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10004158c` (Offset: `0x4158c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000416ec` (Offset: `0x416ec`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10004184c` (Offset: `0x4184c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000419ac` (Offset: `0x419ac`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10009da00` (Offset: `0x9da00`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000ac58c` (Offset: `0xac58c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000ac830` (Offset: `0xac830`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000d8be4` (Offset: `0xd8be4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000bc384` (Offset: `0xbc384`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000bc4e4` (Offset: `0xbc4e4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006c2c4` (Offset: `0x6c2c4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x10006c40c` (Offset: `0x6c40c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000ee698` (Offset: `0xee698`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000ee7b4` (Offset: `0xee7b4`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000eee30` (Offset: `0xeee30`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

#### SQL Injection Risk

**Description**: Using sqlite3_exec with direct SQL execution

**Location**: `0x1000eef4c` (Offset: `0xeef4c`)

**Function**: `sqlite3_exec`

**Impact**: High risk of SQL injection if queries use string concatenation

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries

---

### 🟡 MEDIUM (4)

#### Insecure Archiving

**Description**: Using deprecated archiver without secure coding

**Location**: `0x1002f4bc0` (Offset: `0x2f4bc0`)

**Function**: `archivedDataWithRootObject:`

**Impact**: No protection against deserialization attacks

**Recommendation**: Use archivedDataWithRootObject:requiringSecureCoding:error: with secure coding enabled

---

#### Insecure Archiving

**Description**: Using deprecated archiver without secure coding

**Location**: `0x1002f4cac` (Offset: `0x2f4cac`)

**Function**: `archivedDataWithRootObject:`

**Impact**: No protection against deserialization attacks

**Recommendation**: Use archivedDataWithRootObject:requiringSecureCoding:error: with secure coding enabled

---

#### Insecure Archiving

**Description**: Using deprecated archiver without secure coding

**Location**: `0x100348f30` (Offset: `0x348f30`)

**Function**: `archivedDataWithRootObject:`

**Impact**: No protection against deserialization attacks

**Recommendation**: Use archivedDataWithRootObject:requiringSecureCoding:error: with secure coding enabled

---

#### Insecure Archiving

**Description**: Using deprecated archiver without secure coding

**Location**: `0x10036f5a8` (Offset: `0x36f5a8`)

**Function**: `archivedDataWithRootObject:`

**Impact**: No protection against deserialization attacks

**Recommendation**: Use archivedDataWithRootObject:requiringSecureCoding:error: with secure coding enabled

---

### ⚪ INFO (94)

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100175438` (Offset: `0x175438`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100180714` (Offset: `0x180714`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10018496c` (Offset: `0x18496c`)

**Function**: `setBool:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1001984c4` (Offset: `0x1984c4`)

**Function**: `setBool:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1001b1058` (Offset: `0x1b1058`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1001ea758` (Offset: `0x1ea758`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100206a48` (Offset: `0x206a48`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10020b554` (Offset: `0x20b554`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10020b6a4` (Offset: `0x20b6a4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100212fa8` (Offset: `0x212fa8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226730` (Offset: `0x226730`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226a94` (Offset: `0x226a94`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226ac8` (Offset: `0x226ac8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226af4` (Offset: `0x226af4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226b3c` (Offset: `0x226b3c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100226e24` (Offset: `0x226e24`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100251eac` (Offset: `0x251eac`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002520a8` (Offset: `0x2520a8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002636b0` (Offset: `0x2636b0`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10027b62c` (Offset: `0x27b62c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10027b6f8` (Offset: `0x27b6f8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10027b72c` (Offset: `0x27b72c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002bee88` (Offset: `0x2bee88`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002cf850` (Offset: `0x2cf850`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d060c` (Offset: `0x2d060c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0a38` (Offset: `0x2d0a38`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0af4` (Offset: `0x2d0af4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0b24` (Offset: `0x2d0b24`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0c04` (Offset: `0x2d0c04`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0c50` (Offset: `0x2d0c50`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0c74` (Offset: `0x2d0c74`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d0c94` (Offset: `0x2d0c94`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002d152c` (Offset: `0x2d152c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002e8aa4` (Offset: `0x2e8aa4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f491c` (Offset: `0x2f491c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f4950` (Offset: `0x2f4950`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f49ac` (Offset: `0x2f49ac`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f4a40` (Offset: `0x2f4a40`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f4f74` (Offset: `0x2f4f74`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f50a4` (Offset: `0x2f50a4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002f51c4` (Offset: `0x2f51c4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002fa668` (Offset: `0x2fa668`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1002fa790` (Offset: `0x2fa790`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003016ec` (Offset: `0x3016ec`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100301968` (Offset: `0x301968`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100301a18` (Offset: `0x301a18`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100301d78` (Offset: `0x301d78`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100301ee0` (Offset: `0x301ee0`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100302340` (Offset: `0x302340`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100302390` (Offset: `0x302390`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100302570` (Offset: `0x302570`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003031f4` (Offset: `0x3031f4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10030dd68` (Offset: `0x30dd68`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100315a18` (Offset: `0x315a18`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100315fc4` (Offset: `0x315fc4`)

**Function**: `setInteger:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100318a48` (Offset: `0x318a48`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100318ae8` (Offset: `0x318ae8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100318bb0` (Offset: `0x318bb0`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100318c34` (Offset: `0x318c34`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100322838` (Offset: `0x322838`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10032ec24` (Offset: `0x32ec24`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10032ed98` (Offset: `0x32ed98`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10033039c` (Offset: `0x33039c`)

**Function**: `setInteger:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003306a8` (Offset: `0x3306a8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003306c8` (Offset: `0x3306c8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### File Write

**Description**: Writing plist file to: 16552

**Location**: `0x100330f4c` (Offset: `0x330f4c`)

**Function**: `writeToFile:atomically:`

**Evidence**:
- path: `16552`

**Impact**: Plist files are unencrypted XML/binary format

**Recommendation**: Consider encryption for sensitive data

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003374e4` (Offset: `0x3374e4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100337720` (Offset: `0x337720`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100337858` (Offset: `0x337858`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10033850c` (Offset: `0x33850c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034adbc` (Offset: `0x34adbc`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034af88` (Offset: `0x34af88`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034c3f8` (Offset: `0x34c3f8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034c53c` (Offset: `0x34c53c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034c6f8` (Offset: `0x34c6f8`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034c800` (Offset: `0x34c800`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10034e28c` (Offset: `0x34e28c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100355c9c` (Offset: `0x355c9c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035c258` (Offset: `0x35c258`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035c3dc` (Offset: `0x35c3dc`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035c478` (Offset: `0x35c478`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035cbc4` (Offset: `0x35cbc4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035db64` (Offset: `0x35db64`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035f13c` (Offset: `0x35f13c`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035f254` (Offset: `0x35f254`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035f7d4` (Offset: `0x35f7d4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035f984` (Offset: `0x35f984`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035f9f0` (Offset: `0x35f9f0`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035fb98` (Offset: `0x35fb98`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035fcb0` (Offset: `0x35fcb0`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x10035ff74` (Offset: `0x35ff74`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003601d4` (Offset: `0x3601d4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x1003667a4` (Offset: `0x3667a4`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

#### UserDefaults Storage

**Description**: Storing data in NSUserDefaults (key unknown)

**Location**: `0x100377308` (Offset: `0x377308`)

**Function**: `setObject:forKey:`

**Impact**: NSUserDefaults is not suitable for sensitive data

**Recommendation**: Verify no sensitive data is stored

---

## Functions Analyzed

### `sqlite3_prepare_v2`

- **Library**: libsqlite3.dylib
- **Address**: `0x39`
- **Type**: import

### `sqlite3_exec`

- **Library**: libsqlite3.dylib
- **Address**: `0x55`
- **Type**: import

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1000350f4`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1000355ac`
- **Type**: symbol

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1000f09cc`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1000f0ac0`
- **Type**: symbol

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x100113c80`
- **Type**: symbol

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10011c098`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10011cad0`
- **Type**: symbol

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100134da0`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100134e6c`
- **Type**: symbol

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1001350f8`
- **Type**: symbol

### `initWithContentsOfFile:`

- **Library**: Foundation
- **Address**: `0x10013cb8c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$init` | `0x10013cb8c` |

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x100147f94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$saveInPlistFileTapped` | `0x100147f94` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100175438`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$saveInKeychainTapped` | `0x100175438` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100180714`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `$saveInUserDefaultsTapped` | `0x100180714` |
- **Findings**: 1 issue(s)

### `setBool:forKey:`

- **Library**: Foundation
- **Address**: `0x10018496c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `textFieldShouldReturn` | `0x10018496c` |
- **Findings**: 1 issue(s)

### `setBool:forKey:`

- **Library**: Foundation
- **Address**: `0x1001984c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `textFieldShouldReturn` | `0x1001984c4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001b0f1c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `propertyNames` | `0x1001b0f1c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1001b1058`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `propertyNames` | `0x1001b1058` |
- **Findings**: 1 issue(s)

### `boolForKey:`

- **Library**: Foundation
- **Address**: `0x1001b92c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___InitLogging_block_invoke` | `0x1001b92c8` |

### `boolForKey:`

- **Library**: Foundation
- **Address**: `0x1001b93cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___InitLogging_block_invoke` | `0x1001b93cc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001c756c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_CBLStemmerNameForCurrentLocale` | `0x1001c756c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001df890`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___43-[CBLCookieStorage_migrateOldCookieStorage]_block_invoke` | `0x1001df890` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001df8d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___43-[CBLCookieStorage_migrateOldCookieStorage]_block_invoke` | `0x1001df8d8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001ea730`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addResource:` | `0x1001ea730` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1001ea758`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addResource:` | `0x1001ea758` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001ea854`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addResource:` | `0x1001ea854` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001ea8e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `resourceWithCacheKey:` | `0x1001ea8e0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001ea9a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `resourceWithCacheKeyDontRecache:` | `0x1001ea9a8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001edde8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `labelForRow:` | `0x1001edde8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001f2100`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAttributes:ofDir:error:` | `0x1001f2100` |

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1001f26a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithDirectory:options:shared:` | `0x1001f26a0` |

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1001f2724`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithDirectory:options:shared:` | `0x1001f2724` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1001f4e48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_forgetDatabase:` | `0x1001f4e48` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100206a48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___90-[CBLBulkDownloader_initWithDbURL:database:revisions:attachments:onDocument:onCompletion:]_block_invoke` | `0x100206a48` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10020b554`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b554` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10020b6a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b6a4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10020b8b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `renameAttachmentFileNamesInDir:` | `0x10020b8b8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10020dce4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removeLocalCheckpointDocumentWithKey:outError:` | `0x10020dce4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10020ddfc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getLocalCheckpointDocumentPropertyValueForKey:` | `0x10020ddfc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100210b60`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSDictionary(MYUtils)_my_compactDescription]` | `0x100210b60` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100212f4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSError(MYUtils)_my_errorByPrependingMessage:]` | `0x100212f4c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100212fa8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSError(MYUtils)_my_errorByPrependingMessage:]` | `0x100212fa8` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002144b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSURL(MYUtilities)_my_credentialForRealm:authenticationMethod:]` | `0x1002144b4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100222fa4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `prepare` | `0x100222fa4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002235dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_signatureBaseString` | `0x1002235dc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226730`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAttribute:value:` | `0x100226730` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002268f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `attributeString` | `0x1002268f0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002269d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `attribute:` | `0x1002269d8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226a94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parameters` | `0x100226a94` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226ac8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parameters` | `0x100226ac8` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226af4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parameters` | `0x100226af4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226b3c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parameters` | `0x100226b3c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226b7c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parameters` | `0x100226b7c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100226da4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `loadSetting:provider:prefix:` | `0x100226da4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100226e24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `saveSetting:object:provider:prefix:` | `0x100226e24` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10022723c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `attributesWithString:` | `0x10022723c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100236ecc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addEventsToDB:` | `0x100236ecc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10024c69c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `attachConnection:` | `0x10024c69c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10024c6dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `attachConnection:` | `0x10024c6dc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10024ddd8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___40-[PSWebSocketServer_stream:handleEvent:]_block_invoke` | `0x10024ddd8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100251e30`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDocNumericID:` | `0x100251e30` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100251eac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDocNumericID:` | `0x100251eac` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100251fe0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createOrGetDocNumericID:isNew:` | `0x100251fe0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002520a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createOrGetDocNumericID:isNew:` | `0x1002520a8` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100263658`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `cachedStatementForQuery:` | `0x100263658` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002636b0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCachedStatement:forQuery:` | `0x1002636b0` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002654f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupColumnNames` | `0x1002654f4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002657b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `columnIndexForName:` | `0x1002657b4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100278c4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithFilePath:forConnection:` | `0x100278c4c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10027b368`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startConnection` | `0x10027b368` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10027b38c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startConnection` | `0x10027b38c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10027b62c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseParams:` | `0x10027b62c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10027b6f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseParams:` | `0x10027b6f8` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10027b72c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseParams:` | `0x10027b72c` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10027eac0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `preprocessResponse:` | `0x10027eac0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10027ecac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `preprocessErrorResponse:` | `0x10027ecac` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8054`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `maybeStartTLS` | `0x1002a8054` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8488`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8488` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a86c0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a86c0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8764`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8764` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8934`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8934` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8a9c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8a9c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8c50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8c50` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8da4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8da4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a8f24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a8f24` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a9098`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a9098` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a9210`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a9210` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a94c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a94c4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a95d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a95d8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a96bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a96bc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a97a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a97a4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002a9888`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `ssl_startTLS` | `0x1002a9888` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002b413c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithBundle:configuration:` | `0x1002b413c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002b4184`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithBundle:configuration:` | `0x1002b4184` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002bee88`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_Flurryplcrash_populate_error` | `0x1002bee88` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002cf850`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionaryRepresentation` | `0x1002cf850` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002cf980`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionaryRepresentation` | `0x1002cf980` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d060c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d060c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0a38`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0a38` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0a50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0a50` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0a68`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0a68` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0a80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0a80` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0a98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0a98` |

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1002d0ac4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0ac4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0af4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0af4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b24` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b3c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b3c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b54`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b54` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b6c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b6c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b84`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b84` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0b9c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0b9c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0bb4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0bb4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0c04`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0c04` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0c50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0c50` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0c74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0c74` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d0c94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getJSONRequestForKeyBagStore:withFConfigImpl:withIncludePublisherSegmentation:` | `0x1002d0c94` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002d152c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `appendUUIDToDictionary:` | `0x1002d152c` |
- **Findings**: 1 issue(s)

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1002d4d3c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `installationIDForSessionReport` | `0x1002d4d3c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002d5400`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setCookies:` | `0x1002d5400` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002d5468`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_setCookies:` | `0x1002d5468` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002dab90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___50-[FConfigKillSwitch_initWithKillResponseDelegate:]_block_invoke_3` | `0x1002dab90` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002dabb0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___50-[FConfigKillSwitch_initWithKillResponseDelegate:]_block_invoke_3` | `0x1002dabb0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002daf28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `startWithVersion:withKillSwitchConfig:` | `0x1002daf28` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002db39c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIfPerformKillOrNag:withCurrentDate:` | `0x1002db39c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002db4fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIfPerformKillOrNag:withCurrentDate:` | `0x1002db4fc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002dbe1c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `handleFetchComplete` | `0x1002dbe1c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002e72e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_streamMessage:` | `0x1002e72e4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002e8aa4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_populateMetrics:` | `0x1002e8aa4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002eb480`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___45-[FConfigImpl_getConfigOfConfigObjectForKey:]_block_invoke` | `0x1002eb480` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002ebb80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___42-[FConfigImpl_readDirtyBitWithCompletion:]_block_invoke_2` | `0x1002ebb80` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002f47f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithIdentifier:` | `0x1002f47f4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f491c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupSearchForKey:` | `0x1002f491c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4950`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupSearchForKey:` | `0x1002f4950` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f49ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupSearchForKey:` | `0x1002f49ac` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f49c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupSearchForKey:` | `0x1002f49c8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4a40`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dataForKey:` | `0x1002f4a40` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4a64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dataForKey:` | `0x1002f4a64` |

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1002f4acc`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4b38`
- **Type**: symbol

### `archivedDataWithRootObject:requiringSecureCoding:error:`

- **Library**: Foundation
- **Address**: `0x1002f4ba0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setObject:forKey:` | `0x1002f4ba0` |

### `archivedDataWithRootObject:`

- **Library**: Foundation
- **Address**: `0x1002f4bc0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setObject:forKey:` | `0x1002f4bc0` |
- **Findings**: 1 issue(s)

### `archivedDataWithRootObject:requiringSecureCoding:error:`

- **Library**: Foundation
- **Address**: `0x1002f4c8c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setThisDeviceObject:forKey:` | `0x1002f4c8c` |

### `archivedDataWithRootObject:`

- **Library**: Foundation
- **Address**: `0x1002f4cac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setThisDeviceObject:forKey:` | `0x1002f4cac` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4f74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setData:forKey:` | `0x1002f4f74` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f4f9c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setData:forKey:` | `0x1002f4f9c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f50a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setThisDeviceData:forKey:` | `0x1002f50a4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f50cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setThisDeviceData:forKey:` | `0x1002f50cc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002f51c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `updateValueData:forKey:` | `0x1002f51c4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002f5d80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___137-[FConfigEngine_fetchedMergedConfigWithDefaultConfig:withLastFetchedConfig:withEndpoint:withCompletion:withIncludePublisherSegmentation:]_block_invoke_3` | `0x1002f5d80` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002f5da0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___137-[FConfigEngine_fetchedMergedConfigWithDefaultConfig:withLastFetchedConfig:withEndpoint:withCompletion:withIncludePublisherSegmentation:]_block_invoke_3` | `0x1002f5da0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002f66cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___98-[FConfigEngine_checkForBackgroundResponseWithDefaultConfig:withLastFetchedConfig:withCompletion:]_block_invoke_3` | `0x1002f66cc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002f66ec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___98-[FConfigEngine_checkForBackgroundResponseWithDefaultConfig:withLastFetchedConfig:withCompletion:]_block_invoke_3` | `0x1002f66ec` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa428`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getUniqueVariants` | `0x1002fa428` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002fa4e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getUniqueVariants` | `0x1002fa4e0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002fa668`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryRepresentation` | `0x1002fa668` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa6b4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryRepresentation` | `0x1002fa6b4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa70c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryRepresentation` | `0x1002fa70c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa764`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryRepresentation` | `0x1002fa764` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1002fa790`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryRepresentation` | `0x1002fa790` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa884`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:` | `0x1002fa884` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fa980`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:` | `0x1002fa980` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fabf0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getFValueForKey:` | `0x1002fabf0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fbf90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x1002fbf90` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1002fc190`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x1002fc190` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003016a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x1003016a4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003016ec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithJSONDictionary:fromPreviousConfig:shouldPurgeOldVariants:` | `0x1003016ec` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003018f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x1003018f8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100301968`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x100301968` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100301994`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x100301994` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003019e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x1003019e4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100301a18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x100301a18` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100301b2c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x100301b2c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100301ba0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `purgeOldVariantsFromBags:withNewSet:` | `0x100301ba0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100301d6c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createDictionaryFromKeyBagStore:` | `0x100301d6c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100301d78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createDictionaryFromKeyBagStore:` | `0x100301d78` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100301dbc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createDictionaryFromKeyBagStore:` | `0x100301dbc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100301e94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createDictionaryFromKeyBagStore:` | `0x100301e94` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100301ee0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createDictionaryFromKeyBagStore:` | `0x100301ee0` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302288`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x100302288` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003022b0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x1003022b0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10030230c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x10030230c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100302340`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x100302340` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10030235c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x10030235c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100302390`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x100302390` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003023bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x1003023bc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302508`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x100302508` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100302570`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `serializeToJSON` | `0x100302570` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003026f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getVariantsArray` | `0x1003026f0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003028ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `allObjects` | `0x1003028ac` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302aa8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `allObjectsForNamespace:` | `0x100302aa8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302e10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getBagOfKeysForNamespace:` | `0x100302e10` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302ea0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringForKey:forNamespace:` | `0x100302ea0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100302f60`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getNumberForKey:forNamespace:` | `0x100302f60` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100303020`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setBagOfKeys:forNamespace:` | `0x100303020` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003031a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createAndInsertNewFValue:withLocalizedValues:withType:withVersion:withVariantId:forNamespace:withKey:withBags:` | `0x1003031a0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003031f4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createAndInsertNewFValue:withLocalizedValues:withType:withVersion:withVariantId:forNamespace:withKey:withBags:` | `0x1003031f4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100303208`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createAndInsertNewFValue:withLocalizedValues:withType:withVersion:withVariantId:forNamespace:withKey:withBags:` | `0x100303208` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003032ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removeFValueForNamespace:forKey:forVariantId:withBags:` | `0x1003032ac` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003032cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removeFValueForNamespace:forKey:forVariantId:withBags:` | `0x1003032cc` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100303b30`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `refreshRequestBody` | `0x100303b30` |

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x100307f9c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setConversionValue:` | `0x100307f9c` |

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x10030812c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `conversionValue` | `0x10030812c` |

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x100308524`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `migrateDataIfNeeded` | `0x100308524` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030ca50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_captureDiskUsage` | `0x10030ca50` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030dcb4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableDictionary(Flurry)_hashAndUpdateValueForKey:]` | `0x10030dcb4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10030dd68`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `-[NSMutableDictionary(Flurry)_hashAndUpdateValueForKey:]` | `0x10030dd68` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e1ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e1ac` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e268`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e268` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e324`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e324` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e3e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e3e8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e4a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e4a0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e52c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setLaunchOptions:` | `0x10030e52c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e8b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseDictionary:` | `0x10030e8b8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10030e950`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parseDictionary:` | `0x10030e950` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100310b0c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `updateSyndicationParameters:syndicationID:` | `0x100310b0c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100315a18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setString:forKey:` | `0x100315a18` |
- **Findings**: 1 issue(s)

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x100315a64`
- **Type**: symbol

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x100315fc4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setInteger:forParam:` | `0x100315fc4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318a48`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `publicKeyFromData:` | `0x100318a48` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318a6c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `publicKeyFromData:` | `0x100318a6c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318a84`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `publicKeyFromData:` | `0x100318a84` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318aa0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `publicKeyFromData:` | `0x100318aa0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318ae8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `publicKeyFromData:` | `0x100318ae8` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318bb0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removePublicKeyReference:` | `0x100318bb0` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318bd4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removePublicKeyReference:` | `0x100318bd4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318bec`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removePublicKeyReference:` | `0x100318bec` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100318c34`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removePublicKeyReference:` | `0x100318c34` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10031ad28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `populateEndEventFields:` | `0x10031ad28` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100320bb0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithConfig:nodeDataProvider:filePath:fileManager:fileTransferAgent:` | `0x100320bb0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100320c0c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithConfig:nodeDataProvider:filePath:fileManager:fileTransferAgent:` | `0x100320c0c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003210e0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_didCompleteTransfer:withError:` | `0x1003210e0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003220c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_processFiles` | `0x1003220c8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100322838`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_addToStatusDictionaryNewFilesFromFolder:` | `0x100322838` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100322874`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_addToStatusDictionaryNewFilesFromFolder:` | `0x100322874` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100322908`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_addToStatusDictionaryNewFilesFromFolder:` | `0x100322908` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100322b1c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_removeFromDictionaryFilesNotInFolder:` | `0x100322b1c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100322b80`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_removeFromDictionaryFilesNotInFolder:` | `0x100322b80` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100324448`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___74-[FlurryWatchConnectivity_observeValueForKeyPath:ofObject:change:context:]_block_invoke` | `0x100324448` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100325264`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___49-[FlurryDataSenderIndex_addBlockInfo:forDataKey:]_block_invoke` | `0x100325264` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003252c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___49-[FlurryDataSenderIndex_addBlockInfo:forDataKey:]_block_invoke` | `0x1003252c4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10032546c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___66-[FlurryDataSenderIndex_removeBlockInfoWithIdentifier:forDataKey:]_block_invoke` | `0x10032546c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10032580c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupForCurrentDataKey:` | `0x10032580c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100325864`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setupForCurrentDataKey:` | `0x100325864` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100325bd8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___57-[FlurryDataSenderIndex_discardOutdatedBlocksForDataKey:]_block_invoke` | `0x100325bd8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100325d54`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `discardOldBlocksForDataKey:` | `0x100325d54` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100325ed8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `discardOldBlocksForDataKey:` | `0x100325ed8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003261c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___49-[FlurryDataSenderIndex_notSentBlocksForDataKey:]_block_invoke` | `0x1003261c4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100329ae0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isValidDict:` | `0x100329ae0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100329b0c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isValidDict:` | `0x100329b0c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10032b208`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `retrieveETagFromSession:` | `0x10032b208` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10032b2c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `retrieveHeader:fromSession:` | `0x10032b2c4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10032d248`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `encoded2TransactionDictionary` | `0x10032d248` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10032ec24`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `jsonRepresentation` | `0x10032ec24` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10032ed98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `jsonRepresentationForDebug` | `0x10032ed98` |
- **Findings**: 1 issue(s)

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x10033039c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_writeCounterFrame` | `0x10033039c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003306a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_streamMessage:` | `0x1003306a8` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003306c8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_streamMessage:` | `0x1003306c8` |
- **Findings**: 1 issue(s)

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x100330f4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_validatePendingLogFile` | `0x100330f4c` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100331228`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `didReceiveUserInfo:` | `0x100331228` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100333bc8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getStringFromDictionary:forKey:` | `0x100333bc8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100333c44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDictionaryFromDictionary:forKey:` | `0x100333c44` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100333cc0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getNumberFromDictionary:forKey:` | `0x100333cc0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100333d3c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getArrayFromDictionary:forKey:` | `0x100333d3c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003374e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setString:forKey:` | `0x1003374e4` |
- **Findings**: 1 issue(s)

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x1003374ec`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100337544`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setInteger:forKey:` | `0x100337544` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003375d0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setFloat:forKey:` | `0x1003375d0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10033765c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setDouble:forKey:` | `0x10033765c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003376e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setBoolean:forKey:` | `0x1003376e8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100337720`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setData:forKey:` | `0x100337720` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100337728`
- **Type**: symbol

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100337858`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___36-[FlurryKVStorage_setObject:forKey:]_block_invoke` | `0x100337858` |
- **Findings**: 1 issue(s)

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x100337974`
- **Type**: symbol

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337984`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `stringForKey:` | `0x100337984` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337a18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `integerForKey:withDefaultValue:` | `0x100337a18` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337ab0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `floatForKey:withDefaultValue:` | `0x100337ab0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337b4c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `doubleForKey:withDefaultValue:` | `0x100337b4c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337be4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `booleanForKey:withDefaultValue:` | `0x100337be4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337c64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dataForKey:` | `0x100337c64` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337cd4`
- **Type**: symbol

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337e2c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___32-[FlurryKVStorage_objectForKey:]_block_invoke` | `0x100337e2c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100337f94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___38-[FlurryKVStorage_removeObjectForKey:]_block_invoke` | `0x100337f94` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100338500`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `objectForKeyedSubscript:` | `0x100338500` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10033850c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setObject:forKeyedSubscript:` | `0x10033850c` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10033a480`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `isValidDict:` | `0x10033a480` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10033c710`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x10033c710` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10033c8c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `flushResponseForMessage:` | `0x10033c8c4` |

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x10033f314`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithData:` | `0x10033f314` |

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x10033faa8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setData:` | `0x10033faa8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100345b94`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_getIntanceForProtocolOrClass:` | `0x100345b94` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100345bd4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_getIntanceForProtocolOrClass:` | `0x100345bd4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100345c74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `onqueue_getIntanceForProtocolOrClass:` | `0x100345c74` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100346360`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___44-[FlurryStreamBaseManager_setModule:forKey:]_block_invoke` | `0x100346360` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100346548`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createOrGetProviderModule:` | `0x100346548` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100346588`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createOrGetProviderModule:` | `0x100346588` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003465e8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createOrGetProviderModule:` | `0x1003465e8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100346a64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `chainSourceModules:` | `0x100346a64` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100346b58`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addModule:moduleString:` | `0x100346b58` |

### `initWithContentsOfFile:`

- **Library**: Foundation
- **Address**: `0x1003481bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_safeUnarchiveObjectWithFile:ofClasses:` | `0x1003481bc` |

### `initWithContentsOfFile:`

- **Library**: Foundation
- **Address**: `0x100348564`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_safeUnarchiveObjectWithFile:ofClass:` | `0x100348564` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003488d0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_unarchiveFromNSUserDefaultsWithPath:ofClasses:` | `0x1003488d0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100348a88`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_unarchiveFromNSUserDefaultsWithPath:ofClass:` | `0x100348a88` |

### `archivedDataWithRootObject:requiringSecureCoding:error:`

- **Library**: Foundation
- **Address**: `0x100348f10`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_TVOS_archiveObject:toPath:` | `0x100348f10` |

### `archivedDataWithRootObject:`

- **Library**: Foundation
- **Address**: `0x100348f30`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_TVOS_archiveObject:toPath:` | `0x100348f30` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100348f90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_TVOS_archiveObject:toPath:` | `0x100348f90` |

### `archivedDataWithRootObject:requiringSecureCoding:error:`

- **Library**: Foundation
- **Address**: `0x10034912c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_archiveObject:toPath:` | `0x10034912c` |

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x100349160`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_archiveObject:toPath:` | `0x100349160` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034a04c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `appIsCracked` | `0x10034a04c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034ad38`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `incrementCounter:` | `0x10034ad38` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034ad5c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `incrementCounter:` | `0x10034ad5c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034adbc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `incrementCounter:` | `0x10034adbc` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034af04`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decrementCounter:` | `0x10034af04` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034af28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decrementCounter:` | `0x10034af28` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034af88`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decrementCounter:` | `0x10034af88` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034b12c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `printCounters` | `0x10034b12c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034b37c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getFreeDiskspace` | `0x10034b37c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034b8c0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `getDiskSize` | `0x10034b8c0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034c000`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `substituteParamsInString:withValuesDictionary:forPattern:` | `0x10034c000` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034c3e4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionary2Base64UTF8Dictionary:` | `0x10034c3e4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034c3f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionary2Base64UTF8Dictionary:` | `0x10034c3f8` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034c424`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionary2Base64UTF8Dictionary:` | `0x10034c424` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034c53c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionary2Base64UTF8Dictionary:` | `0x10034c53c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034c6f8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionaryToStringDictionary:` | `0x10034c6f8` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034c724`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionaryToStringDictionary:` | `0x10034c724` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034c800`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `dictionaryToStringDictionary:` | `0x10034c800` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034e25c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `init` | `0x10034e25c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10034e28c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `init` | `0x10034e28c` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10034e8b8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `removeTrackerByName:` | `0x10034e8b8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100355600`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIAdCampaignAttributionWithHitParameters:` | `0x100355600` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003557a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `checkIAdCampaignAttributionWithHitParameters:` | `0x1003557a8` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100355c18`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `handleCampaignResult:campaignHitParameters:` | `0x100355c18` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100355c9c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `handleCampaignResult:campaignHitParameters:` | `0x100355c9c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035c258`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_set:forKey:` | `0x10035c258` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035c3d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAll:` | `0x10035c3d4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035c3dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAll:` | `0x10035c3dc` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035c404`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAll:` | `0x10035c404` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035c478`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setAll:` | `0x10035c478` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035c688`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `get:` | `0x10035c688` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035cbc4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `build` | `0x10035cbc4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035cbf4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `build` | `0x10035cbf4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035ccfc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `build` | `0x10035ccfc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035cf00`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `build` | `0x10035cf00` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035cf78`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `build` | `0x10035cf78` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d18c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d18c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d208`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d208` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d234`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d234` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d290`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d290` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d2bc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d2bc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d318`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d318` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d344`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d344` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d3a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d3a0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d3cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d3cc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d428`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d428` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d454`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d454` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d4b0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d4b0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d4dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d4dc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d538`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d538` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d564`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d564` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d5c4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d5c4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d5f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d5f0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d64c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d64c` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d678`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d678` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d6d0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d6d0` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035d6fc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d6fc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035d758`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setCampaignParametersFromUrl:` | `0x10035d758` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035da28`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createEventWithCategory:action:label:value:` | `0x10035da28` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035da90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createEventWithCategory:action:label:value:` | `0x10035da90` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035daf8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createEventWithCategory:action:label:value:` | `0x10035daf8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035db64`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `createEventWithCategory:action:label:value:` | `0x10035db64` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035ea90`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addProductImpression:impressionList:impressionSource:` | `0x10035ea90` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035eb38`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `addProductImpression:impressionList:impressionSource:` | `0x10035eb38` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035f13c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setString:forKey:` | `0x10035f13c` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035f254`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setNumber:forKey:` | `0x10035f254` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035f758`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x10035f758` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035f788`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x10035f788` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035f7d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x10035f7d4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035f96c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithListIndex:index:` | `0x10035f96c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035f984`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithListIndex:index:` | `0x10035f984` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10035f9a0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithListIndex:index:` | `0x10035f9a0` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035f9f0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithListIndex:index:` | `0x10035f9f0` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035fb98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setString:forKey:` | `0x10035fb98` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035fcb0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setNumber:forKey:` | `0x10035fcb0` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10035ff74`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setString:forKey:` | `0x10035ff74` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100360158`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x100360158` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100360188`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x100360188` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003601d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `buildWithIndex:` | `0x1003601d4` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100360764`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `systemCountryFromLocale:` | `0x100360764` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003619d4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `encodeParameters:` | `0x1003619d4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100361ba4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parametersForHit:` | `0x100361ba4` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100365014`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `decodeParametersFromQuery:` | `0x100365014` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1003659a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_set:` | `0x1003659a4` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100365a60`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `gai_send:` | `0x100365a60` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100366760`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x100366760` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003667a4`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x1003667a4` |
- **Findings**: 1 issue(s)

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003667d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x1003667d8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10036680c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x10036680c` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100366840`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x100366840` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100366874`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x100366874` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003668a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x1003668a8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1003668dc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x1003668dc` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100366910`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initialize` | `0x100366910` |

### `sqlite3_prepare_v2`

- **Library**: libsqlite3.dylib
- **Address**: `0x100369c74`
- **Type**: symbol
- **Call Sites**: 79

| Caller | Address |
|--------|--------|
| `yapGetDataForKeyStatement` | `0x1000db894` |
| `restoreMasterChangeQueue` | `0x100083aa4` |
| `yapSetDataForKeyStatement` | `0x1000dba24` |
| `yapRemoveForKeyStatement` | `0x1000dbbb4` |
| `executeQuery:withArgumentsInArray:orVAList:` | `0x100263dc4` |
| `yapRemoveExtensionStatement` | `0x1000dbd44` |
| `getCollectionCountStatement` | `0x1000dbed4` |
| `getKeyCountForCollectionStatement` | `0x1000dc064` |
| `columnNamesAndAffinityForTable:using:` | `0x10006b234` |
| `prepareStatement:withString:caller:` | `0x10003f490` |
| `beginTransactionStatement` | `0x1000db3e4` |
| `commitTransactionStatement` | `0x1000db574` |
| `get_user_version:` | `0x10006b648` |
| `rollbackTransactionStatement` | `0x1000db704` |
| `enumerateRowsForKeys:inCollection:unorderedUsingBlock:` | `0x100017f10` |
| `enumerateRowsInCollectionStatement` | `0x1000de904` |
| `mappingTableInfoForRowids:` | `0x10008b0ac` |
| `tableExists:using:` | `0x10006aa94` |
| `enumerateRowsInAllCollectionsStatement` | `0x1000dea94` |
| `removeAllObjectsInCollection:` | `0x100027e1c` |

*...and 59 more call sites*

### `sqlite3_exec`

- **Library**: libsqlite3.dylib
- **Address**: `0x100369dc4`
- **Type**: symbol
- **Call Sites**: 45

| Caller | Address |
|--------|--------|
| `set_user_version:` | `0x10006b94c` |
| `createTables` | `0x10002bb34` |
| `upgradeTable_1_2` | `0x10006bab8` |
| `upgradeTable_2_3` | `0x10006bbe8` |
| `upgradeTable_2_3` | `0x10006bcf8` |
| `dropTablesForOldClassVersion:` | `0x1000bbeec` |
| `dropTablesForOldClassVersion:` | `0x1000bc10c` |
| `dropTable` | `0x1000ac074` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x100123204` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x10012334c` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x10009a914` |
| `createTables` | `0x100082e18` |
| `createTables` | `0x100083020` |
| `createTables` | `0x100083328` |
| `createTables` | `0x100083630` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x100062db8` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x100036fb0` |
| `dropTablesForRegisteredName:withTransaction:wasPersistent:` | `0x10011e38c` |
| `configureDatabase:` | `0x1000698e0` |
| `configureDatabase:` | `0x1000699f4` |

*...and 25 more call sites*
- **Findings**: 45 issue(s)

### `archivedDataWithRootObject:`

- **Library**: Foundation
- **Address**: `0x10036f5a8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$archivedDataWithRootObject:` | `0x10036f5a8` |
- **Findings**: 1 issue(s)

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100374de8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$objectForKey:` | `0x100374de8` |

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100377308`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$setObject:forKey:` | `0x100377308` |
- **Findings**: 1 issue(s)

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x100377d08`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_objc_msgSend$stringForKey:` | `0x100377d08` |

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100458830`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100458860`
- **Type**: objc_selector

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100462cd0`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100462ce8`
- **Type**: objc_selector

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x100466e70`
- **Type**: objc_selector

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x100468930`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x100468978`
- **Type**: objc_selector

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x10046dd88`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x10046dda0`
- **Type**: objc_selector

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x10046dde8`
- **Type**: objc_selector

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1004a5878`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1004a5890`
- **Type**: objc_selector

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x1004acf40`
- **Type**: objc_selector

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x1004b7f70`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1004b7fe8`
- **Type**: objc_selector

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1004b8000`
- **Type**: objc_selector

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1004b80f0`
- **Type**: objc_selector

### `initWithContentsOfFile:`

- **Library**: Foundation
- **Address**: `0x1004c3cc8`
- **Type**: objc_selector

### `writeToFile:atomically:`

- **Library**: Foundation
- **Address**: `0x1004c3d10`
- **Type**: objc_selector

### `setBool:forKey:`

- **Library**: Foundation
- **Address**: `0x1004c40a8`
- **Type**: objc_selector

### `boolForKey:`

- **Library**: Foundation
- **Address**: `0x1004c4e30`
- **Type**: objc_selector

### `archivedDataWithRootObject:requiringSecureCoding:error:`

- **Library**: Foundation
- **Address**: `0x1004ca478`
- **Type**: objc_selector

### `setInteger:forKey:`

- **Library**: Foundation
- **Address**: `0x1004cab48`
- **Type**: objc_selector

### `archivedDataWithRootObject:`

- **Library**: Foundation
- **Address**: `0x1004ccfc0`
- **Type**: objc_selector

### `objectForKey:`

- **Library**: Foundation
- **Address**: `0x1004ce5d0`
- **Type**: objc_selector

### `setObject:forKey:`

- **Library**: Foundation
- **Address**: `0x1004cef18`
- **Type**: objc_selector

### `stringForKey:`

- **Library**: Foundation
- **Address**: `0x1004cf198`
- **Type**: objc_selector

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
