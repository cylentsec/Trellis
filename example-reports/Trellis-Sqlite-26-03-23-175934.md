# Trellis Sqlite Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:59:34
**Category**: SQLite database security (SQL injection, encryption)
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 28 |
| Total Findings | 124 |
| Critical | 0 |
| High | 45 |
| Medium | 0 |
| Low | 0 |
| Info | 79 |

---

## Security Findings

### 🟠 HIGH (45)

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006b94c` (Offset: `0x6b94c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10002bb34` (Offset: `0x2bb34`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006bab8` (Offset: `0x6bab8`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006bbe8` (Offset: `0x6bbe8`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006bcf8` (Offset: `0x6bcf8`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000bbeec` (Offset: `0xbbeec`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000bc10c` (Offset: `0xbc10c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000ac074` (Offset: `0xac074`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100123204` (Offset: `0x123204`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10012334c` (Offset: `0x12334c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10009a914` (Offset: `0x9a914`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100082e18` (Offset: `0x82e18`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100083020` (Offset: `0x83020`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100083328` (Offset: `0x83328`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100083630` (Offset: `0x83630`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100062db8` (Offset: `0x62db8`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100036fb0` (Offset: `0x36fb0`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10011e38c` (Offset: `0x11e38c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000698e0` (Offset: `0x698e0`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000699f4` (Offset: `0x699f4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100069b10` (Offset: `0x69b10`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100069c14` (Offset: `0x69c14`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100069d70` (Offset: `0x69d70`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100069edc` (Offset: `0x69edc`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x100069ff4` (Offset: `0x69ff4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006a10c` (Offset: `0x6a10c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000412ac` (Offset: `0x412ac`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000f140c` (Offset: `0xf140c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10009d4a4` (Offset: `0x9d4a4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10004158c` (Offset: `0x4158c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000416ec` (Offset: `0x416ec`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10004184c` (Offset: `0x4184c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000419ac` (Offset: `0x419ac`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10009da00` (Offset: `0x9da00`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000ac58c` (Offset: `0xac58c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000ac830` (Offset: `0xac830`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000d8be4` (Offset: `0xd8be4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000bc384` (Offset: `0xbc384`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000bc4e4` (Offset: `0xbc4e4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006c2c4` (Offset: `0x6c2c4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x10006c40c` (Offset: `0x6c40c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000ee698` (Offset: `0xee698`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000ee7b4` (Offset: `0xee7b4`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000eee30` (Offset: `0xeee30`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

#### SQLite Direct Execution

**Description**: sqlite3_exec used - high risk of SQL injection if query is dynamic

**Location**: `0x1000eef4c` (Offset: `0xeef4c`)

**Function**: `sqlite3_exec`

**Evidence**:
- api: `sqlite3_exec`

**Impact**: SQL injection can lead to data theft, modification, or deletion

**Recommendation**: Use sqlite3_prepare_v2 with parameterized queries instead

---

### ⚪ INFO (79)

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000db894` (Offset: `0xdb894`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100083aa4` (Offset: `0x83aa4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dba24` (Offset: `0xdba24`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dbbb4` (Offset: `0xdbbb4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100263dc4` (Offset: `0x263dc4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dbd44` (Offset: `0xdbd44`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dbed4` (Offset: `0xdbed4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc064` (Offset: `0xdc064`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006b234` (Offset: `0x6b234`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10003f490` (Offset: `0x3f490`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000db3e4` (Offset: `0xdb3e4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000db574` (Offset: `0xdb574`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006b648` (Offset: `0x6b648`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000db704` (Offset: `0xdb704`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100017f10` (Offset: `0x17f10`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de904` (Offset: `0xde904`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10008b0ac` (Offset: `0x8b0ac`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006aa94` (Offset: `0x6aa94`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dea94` (Offset: `0xdea94`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100027e1c` (Offset: `0x27e1c`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006ae38` (Offset: `0x6ae38`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10009eff4` (Offset: `0x9eff4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10012a1c0` (Offset: `0x12a1c0`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de134` (Offset: `0xde134`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006a260` (Offset: `0x6a260`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de2c4` (Offset: `0xde2c4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10012a3e4` (Offset: `0x12a3e4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de454` (Offset: `0xde454`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1001225d8` (Offset: `0x1225d8`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006a5dc` (Offset: `0x6a5dc`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de5e4` (Offset: `0xde5e4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100016c80` (Offset: `0x16c80`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000ba960` (Offset: `0xba960`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000de774` (Offset: `0xde774`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000aea34` (Offset: `0xaea34`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10002eaa8` (Offset: `0x2eaa8`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100129930` (Offset: `0x129930`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd964` (Offset: `0xdd964`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100025eb8` (Offset: `0x25eb8`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100026400` (Offset: `0x26400`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100129b54` (Offset: `0x129b54`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000ddaf4` (Offset: `0xddaf4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000ddc84` (Offset: `0xddc84`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100129d78` (Offset: `0x129d78`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dde14` (Offset: `0xdde14`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100129f9c` (Offset: `0x129f9c`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000ddfa4` (Offset: `0xddfa4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd194` (Offset: `0xdd194`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd324` (Offset: `0xdd324`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100015ab0` (Offset: `0x15ab0`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1001296dc` (Offset: `0x1296dc`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd4b4` (Offset: `0xdd4b4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10008dacc` (Offset: `0x8dacc`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd644` (Offset: `0xdd644`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000b17e8` (Offset: `0xb17e8`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd7d4` (Offset: `0xdd7d4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006c8d0` (Offset: `0x6c8d0`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc9c4` (Offset: `0xdc9c4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dcb54` (Offset: `0xdcb54`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dcce4` (Offset: `0xdcce4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100264d64` (Offset: `0x264d64`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10020cdf8` (Offset: `0x20cdf8`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dce74` (Offset: `0xdce74`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100118fc0` (Offset: `0x118fc0`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000f4fb4` (Offset: `0xf4fb4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10012926c` (Offset: `0x12926c`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dd004` (Offset: `0xdd004`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000b0254` (Offset: `0xb0254`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc1f4` (Offset: `0xdc1f4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1002642ec` (Offset: `0x2642ec`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc384` (Offset: `0xdc384`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100265d8c` (Offset: `0x265d8c`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1003644d4` (Offset: `0x3644d4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc514` (Offset: `0xdc514`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x10006c594` (Offset: `0x6c594`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc6a4` (Offset: `0xdc6a4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000c0bb4` (Offset: `0xc0bb4`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x1000dc834` (Offset: `0xdc834`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

---

#### SQLite Prepared Statement

**Description**: sqlite3_prepare_v2 used (safer than sqlite3_exec)

**Location**: `0x100072b7c` (Offset: `0x72b7c`)

**Function**: `sqlite3_prepare_v2`

**Evidence**:
- api: `sqlite3_prepare_v2`

**Impact**: Prepared statements prevent SQL injection when used correctly

**Recommendation**: Ensure all dynamic values use sqlite3_bind_* functions

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

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x1001f9c08`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `findInverseOfRelation:fromClass:` | `0x1001f9c08` |

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x1001f9c44`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `findInverseOfRelation:fromClass:` | `0x1001f9c44` |

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x100215c50`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithView:inDatabase:select:wherePredicate:orderBy:error:` | `0x100215c50` |

### `predicateWithFormat:argumentArray:`

- **Library**: Foundation.framework
- **Address**: `0x1002160ac`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `initWithDatabase:select:where:orderBy:error:` | `0x1002160ac` |

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x100358430`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `requestPropertyWithName:` | `0x100358430` |

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x100358dd0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___40-[GAIDataStore_context:removeStaleHits:]_block_invoke` | `0x100358dd0` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x100358e20`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___40-[GAIDataStore_context:removeStaleHits:]_block_invoke` | `0x100358e20` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035989c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setProperty:numberValue:withError:` | `0x10035989c` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x100359acc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `setProperty:stringValue:withError:` | `0x100359acc` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035a210`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___29-[GAIDataStore_fetchClientId]_block_invoke` | `0x10035a210` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035a88c`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___41-[GAIDataStore_fetchHitsWithLimit:error:]_block_invoke` | `0x10035a88c` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035ae98`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___30-[GAIDataStore_deleteAllHits:]_block_invoke` | `0x10035ae98` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035aea0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___30-[GAIDataStore_deleteAllHits:]_block_invoke` | `0x10035aea0` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035afb0`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___30-[GAIDataStore_deleteAllHits:]_block_invoke` | `0x10035afb0` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035b8cc`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___29-[GAIDataStore_setUpCoreData]_block_invoke` | `0x10035b8cc` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035b9d8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___29-[GAIDataStore_setUpCoreData]_block_invoke_2` | `0x10035b9d8` |

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x10035bb04`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `___29-[GAIDataStore_setUpCoreData]_block_invoke_3` | `0x10035bb04` |

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x100360300`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `symbolFromStackFrame:` | `0x100360300` |

### `filteredArrayUsingPredicate:`

- **Library**: Foundation.framework
- **Address**: `0x100360340`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `symbolFromStackFrame:` | `0x100360340` |

### `filteredArrayUsingPredicate:`

- **Library**: Foundation.framework
- **Address**: `0x100361bf8`
- **Type**: objc_selector
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `parametersForHit:` | `0x100361bf8` |

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
- **Findings**: 79 issue(s)

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

### `predicateWithFormat:`

- **Library**: Foundation.framework
- **Address**: `0x1004c6510`
- **Type**: objc_selector

### `predicateWithFormat:argumentArray:`

- **Library**: Foundation.framework
- **Address**: `0x1004c6bf0`
- **Type**: objc_selector

### `executeFetchRequest:error:`

- **Library**: CoreData.framework
- **Address**: `0x1004cc998`
- **Type**: objc_selector

### `filteredArrayUsingPredicate:`

- **Library**: Foundation.framework
- **Address**: `0x1004ccb38`
- **Type**: objc_selector

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
