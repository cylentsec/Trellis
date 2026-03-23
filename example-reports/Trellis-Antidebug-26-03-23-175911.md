# Trellis Antidebug Analysis Report

**Binary**: `DVIA-v2`
**Generated**: 2026-03-23 17:59:11
**Category**: Anti-debugging techniques detected in the binary
**Tool**: Trellis for Ghidra

---

## Summary

| Metric | Value |
|--------|-------|
| Functions Analyzed | 22 |
| Total Findings | 45 |
| Critical | 0 |
| High | 1 |
| Medium | 13 |
| Low | 31 |
| Info | 0 |

---

## Security Findings

### 🟠 HIGH (1)

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x10011e07c` (Offset: `0x11e07c`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`
- caller: `_disable_gdb`
- caller_context: `GDB/debugger disabling function`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook ptrace in '_disable_gdb' and return 0 to prevent debugger denial; alternatively NOP the call instruction

---

### 🟡 MEDIUM (13)

#### Anti-Injection: _dyld_get_image_name

**Description**: _dyld_get_image_name call detected (enumerates loaded library paths)

**Location**: `0x10011e0e8` (Offset: `0x11e0e8`)

**Function**: `_dyld_get_image_name`

**Evidence**:
- technique: `Loaded library path enumeration`
- detects: `Frida, Cydia Substrate, injected dylibs`
- caller: `_detect_injected_dylds`
- caller_context: `Injected dylib detection`

**Impact**: Can detect injected libraries by checking image paths for known hooking frameworks

**Recommendation**: Hook _dyld_image_count/_dyld_get_image_name to hide injected libraries, or hook '_detect_injected_dylds' to return false/0

---

#### Anti-Injection: _dyld_image_count

**Description**: _dyld_image_count call detected (counts loaded images)

**Location**: `0x10011e0bc` (Offset: `0x11e0bc`)

**Function**: `_dyld_image_count`

**Evidence**:
- technique: `Loaded image count check`
- note: `Typically used with _dyld_get_image_name to enumerate libraries`
- caller: `_detect_injected_dylds`
- caller_context: `Injected dylib detection`

**Impact**: Can detect unexpected libraries by monitoring loaded image count

**Recommendation**: Hook _dyld_image_count/_dyld_get_image_name to hide injected libraries, or hook '_detect_injected_dylds' to return false/0

---

#### Anti-Debug: sysctl

**Description**: sysctl call detected checking P_TRACED flag

**Location**: `0x1002caac0` (Offset: `0x2caac0`)

**Function**: `sysctl`

**Evidence**:
- technique: `kinfo_proc P_TRACED flag check`
- mib_pattern: `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}`
- mib_len: `4`

**Impact**: Can detect if process is being traced by a debugger

**Recommendation**: Hook sysctl to clear P_TRACED flag (0x800) in response

---

#### Anti-Debug: sysctl

**Description**: sysctl call detected checking P_TRACED flag

**Location**: `0x100305ae8` (Offset: `0x305ae8`)

**Function**: `sysctl`

**Evidence**:
- technique: `kinfo_proc P_TRACED flag check`
- mib_pattern: `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}`
- mib_len: `4`

**Impact**: Can detect if process is being traced by a debugger

**Recommendation**: Hook sysctl to clear P_TRACED flag (0x800) in response

---

#### Anti-Debug: sysctl

**Description**: sysctl call detected checking P_TRACED flag

**Location**: `0x10011e218` (Offset: `0x11e218`)

**Function**: `sysctl`

**Evidence**:
- technique: `kinfo_proc P_TRACED flag check`
- mib_pattern: `{CTL_KERN, KERN_PROC, KERN_PROC_PID, pid}`
- mib_len: `4`
- caller: `_isDebugged`
- caller_context: `Debugger detection function`

**Impact**: Can detect if process is being traced by a debugger

**Recommendation**: Hook '_isDebugged' to always return false/0 to bypass debugger detection; or hook sysctl to return benign values

---

#### Anti-Debug: Defensive exit

**Description**: exit call detected (possible defensive termination after tampering detection)

**Location**: `0x10011e178` (Offset: `0x11e178`)

**Function**: `exit`

**Evidence**:
- technique: `Defensive process termination`
- function: `exit`
- exit_code: `0`
- caller: `_detect_injected_dylds`
- caller_context: `Injected dylib detection`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook _dyld_image_count/_dyld_get_image_name to hide injected libraries, or hook '_detect_injected_dylds' to return false/0

---

#### Anti-Debug: Exception Ports

**Description**: task_get_exception_ports call detected (debugger handler check)

**Location**: `0x1002cae44` (Offset: `0x2cae44`)

**Function**: `task_get_exception_ports`

**Evidence**:
- technique: `Exception handler enumeration`
- target: `mach_task_self() or target task`

**Impact**: Debuggers register exception handlers - checking ports reveals them

**Recommendation**: Hook to return empty exception port list

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x1003478a0` (Offset: `0x3478a0`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x100305fa4` (Offset: `0x305fa4`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x10030c928` (Offset: `0x30c928`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x1000f0ed8` (Offset: `0xf0ed8`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x100306058` (Offset: `0x306058`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

#### Anti-Injection: task_info

**Description**: task_info call detected (may enumerate loaded libraries via TASK_DYLD_INFO)

**Location**: `0x100305c70` (Offset: `0x305c70`)

**Function**: `task_info`

**Evidence**:
- technique: `Mach task library enumeration`
- detects: `Injected dylibs, hooking frameworks`

**Impact**: TASK_DYLD_INFO can enumerate all loaded libraries to detect injection

**Recommendation**: Hook task_info to filter injected libraries from results

---

### 🔵 LOW (31)

#### Anti-Hook: dladdr

**Description**: dladdr call detected (validates caller address or detects function hooking)

**Location**: `0x1002b2e34` (Offset: `0x2b2e34`)

**Function**: `dladdr`

**Evidence**:
- technique: `Address-to-symbol resolution`
- detects: `Function hooks, injected code, unexpected callers`

**Impact**: Can detect if functions have been hooked by checking if return addresses are in expected libraries

**Recommendation**: Hook dladdr to return expected Dl_info values

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003693e4` (Offset: `0x3693e4`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x10036973c` (Offset: `0x36973c`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100369834` (Offset: `0x369834`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100369864` (Offset: `0x369864`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100369990` (Offset: `0x369990`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003699c0` (Offset: `0x3699c0`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003688c8` (Offset: `0x3688c8`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003688e0` (Offset: `0x3688e0`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003688f8` (Offset: `0x3688f8`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x10036890c` (Offset: `0x36890c`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100368928` (Offset: `0x368928`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100368940` (Offset: `0x368940`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100368958` (Offset: `0x368958`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100368970` (Offset: `0x368970`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x100368988` (Offset: `0x368988`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: dlsym

**Description**: dlsym call detected (dynamic symbol resolution, may resolve anti-debug APIs at runtime)

**Location**: `0x1003689a0` (Offset: `0x3689a0`)

**Function**: `dlsym`

**Evidence**:
- technique: `Dynamic symbol resolution`
- note: `May resolve ptrace, sysctl, or other anti-debug functions to evade static analysis`

**Impact**: Can dynamically resolve security-sensitive functions to bypass static analysis detection

**Recommendation**: Hook dlsym to monitor which symbols are being resolved

---

#### Anti-Debug: Defensive exit

**Description**: exit call detected (possible defensive termination after tampering detection)

**Location**: `0x10015716c` (Offset: `0x15716c`)

**Function**: `exit`

**Evidence**:
- technique: `Defensive process termination`
- function: `exit`
- exit_code: `4294967295`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook exit to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive exit

**Description**: exit call detected (possible defensive termination after tampering detection)

**Location**: `0x100141cb8` (Offset: `0x141cb8`)

**Function**: `exit`

**Evidence**:
- technique: `Defensive process termination`
- function: `exit`
- exit_code: `0`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook exit to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive exit

**Description**: exit call detected (possible defensive termination after tampering detection)

**Location**: `0x100144818` (Offset: `0x144818`)

**Function**: `exit`

**Evidence**:
- technique: `Defensive process termination`
- function: `exit`
- exit_code: `0`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook exit to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive exit

**Description**: exit call detected (possible defensive termination after tampering detection)

**Location**: `0x1002dbd28` (Offset: `0x2dbd28`)

**Function**: `exit`

**Evidence**:
- technique: `Defensive process termination`
- function: `exit`
- exit_code: `0`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook exit to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1002110d8` (Offset: `0x2110d8`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1002c379c` (Offset: `0x2c379c`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1002b2c7c` (Offset: `0x2b2c7c`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x100211158` (Offset: `0x211158`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x100233090` (Offset: `0x233090`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x100169040` (Offset: `0x169040`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x10020ac98` (Offset: `0x20ac98`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1002b4884` (Offset: `0x2b4884`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1003693c4` (Offset: `0x3693c4`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

#### Anti-Debug: Defensive abort

**Description**: abort call detected (possible defensive termination after tampering detection)

**Location**: `0x1003694e8` (Offset: `0x3694e8`)

**Function**: `abort`

**Evidence**:
- technique: `Defensive process termination`
- function: `abort`
- exit_code: `unknown`

**Impact**: May terminate the process when debugging or tampering is detected

**Recommendation**: Hook abort to prevent termination; investigate caller for detection logic

---

## Functions Analyzed

### `dladdr`

- **Library**: libdyld.dylib
- **Address**: `0x1b0`
- **Type**: import

### `dlsym`

- **Library**: libdyld.dylib
- **Address**: `0x1b2`
- **Type**: import

### `_dyld_get_image_name`

- **Library**: libdyld.dylib
- **Address**: `0x1b3`
- **Type**: import

### `_dyld_image_count`

- **Library**: libdyld.dylib
- **Address**: `0x1b5`
- **Type**: import

### `sysctl`

- **Library**: libsystem_c.dylib
- **Address**: `0x1c7`
- **Type**: import

### `exit`

- **Library**: libsystem_c.dylib
- **Address**: `0x1e3`
- **Type**: import

### `abort`

- **Library**: libsystem_c.dylib
- **Address**: `0x207`
- **Type**: import

### `task_get_exception_ports`

- **Library**: libsystem_kernel.dylib
- **Address**: `0x22a`
- **Type**: import

### `getpid`

- **Library**: libsystem_c.dylib
- **Address**: `0x22b`
- **Type**: import

### `task_info`

- **Library**: libsystem_kernel.dylib
- **Address**: `0x232`
- **Type**: import

### `abort`

- **Library**: libsystem_c.dylib
- **Address**: `0x1000f7d94`
- **Type**: symbol

### `abort`

- **Library**: libsystem_c.dylib
- **Address**: `0x100278df8`
- **Type**: symbol

### `dladdr`

- **Library**: libdyld.dylib
- **Address**: `0x10036ae08`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_image_add_callback` | `0x1002b2e34` |
- **Findings**: 1 issue(s)

### `dlsym`

- **Library**: libdyld.dylib
- **Address**: `0x10036ae20`
- **Type**: symbol
- **Call Sites**: 17

| Caller | Address |
|--------|--------|
| `_disable_gdb` | `0x10011e07c` |
| `__invoke` | `0x1003693e4` |
| `__invoke` | `0x10036973c` |
| `__invoke` | `0x100369834` |
| `__invoke` | `0x100369864` |
| `__invoke` | `0x100369990` |
| `__invoke` | `0x1003699c0` |
| `__initializeAvailabilityCheck` | `0x1003688c8` |
| `__initializeAvailabilityCheck` | `0x1003688e0` |
| `__initializeAvailabilityCheck` | `0x1003688f8` |
| `__initializeAvailabilityCheck` | `0x10036890c` |
| `__initializeAvailabilityCheck` | `0x100368928` |
| `__initializeAvailabilityCheck` | `0x100368940` |
| `__initializeAvailabilityCheck` | `0x100368958` |
| `__initializeAvailabilityCheck` | `0x100368970` |
| `__initializeAvailabilityCheck` | `0x100368988` |
| `__initializeAvailabilityCheck` | `0x1003689a0` |
- **Findings**: 17 issue(s)

### `_dyld_get_image_name`

- **Library**: libdyld.dylib
- **Address**: `0x10036ae2c`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_detect_injected_dylds` | `0x10011e0e8` |
- **Findings**: 1 issue(s)

### `_dyld_image_count`

- **Library**: libdyld.dylib
- **Address**: `0x10036ae44`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `_detect_injected_dylds` | `0x10011e0bc` |
- **Findings**: 1 issue(s)

### `sysctl`

- **Library**: libsystem_c.dylib
- **Address**: `0x10036af1c`
- **Type**: symbol
- **Call Sites**: 5

| Caller | Address |
|--------|--------|
| `lastBootTime` | `0x10034b9c4` |
| `initWithProcessID:` | `0x1002caac0` |
| `fetchColdStartTime` | `0x100305ae8` |
| `uptime` | `0x10034c1ec` |
| `_isDebugged` | `0x10011e218` |
- **Findings**: 3 issue(s)

### `exit`

- **Library**: libsystem_c.dylib
- **Address**: `0x10036b06c`
- **Type**: symbol
- **Call Sites**: 5

| Caller | Address |
|--------|--------|
| `$killApplicationTapped` | `0x10015716c` |
| `_detect_injected_dylds` | `0x10011e178` |
| `$$closure_#1_@Swift.MainActor_()_->_()_in_DVIA_v2.JailbreakDetectionViewController.jailbreakTest4Tapped(Any)_->_()` | `0x100141cb8` |
| `$$closure_#1_@Swift.MainActor_()_->_()_in_DVIA_v2.JailbreakDetectionViewController.jailbreakTest5Tapped(Any)_->_()` | `0x100144818` |
| `___121-[FConfigKillSwitch_showAlertWithType:withDismissButtonText:withTitleText:withMessageText:withPrimaryButtonText:withURL:]_block_invoke_2` | `0x1002dbd28` |
- **Findings**: 5 issue(s)

### `abort`

- **Library**: libsystem_c.dylib
- **Address**: `0x10036b21c`
- **Type**: symbol
- **Call Sites**: 10

| Caller | Address |
|--------|--------|
| `__AssertFailed` | `0x1002110d8` |
| `_Flurryplcrash_async_thread_state_get_reg_name` | `0x1002c379c` |
| `_Flurryplcrash_writer_pack` | `0x1002b2c7c` |
| `__AssertAbstractMethodFailed` | `0x100211158` |
| `_yajl_do_parse` | `0x100233090` |
| `$$closure_#1_()_->___C.NSPersistentStoreCoordinator_in_DVIA_v2.CoreDataStack.persistentStoreCoordinator.getter_:___C.NSPersistentStoreCoordinator` | `0x100169040` |
| `_collateRevIDs` | `0x10020ac98` |
| `_uncaught_exception_handler.cold.1` | `0x1002b4884` |
| `swift_task_escalateBackdeploy56` | `0x1003693c4` |
| `swift_Concurrency_fatalError` | `0x1003694e8` |
- **Findings**: 10 issue(s)

### `task_get_exception_ports`

- **Library**: libsystem_kernel.dylib
- **Address**: `0x10036b3c0`
- **Type**: symbol
- **Call Sites**: 1

| Caller | Address |
|--------|--------|
| `exceptionPortsForTask:mask:error:` | `0x1002cae44` |
- **Findings**: 1 issue(s)

### `getpid`

- **Library**: libsystem_c.dylib
- **Address**: `0x10036b3cc`
- **Type**: symbol
- **Call Sites**: 5

| Caller | Address |
|--------|--------|
| `init` | `0x10007b720` |
| `currentProcessInfo` | `0x1002caa18` |
| `fetchColdStartTime` | `0x100305ac8` |
| `getDeviceInfo` | `0x1000f1250` |
| `_isDebugged` | `0x10011e1f4` |

### `task_info`

- **Library**: libsystem_kernel.dylib
- **Address**: `0x10036b420`
- **Type**: symbol
- **Call Sites**: 6

| Caller | Address |
|--------|--------|
| `_total_cpu_usage` | `0x1003478a0` |
| `flurryApplicationDidFinishLaunching` | `0x100305fa4` |
| `onqueue_captureMemoryUsage` | `0x10030c928` |
| `getDeviceInfo` | `0x1000f0ed8` |
| `_fetchMemory` | `0x100306058` |
| `___42-[FlurryColdStartMonitor_reportFullyDrawn]_block_invoke` | `0x100305c70` |
- **Findings**: 6 issue(s)

---

## Next Steps

1. Review each finding and assess its impact
2. Use Frida scripts for runtime validation (generate with Trellis CLI)
3. Address critical and high severity issues first
4. Consider security notes for functions without specific findings

---

*Generated by [Trellis](https://github.com/cylentsec/Trellis) - iOS Security Analysis Toolkit for Ghidra*
