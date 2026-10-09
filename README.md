# Poor DMA (Remote Memory Introspection via KslD.sys)

[![Rust](https://img.shields.io/badge/language-Rust%202024-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%2011%20(24H2%20%7C%2025H2)-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

> ### Notice
> * **Pre-Compiled Binaries:** Ready-to-use binaries (`poor_dma_server.exe` and `poor_dma_client.exe`) are available on the release thread: [hackvshack.net Poor DMA Release Thread](https://hackvshack.net/threads/poor-dma-alternative-for-dma-cards-by-abusing-window-defender-driver-to-read-physical-memory.14277/)
> * **Questions, Support & Usage:** For troubleshooting, setup help, questions, and usage discussions, visit the forum thread linked above.
> * **GitHub Scope:** This GitHub repository is exclusively dedicated to source code. Contributions, bug fixes, performance improvements, and pull requests are welcome.

---

## Table of Contents
1. [Overview](#overview)
2. [Driver Trust Model & Security Research](#driver-trust-model--security-research)
3. [Infrastructure](#infrastructure)
4. [Repository Structure](#repository-structure)
5. [Setup](#setup)
6. [CLI Usage Reference](#cli-usage-reference)
7. [Developer Integration](#developer-integration)
8. [CR3 Shuffling Fix & PFN Database Recovery](#cr3-shuffling-fix--pfn-database-recovery)
9. [Disclaimer & Contributing](#disclaimer--contributing)

---

## Overview

**Poor DMA** is an open-source, software-based architecture designed for remote memory inspection across a local area network (LAN). Instead of requiring physical PCIe hardware cards with custom firmware, Poor DMA utilizes a Microsoft-signed diagnostic driver: **`KslD.sys`** (a native diagnostic component of Windows Defender).

### Key Architecture Features
* **Arbitrary Physical Memory Access:** Utilizes the driver's underlying `MmCopyMemory` physical read primitive (`MM_COPY_MEMORY_PHYSICAL` via Sub-Command `0x0C`), allowing physical memory pages to be safely queried without triggering system bugchecks on unmapped regions.
* **CPU Control Register Read via DPCs:** Queries Sub-Command `0x02` to extract processor control registers (`CR3`, `CR0`, `CR4`, `IDTR`, and `GDTR`) across active CPU cores.
* **CR3 Shuffling Fix (PFN Recovery):** Dynamically resolves `MmPfnDatabase` without debugging symbols and traverses physical page frames to recover the genuine Directory Table Base (`CR3`) when process pointers are obfuscated, stripped, or randomized via CR3 shuffling.
* **Software 4-Level x64 Page-Table Walker:** Implements a full software page-table walker (PML4 -> PDPT -> PD -> PT) with a translation cache, enabling seamless virtual address translation over physical reads.
* **Isolated Analysis Pipeline:** Memory inspection, parsing, and data display run entirely on a secondary system over LAN. The target machine remains clean of intrusive hooks, code injections, and analysis windows.

---

## Driver Trust Model & Security Research

### Driver Revocation & Trust Hierarchy
1. **Consumer OEM Drivers:** Drivers from small hardware vendors have a narrow operational footprint and are frequently revoked via Windows Hypervisor-Protected Code Integrity (HVCI) vulnerable driver blocklists (`DriverSiPolicy.p7b`).
2. **Silicon Diagnostic Drivers (Intel, etc.):** Historically distributed across enterprise installations for system diagnostics (e.g., `iqvw64e.sys` / CVE-2015-2291). Due to their arbitrary write and execution capabilities, modern hypervisors strictly supervise their loading.
3. **First-Party Operating System Drivers (KslD.sys):** Signed directly by Microsoft Windows Component PCA / WHQL. Operating strictly as a read diagnostic interface, it avoids code modification primitives while providing read capabilities.

### Microsoft Servicing Criteria
Under official Microsoft Security Response Center (MSRC) guidelines, **Administrator-to-Kernel is not recognized as a security boundary**. Access to `\\.\KslD` and modification of the `AllowedProcessName` service configuration require local Administrator elevation, which already grants system-level privileges under the Windows trust model.

---

## Infrastructure

```text
+-----------------------+           +-----------------------+
|  TARGET MACHINE (OS)  |           |  ANALYSIS MACHINE     |
|                       |           |                       |
|  [Target Process]     |           |  [Analysis / GUI]     |
|      |                |           |           ^           |
|  [Physical RAM]       |           |           |           |
|      ^                |           |  poor_dma_client.exe  |
|      | MM_COPY        |           +-----------+-----------+
|  [KslD.sys Driver]    |                       |
|      ^                |           TCP Stream  |
|      | IOCTL          |     <-----------------+
|  poor_dma_server.exe  |          (Port 39172)
+-----------------------+
```

### Execution Lifecycle:
1. **Service Registration:** `poor_dma_server.exe` registers the driver path in `System32\drivers\wd\`, updates `HKLM\SYSTEM\CurrentControlSet\Services\KslD\AllowedProcessName` to authorize the binary, and starts the service.
2. **Register Bootstrap:** The server queries Sub-Command `0x02` to retrieve the active `CR3` and physical RAM limits directly from CPU registers.
3. **CR3 & DTB Resolution:** If a target process has its Directory Table Base (`DirectoryTableBase`) scrambled or sanitized in its `EPROCESS` structure, the built-in PFN recovery algorithm scans the physical page frame database to uncover the genuine user-mode PML4 root. This allows complete virtual memory translation even on protected processes.
4. **Network Handshake:** `poor_dma_client.exe` issues a UDP broadcast on port `39171` to discover the server, establishing a persistent TCP session on port `39172`.
5. **Memory Streaming:** The client requests virtual or physical addresses. The server walks the page tables in software, retrieves data via `KslD.sys`, and streams buffers back to the client.

---

## Repository Structure

```text
poor_dma/
├── Cargo.toml                  # Workspace configuration (LTO, strip, opt-level 3)
├── LICENSE                     # MIT License
├── lan_server/                 # Headless server (executes on Target system)
│   ├── Cargo.toml
│   ├── KslD.sys                # Signed Microsoft diagnostic driver
│   └── src/
│       ├── main.rs             # CLI router & server initialization
│       ├── lib.rs              # Library exports
│       ├── cli.rs              # Argument parser and commands
│       ├── driver.rs           # IOCTL communication interface
│       ├── drop_driver.rs      # Service drop & registry authorization
│       ├── memory.rs           # x64 4-level software page-table walker & cache
│       ├── offsets.rs          # Supported OS offset profiles (Windows 24H2 / 25H2)
│       ├── output.rs           # Formatting & display helpers
│       ├── privilege.rs        # SeDebugPrivilege elevation helpers
│       ├── server.rs           # Multi-threaded TCP/UDP server
│       ├── lan_protocol.rs     # Network protocol codec & framing
│       └── windows/
│           ├── mod.rs          # Subsystem module router
│           ├── kernel.rs       # ntoskrnl base & PsInitialSystemProcess resolution
│           ├── process.rs      # ActiveProcessLinks traversal & EPROCESS parsing
│           ├── loader.rs       # PEB / LDR module enumeration
│           └── dtb.rs          # PFN Database DTB recovery algorithm
└── lan_client/                 # Client library & CLI (executes on Analysis system)
    ├── Cargo.toml
    └── src/
        ├── main.rs             # Interactive shell & CLI reader
        ├── lib.rs              # High-level client API
        └── lan_protocol.rs     # Shared protocol definitions
```

---

## Setup

> [!IMPORTANT]
> **Compatibility Requirements:**  
> 1. **Operating System:** Officially validated on **Windows 11 24H2 (Build 26100)** and **25H2 (Build 26200)**. The server validates build offsets on startup.  
> 2. **Network Environment:** Both systems must be on the same local subnet for UDP auto-discovery and TCP streaming.

### Step 1: Start Server (Target System)
Run the server with **Administrator** privileges:
```cmd
poor_dma_server.exe
```

### Step 2: Start Client (Analysis System)
Run the client executable on your secondary computer:
```cmd
poor_dma_client.exe
```
The client will discover the server and enter the interactive prompt:
```text
[-] CONNECTION
    Status        : DISCONNECTED
    Reason        : searching for server
[+] CONNECTION                                      
    Status        : CONNECTED
    Server        : 192.168.1.100:39172
    Transport     : persistent TCP
poor-dma> 
```

---

## CLI Usage Reference

Commands can be passed as CLI arguments or entered interactively:

```bash
# Display system kernel diagnostics & bootstrap CR3
poor_dma_client.exe system

# List all active processes, PIDs, and DTBs
poor_dma_client.exe processes

# List loaded modules for a target process
poor_dma_client.exe modules explorer.exe

# Get main executable base address
poor_dma_client.exe explorer.exe

# Get specific DLL base address
poor_dma_client.exe explorer.exe ntdll.dll

# Force PFN FixCr3 recovery for protected processes
poor_dma_client.exe fixcr3 explorer.exe

# Read 64 bytes of virtual memory at address
poor_dma_client.exe read-process explorer.exe 0x7FF712345678 64

# Read 8 bytes of kernel memory
poor_dma_client.exe read-kernel 0xFFFFF80012345678 8
```

---

## Developer Integration

You can integrate `poor_dma_client` as a library into custom tools, analysis pipelines, or memory dumpers:

```rust
use poor_dma_client::{MemoryClient, ReadSpan, ReadTarget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MemoryClient::connect("192.168.1.100:39172")?;
    let target = ReadTarget::process_name("explorer.exe")?;

    // Batched scatter read
    let spans = vec![
        ReadSpan::new(0x7FF700001000, 8)?,
        ReadSpan::new(0x7FF700002000, 16)?,
    ];

    let results = client.read_scatter(&target, &spans)?;
    println!("Retrieved {} memory segments over LAN.", results.len());
    Ok(())
}
```

---

## CR3 Shuffling Fix & PFN Database Recovery

In scenarios where process Directory Table Bases (DTBs) are obfuscated or cleared in `_KPROCESS`, standard tools fail to resolve virtual addresses.

Poor DMA incorporates a PFN recovery mechanism in [`windows/dtb.rs`](lan_server/src/windows/dtb.rs):
1. **Dynamic Database Discovery:** Locates the `MmPfnDatabase` base address dynamically by inspecting `ntoskrnl!MmGetVirtualForPhysical` prologue instructions, bypassing KASLR without external PDB symbols.
2. **PML4 Structural Matching:** Because top-level page tables utilize recursive self-referencing mappings, valid PML4 entries share a consistent `_MMPFN.PteAddress` with the System process.
3. **Physical Scan:** Scans active page frame numbers (`_MMPFN.PageLocation == Active`), verifies self-referencing entries, and validates process candidates by resolving the `PEB -> LDR` module list in [`windows/loader.rs`](lan_server/src/windows/loader.rs).

---

## Disclaimer & Contributing

* **Disclaimer:** This project is provided for research, reverse engineering, and defensive analysis purposes.
* **Contributions:** Pull requests for bug fixes, performance improvements, and additional driver implementations are encouraged.
