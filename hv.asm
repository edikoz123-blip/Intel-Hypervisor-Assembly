[bits 64]
[org 0x5000]        

; =========================================================================
; DISCLAIMER: This project is currently a Work-In-Progress (WIP) and is NOT
; ready for production deployment. Everything is built from scratch in pure
; Assembly, including firmware/motherboard protections (ACPI, SMBIOS, etc.)
; mirrored across both the Intel (VMX/FRED) and the second project
; AMD hypervisor.
; =========================================================================


; ============================================================================
; THERMAL AND TEMPERATURE SENSORS
; ============================================================================

IA32_THERM_STATUS           equ 0x19C   ; Core-level digital thermal sensor
                                        ; Bits 22:16 = Temperature delta below TjMax
                                        ; Bit 31     = Valid bit (Must be 1 to trust read)

IA32_PACKAGE_THERM_STATUS   equ 0x1B1   ; Package-level digital thermal sensor
                                        ; Reports the hottest temperature on the whole die
                                        ; Bits 22:16 = Package temperature delta below TjMax

MSR_TEMPERATURE_TARGET      equ 0x1A2   ; Factory absolute reference values
                                        ; Bits 23:16 = TjMax (Maximum allowable temperature)
                                        ; Use formula: True_Temp = TjMax - Delta

; ============================================================================
; HARDWARE THROTTLING AND CRISIS INDICATORS
; ============================================================================

IA32_THERM_INTERRUPT        equ 0x19B   ; Controls hardware thermal thresholds
                                        ; Bit 0  = High-temperature interrupt enable
                                        ; Bit 2  = Critical temperature interrupt enable

MSR_THERM2_CTL              equ 0x19D   ; Hardware Clock Modulation Control
                                        ; If a rootkit tries to bypass your scheduler by forcing 
                                        ; clock modulation to hide its cycles, reading this reveals it.
; ============================================================================
; EXTENDED POWER AND ELECTRICAL LIMITS
; ============================================================================

MSR_PKG_POWER_LIMIT         equ 0x610   ; Controls average sustainable power levels (PL1 and PL2)
                                        ; Bit 63 = Clamp lock (Flipping this to 1 makes the limits 
                                        ; unchangeable until a cold motherboard reset!)

MSR_PP0_ENERGY_STATUS       equ 0x639   ; Energy consumption specifically for the CPU Cores
                                        ; (Combine this with MSR_PKG_ENERGY_STATUS [0x611] to isolate 
                                        ; exactly how much power the uncore vs the cores are draining).
; ============================================================================
; SILICON-LEVEL SECURITY AND MITIGATION STATUS
; ============================================================================

IA32_ARCH_CAPABILITIES      equ 0x10A   ; Enumerates hardware-level vulnerabilities (Read-Only)
                                        ; Bit 0  = RDCL_NO (If 1, the CPU is immune to Rogue Data Cache Load)
                                        ; Bit 2  = RSBA_NO (Immune to speculative branch exploits)

IA32_SPEC_CTRL              equ 0x48    ; Speculative Execution Controls (Indirect Branch Controls)
                                        ; Bit 0  = IBRS (Indirect Branch Restricted Speculation)
                                        ; Bit 1  = STIBP (Single Thread Indirect Branch Predictor)
                                        ; Your Hypervisor will lock this to prevent cross-core leakage!

IA32_THERM_CONTROL          equ 0x19A   ; Software clock modulation control
                                        ; If a malicious driver tries to intentionally stall or 
                                        ; simulate an hardware choke to manipulate your AI's timeline,
                                        ; checking this register exposes if duty cycling is being forced.

IA32_MISC_ENABLE            equ 0x1A0   ; Master processor feature toggles
                                        ; Bit 16 = Enhanced Intel SpeedStep technology enable.
                                        ; Bit 38 = Turbo Mode Disable.
                                        ; If a rootkit tries to over-clock the CPU to intentionally 
                                        ; step past your temperature threshold tracking, it will modify this.

IA32_TSC_DEADLINE           equ 0x6E0   ; Local APIC high-precision timer deadline
                                        ; Your scheduler can use this to guarantee your AI core 
                                        ; wakes up exactly when it needs to, independent of the 
                                        ; main core's instruction pipeline.
; ============================================================================
; INTEL CORE TELEMETRY DEFINITIONS
; ============================================================================

IA32_PERF_STATUS            equ 0x198   ; Performance and Voltage Status Register (Read-Only)
                                        ; Bits 15:0  = Current Frequency Multiplier (P-State)
                                        ; Bits 47:32 = Voltage Identification (VID) target

MSR_VR_CURRENT_CONFIG       equ 0x601   ; Voltage Regulator Current Configuration (PL4)
                                        ; Bits 12:0  = Current Limit (IccMax) in 1/8 A steps
                                        ; Bit 31     = LOCK BIT (If 1, register is write-locked)

; ============================================================================
; FIXED-FUNCTION ARCHITECTURAL PERFORMANCE COUNTERS
; ============================================================================

IA32_FIXED_CTR_CTRL         equ 0x38D   ; Controls Fixed Counter operating rings
                                        ; Your Hypervisor will use this to enable counting 
                                        ; specifically for Ring 1, 2, and 3 code execution.

IA32_FIXED_CTR0             equ 0x309   ; Counts: INSTR_RETIRED.ANY
                                        ; Increments every single time an instruction finishes 
                                        ; executing completely and safely.

IA32_FIXED_CTR1             equ 0x30A   ; Counts: CPU_CLK_UNHALTED.CORE
                                        ; Tracks actual core clock cycles spent processing.
                                        ; Form: CTR0 / CTR1 = Exact real-time IPC (Instructions Per Cycle).

; ============================================================================
; UNCORE AND COMPONENT ENERGY DOMAINS
; ============================================================================

MSR_DRAM_ENERGY_STATUS      equ 0x619   ; Continuous energy consumption ticker for RAM
                                        ; Measures electrical draw of the memory chips in Joules.
                                        ; If an attacker rapidly charges rows to flip bits, 
                                        ; this counter spikes immediately.

; ============================================================================
; MACHINE CHECK ARCHITECTURE (MCA) TELEMETRY
; ============================================================================

IA32_MCG_STATUS             equ 0x17A   ; Global Machine Check Status Register
                                        ; Bit 1 = EIPV (Error IP Valid: holds the exact instruction 
                                        ;         address that caused the physical panic).
                                        ; Bit 2 = MCIP (Machine Check In Progress status marker).

; ==============================================================================
; INTEL VMCS COMPONENT ENCODING DEFINITIONS (x86_64)
; ==============================================================================

; ------------------------------------------------------------------------------
; 16-Bit Control Fields
; ------------------------------------------------------------------------------
VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER  EQU 0x00000000 ; Didnt got used

; ------------------------------------------------------------------------------
; 16-Bit Guest State Fields
; ------------------------------------------------------------------------------
VMCS_GUEST_ES_SELECTOR                  EQU 0x00000800
VMCS_GUEST_CS_SELECTOR                  EQU 0x00000802
VMCS_GUEST_SS_SELECTOR                  EQU 0x00000804
VMCS_GUEST_DS_SELECTOR                  EQU 0x00000806
VMCS_GUEST_FS_SELECTOR                  EQU 0x00000808
VMCS_GUEST_GS_SELECTOR                  EQU 0x0000080A
VMCS_GUEST_LDTR_SELECTOR                EQU 0x0000080C
VMCS_GUEST_TR_SELECTOR                  EQU 0x0000080E

; ------------------------------------------------------------------------------
; 16-Bit Host State Fields
; ------------------------------------------------------------------------------
VMCS_HOST_ES_SELECTOR                   EQU 0x00000C00
VMCS_HOST_CS_SELECTOR                   EQU 0x00000C02
VMCS_HOST_SS_SELECTOR                   EQU 0x00000C04
VMCS_HOST_DS_SELECTOR                   EQU 0x00000C06
VMCS_HOST_FS_SELECTOR                   EQU 0x00000C08
VMCS_HOST_GS_SELECTOR                   EQU 0x00000C0A
VMCS_HOST_TR_SELECTOR                   EQU 0x00000C0C

; ------------------------------------------------------------------------------
; 64-Bit Control Fields
; ------------------------------------------------------------------------------
VMCS_CTRL_IO_BITMAP_A_ADDRESS           EQU 0x00002000
VMCS_CTRL_IO_BITMAP_B_ADDRESS           EQU 0x00002002
VMCS_CTRL_MSR_BITMAP_ADDRESS            EQU 0x00002004
VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS      EQU 0x00002006
VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS       EQU 0x00002008
VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS      EQU 0x0000200A

; ==============================================================================
; INTEL VMCS COMPONENT ENCODING DEFINITIONS (PART 2)
; ==============================================================================

; ------------------------------------------------------------------------------
; 64-Bit Control Fields
; ------------------------------------------------------------------------------
VMCS_CTRL_EOI_EXIT_BITMAP_0             EQU 0x0000201C
VMCS_CTRL_EOI_EXIT_BITMAP_1             EQU 0x0000201E
VMCS_CTRL_EOI_EXIT_BITMAP_2             EQU 0x00002020
VMCS_CTRL_EOI_EXIT_BITMAP_3             EQU 0x00002022
VMCS_CTRL_VMREAD_BITMAP_ADDRESS         EQU 0x00002026
VMCS_CTRL_VMWRITE_BITMAP_ADDRESS        EQU 0x00002028
VMCS_CTRL_VIRT_EXCEPTION_INFO_ADDRESS   EQU 0x0000202A ; Didnt got used
VMCS_CTRL_XSS_EXITING_BITMAP            EQU 0x0000202C
VMCS_CTRL_ENCLS_EXITING_BITMAP          EQU 0x0000202E
VMCS_CTRL_TSC_MULTIPLIER                EQU 0x00002032

; ------------------------------------------------------------------------------
; 64-Bit Read-Only Data Fields (VM-Exit Information)
; ------------------------------------------------------------------------------
VMCS_GUEST_PHYSICAL_ADDRESS             EQU 0x00002400 ; Didnt got used

; ------------------------------------------------------------------------------
; 64-Bit Guest State Fields
; ------------------------------------------------------------------------------
VMCS_GUEST_VMCS_LINK_POINTER            EQU 0x00002800
VMCS_GUEST_DEBUGCTL                     EQU 0x00002802
VMCS_GUEST_PAT                          EQU 0x00002804
VMCS_GUEST_EFER                         EQU 0x00002806
VMCS_GUEST_PERF_GLOBAL_CTRL             EQU 0x00002808
VMCS_GUEST_PDPTE0                       EQU 0x0000280A
VMCS_GUEST_PDPTE1                       EQU 0x0000280C
VMCS_GUEST_PDPTE2                       EQU 0x0000280E
VMCS_GUEST_PDPTE3                       EQU 0x00002810

; ------------------------------------------------------------------------------
; 64-Bit Host State Fields
; ------------------------------------------------------------------------------
VMCS_HOST_PAT                           EQU 0x00002C00 ; Didnt got used
 
; ==============================================================================
; INTEL VMCS COMPONENT ENCODING DEFINITIONS (PART 3)
; ==============================================================================

; ------------------------------------------------------------------------------
; 32-Bit Control Fields
; ------------------------------------------------------------------------------
VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS       EQU 0x00004000
VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS EQU 0x00004002
VMCS_CTRL_EXCEPTION_BITMAP                      EQU 0x00004004
VMCS_CTRL_VMEXIT_CONTROLS                       EQU 0x0000400C
VMCS_CTRL_VMEXIT_MSR_STORE_COUNT                EQU 0x0000400E
VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT                 EQU 0x00004010
VMCS_CTRL_VMENTRY_CONTROLS                      EQU 0x00004012
VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT                EQU 0x00004014
VMCS_CTRL_VMENTRY_INTERRUPTION_INFO_FIELD       EQU 0x00004016 ; Didnt got used
VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE          EQU 0x00004018
VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH            EQU 0x0000401A

; ------------------------------------------------------------------------------
; 32-Bit Read-Only Data Fields (VM-Exit Information) Didnt got used
; ------------------------------------------------------------------------------
VMCS_VM_INSTRUCTION_ERROR                       EQU 0x00004400 
VMCS_EXIT_REASON                                EQU 0x00004402
VMCS_VMEXIT_INTERRUPTION_INFORMATION            EQU 0x00004404
VMCS_VMEXIT_INTERRUPTION_ERROR_CODE             EQU 0x00004406
VMCS_IDT_VECTORING_INFORMATION                  EQU 0x00004408
VMCS_IDT_VECTORING_ERROR_CODE                   EQU 0x0000440A
VMCS_VMEXIT_INSTRUCTION_LENGTH                  EQU 0x0000440C
VMCS_VMEXIT_INSTRUCTION_INFO                    EQU 0x0000440E

; ------------------------------------------------------------------------------
; 32-Bit Guest State Fields (Segment Limits)
; ------------------------------------------------------------------------------
VMCS_GUEST_ES_LIMIT                             EQU 0x00004800
VMCS_GUEST_CS_LIMIT                             EQU 0x00004802
VMCS_GUEST_SS_LIMIT                             EQU 0x00004804
VMCS_GUEST_DS_LIMIT                             EQU 0x00004806
VMCS_GUEST_FS_LIMIT                             EQU 0x00004808


; ==============================================================================
; INTEL VMCS COMPONENT ENCODING DEFINITIONS (PART 4)
; ==============================================================================

; ------------------------------------------------------------------------------
; 32-Bit Guest & Host State Fields
; ------------------------------------------------------------------------------
VMCS_GUEST_LDTR_ACCESS_RIGHTS           EQU 0x00004820 ; Didnt got used
VMCS_GUEST_TR_ACCESS_RIGHTS             EQU 0x00004822 ; didnt got used
VMCS_GUEST_INTERRUPTIBILITY_STATE       EQU 0x00004824
VMCS_GUEST_ACTIVITY_STATE               EQU 0x00004826
VMCS_GUEST_SMBASE                       EQU 0x00004828
VMCS_GUEST_SYSENTER_CS                  EQU 0x0000482A
VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE   EQU 0x0000482E ; didnt got used
VMCS_HOST_SYSENTER_CS                   EQU 0x00004C00

; ------------------------------------------------------------------------------
; Natural Width Control Fields
; ------------------------------------------------------------------------------
VMCS_CTRL_CR0_GUEST_HOST_MASK           EQU 0x00006000 ; they all didnt get used
VMCS_CTRL_CR4_GUEST_HOST_MASK           EQU 0x00006002
VMCS_CTRL_CR0_READ_SHADOW               EQU 0x00006004
VMCS_CTRL_CR4_READ_SHADOW               EQU 0x00006006
VMCS_CTRL_CR3_TARGET_VALUE_0            EQU 0x00006008
VMCS_CTRL_CR3_TARGET_VALUE_1            EQU 0x0000600A
VMCS_CTRL_CR3_TARGET_VALUE_2            EQU 0x0000600C
VMCS_CTRL_CR3_TARGET_VALUE_3            EQU 0x0000600E

; ------------------------------------------------------------------------------
; Natural Width Read-Only Data Fields (VM-Exit Information)
; ------------------------------------------------------------------------------
VMCS_EXIT_QUALIFICATION                 EQU 0x00006400 ; you can use it to get info
VMCS_VMEXIT_IO_RCX                      EQU 0x00006402
VMCS_VMEXIT_IO_RSX                      EQU 0x00006404
VMCS_VMEXIT_IO_RDI                      EQU 0x00006406
VMCS_VMEXIT_IO_RIP                      EQU 0x00006408
VMCS_EXIT_GUEST_LINEAR_ADDRESS          EQU 0x0000640A

; ------------------------------------------------------------------------------
; Natural Width Guest State Fields (Bases & Registers)
; ------------------------------------------------------------------------------
VMCS_GUEST_CR0                          EQU 0x00006800 ; the CRS didnt got used
VMCS_GUEST_CR3                          EQU 0x00006802
VMCS_GUEST_CR4                          EQU 0x00006804
VMCS_GUEST_ES_BASE                      EQU 0x00006806
VMCS_GUEST_CS_BASE                      EQU 0x00006808
VMCS_GUEST_SS_BASE                      EQU 0x0000680A
VMCS_GUEST_DS_BASE                      EQU 0x0000680C
VMCS_GUEST_FS_BASE                      EQU 0x0000680E
VMCS_GUEST_GS_BASE                      EQU 0x00006810
VMCS_GUEST_LDTR_BASE                    EQU 0x00006812
VMCS_GUEST_IA32_BNDCFGS                 EQU 0x0000682C ; Natural-Width Guest MPX Bounds Configuration
VMCS_GUEST_IA32_RTIT_CTL                EQU 0x0000682E ; Natural-Width Guest Processor Trace Control
VMCS_GUEST_IA32_LBR_CTL                 EQU 0x00006830 ; Natural-Width Guest Last Branch Record Control
VMCS_GUEST_IA32_SPEC_CTRL               EQU 0x00006844 ; Natural-Width Guest Speculation Mitigation Control
VMCS_CTRL_VMX_PREEMPTION_TIMER_VALUE    EQU 0x00004832 ; 32-Bit VMX Preemption Timer Boundary Count

; ==============================================================================
; INTEL VMCS COMPONENT ENCODING DEFINITIONS (PART 5)
; ==============================================================================

; ------------------------------------------------------------------------------
; Natural Width Guest State Fields (Remaining Bases & Registers)
; ------------------------------------------------------------------------------
VMCS_GUEST_TR_BASE                      EQU 0x00006814
VMCS_GUEST_GDTR_BASE                    EQU 0x00006816
VMCS_GUEST_IDTR_BASE                    EQU 0x00006818
VMCS_GUEST_DR7                          EQU 0x0000681A
VMCS_GUEST_RSP                          EQU 0x0000681C
VMCS_GUEST_RIP                          EQU 0x0000681E
VMCS_GUEST_RFLAGS                       EQU 0x00006820
VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS     EQU 0x00006822
VMCS_GUEST_SYSENTER_ESP                 EQU 0x00006824
VMCS_GUEST_SYSENTER_EIP                 EQU 0x00006826

; ------------------------------------------------------------------------------
; Natural Width Host State Fields (Registers & Stack)
; ------------------------------------------------------------------------------
VMCS_HOST_CR0                           EQU 0x00006C00
VMCS_HOST_CR3                           EQU 0x00006C02
VMCS_HOST_CR4                           EQU 0x00006C04
VMCS_HOST_FS_BASE                       EQU 0x00006C06
VMCS_HOST_GS_BASE                       EQU 0x00006C08
VMCS_HOST_TR_BASE                       EQU 0x00006C0A
VMCS_HOST_GDTR_BASE                     EQU 0x00006C0C
VMCS_HOST_IDTR_BASE                     EQU 0x00006C0E
VMCS_HOST_SYSENTER_ESP                  EQU 0x00006C10
VMCS_HOST_SYSENTER_EIP                  EQU 0x00006C12
VMCS_HOST_RSP                           EQU 0x00006C14
VMCS_HOST_RIP                           EQU 0x00006C16
VMCS_GUEST_TR_LIMIT                     EQU 0x0000481C ; 32-Bit Guest TR Limit control register encoding

; ==============================================================================
; INTEL VMX GUEST CET (CONTROL-FLOW ENFORCEMENT TECHNOLOGY) FIELD ENCODINGS
; ==============================================================================
VMCS_GUEST_S_CET                                EQU 0x0000686C ; Natural-Width Guest Supervisor CET Control Register
VMCS_GUEST_SSP                                  EQU 0x0000686E ; Natural-Width Guest Shadow Stack Pointer
VMCS_GUEST_INTR_SSP_TABLE                       EQU 0x00006870 ; Natural-Width Guest Interrupt Shadow Stack Table Pointer


; ==============================================================================
; INTEL VMCS ADVANCED COMPONENT ENCODINGS (SUPPLEMENTAL MASTER LIST)
; ==============================================================================

; ------------------------------------------------------------------------------
; 16-Bit Control Fields (Advanced Virtualization) ; didnt got used
; ------------------------------------------------------------------------------
VMCS_CTRL_GUEST_CORE_ID                 EQU 0x00000006 ; Guest Core Tracking Index

; ------------------------------------------------------------------------------
; 64-Bit Control Fields (Tertiary Controls & Extended Paging)
; ------------------------------------------------------------------------------
VMCS_CTRL_TERTIARY_VM_EXEC_CONTROLS     EQU 0x00002034 ; CRITICAL: Tertiary Execution Bitmask pointer (Didnt got used)
VMCS_CTRL_HLAT_POINTER                  EQU 0x00002040 ; Hypervisor-Managed Linear Address Translation Pointer
VMCS_CTRL_PASID_TRANSLATION_TABLE       EQU 0x00002042 ; Linear address space tracking association table (Didnt got used)

; ------------------------------------------------------------------------------
; 64-Bit Guest State Fields (Advanced Security / Protection Keys)
; ------------------------------------------------------------------------------
VMCS_GUEST_IA32_PKRU                    EQU 0x00002812 ; Guest Protection Key Register for User Pages 
VMCS_GUEST_IA32_PASID                   EQU 0x00002814 ; Guest Process Address Space ID MSR tracking (all of them didnt got used)
VMCS_GUEST_SHARED_VIRT_MEM_POINTER      EQU 0x00002816 ; Shared Virtual Memory Pointer block

; ------------------------------------------------------------------------------
; 64-Bit Host State Fields (Advanced Security / Protection Keys)
; ------------------------------------------------------------------------------
VMCS_HOST_IA32_PKRS                    EQU 0x00002C06 ; Host Supervisor Protection Key tracking register (didnt got used)

; ------------------------------------------------------------------------------
; 32-Bit Control Fields (Tertiary, Virtual Interrupts & Exceptions)
; ------------------------------------------------------------------------------
VMCS_CTRL_TERTIARY_PROC_BASED_CONTROLS  EQU 0x0000402A ; Tertiary Processor-Based Execution Controls Bitmask
VMCS_CTRL_NOTIFY_WINDOW                 EQU 0x0000402C ; Notification window for VM-Exits (didnt got used)
VMCS_CTRL_SECONDARY_VM_EXEC_CONTROLS    EQU 0x0000401E ; 32-Bit Secondary Processor-Based Execution Profile
VMCS_CTRL_SPECULATION_CTRL_BITMAP       EQU 0x00004030 ; Hard intercepts for guest mitigation commands (didnt got used)

; ------------------------------------------------------------------------------
; 32-Bit VM-Exit Information Fields (Extended Logging Telemetry)
; ------------------------------------------------------------------------------
VMCS_VMEXIT_MTF_QUALIFICATION           EQU 0x00004410 ; Monitor Trap Flag debug status detail (didnt got used)
VMCS_VMEXIT_TERTIARY_EXIT_REASON        EQU 0x00004412 ; Detailed classification for tertiary exit conditions (didnt got used)

; ------------------------------------------------------------------------------
; Natural Width Control & State Fields (Advanced Shadow Pages)
; ------------------------------------------------------------------------------
VMCS_CTRL_HLAT_RESERVED_SHADOW          EQU 0x00006010 ; Shadow verification vector for secure paging layers (didnt got used)
VMCS_GUEST_IA32_S_CET_BASE              EQU 0x00006828 ; Guest Supervisor Mode CET Shadow Stack base pointer (didnt got used)
VMCS_HOST_IA32_S_CET_BASE               EQU 0x00006C18 ; Host Supervisor Mode CET Shadow Stack base pointer  (didnt got used)

; ==============================================================================
; INTEL VMCS FINAL ARCHITECTURAL COMPONENTS (100% EXHAUSTIVE COMPLETION)
; ==============================================================================

; --- 16-Bit Control Fields (Advanced APIC & Virtualization Tracking) ---
VMCS_CTRL_POSTED_INTERRUPT_STATUS_VECTOR        EQU 0x00000002 ; Overlapped interrupt notification vector 
VMCS_GUEST_INTERRUPT_STATUS                     EQU 0x00000810 ; Tracking virtual execution interrupt requests
VMCS_GUEST_PML_INDEX                            EQU 0x00000812 ; Page Modification Log tracker index

; --- 64-Bit Control Fields (Advanced Hardware Monitoring Acceleration) ---
VMCS_CTRL_VIRTUAL_APIC_ADDRESS                  EQU 0x00002012 ; Direct hardware page for Virtual APIC tracking
VMCS_CTRL_APIC_ACCESS_ADDRESS                   EQU 0x00002014 ; Memory-mapped layout for APIC access acceleration
VMCS_CTRL_POSTED_INTERRUPT_DESC_ADDRESS         EQU 0x00002016 ; Physical pointer to posted descriptor structure (didnt got used)
VMCS_CTRL_VMFUNC_CONTROLS                       EQU 0x00002018 ; Allowed VMFUNC instruction parameters
VMCS_CTRL_PML_ADDRESS                           EQU 0x0000200E ; Base physical address for Page Modification Logging

; --- 32-Bit Control Fields (Dynamic Interception & Extended Filtering) ---
VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK             EQU 0x00004006 ; Isolates precise bits during guest page fault loops
VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH            EQU 0x00004008 ; Evaluates exception signature before exit handling
VMCS_CTRL_CR3_TARGET_COUNT                      EQU 0x0000400A ; Maximum target list boundary for valid CR3 values
VMCS_CTRL_TPR_THRESHOLD                         EQU 0x0000401C ; Task Priority Register intercept boundary limits
VMCS_CTRL_PLE_GAP                               EQU 0x00004020 ; Pause Loop Exiting parameter window
VMCS_CTRL_PLE_WINDOW                            EQU 0x00004022 ; Pause Loop Exiting execution loop duration timer

; ==============================================================================
; ADVANCED VM-EXIT CONTROLS & LIFECYCLE BOUNDARIES (EQU SUPPLEMENT)
; ==============================================================================
VMCS_CTRL_SECONDARY_VM_EXIT_CONTROLS            EQU 0x00002044 ; 64-Bit Secondary VM-Exit Controls (VERIFIED SILICON VALUE)
VMCS_CTRL_TSC_OFFSET                            EQU 0x00002010
VMCS_CTRL_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS   EQU 0x00002016
VMCS_CTRL_EXECUTIVE_VMCS_POINTER                EQU 0x0000200C

; ==============================================================================
;                  INTEL x86_64 PHYSICAL MEMORY ARCHITECTURE MAP
; ==============================================================================
; This blueprint maps the absolute hardware boundaries of the physical RAM.
; Enforced and utilized by the Type-1 Hypervisor core during all phases.
; ==============================================================================

; [1] LOW STERILE ZONE (Conventional Memory Space)
; ------------------------------------------------------------------------------
; Range: 0x00001000 — 0x0009FFFF
; Status: Safe Real RAM / Absolutes Isolation Buffer Zone
; Use:   Bootstrap Page Tables (PML4), VMCS/VMXON blocks, Master MSR Bitmaps, 
;        and the Stackless Execution RSP Vector Anchor.
; Note:  The lower 4KB (0x00000000 — 0x00000FFF) is left clean for IVT/BIOS data.

; [2] UPPER MEMORY AREA (UMA - Hardware Mapped / Non-RAM Territory)
; ------------------------------------------------------------------------------
; Status: Hardware-Mapped I/O (MMIO Boundary) — DO NOT USE FOR STORAGE CORRUPTIONS
; Enclaves:
;   A) Video RAM / VGA Text Mode Buffer:  0x000A0000 — 0x000BFFFF [Debug Frame Dump]
;   B) Option ROMs / Controller Mapping:  0x000C0000 — 0x000DFFFF [Read-Only Hardware]
;   C) System BIOS / UEFI Firmware Core:  0x000E0000 — 0x000FFFFF [System Reset Vector]

; [3] EXTENDED MEMORY REGION (High RAM Ocean)
; ------------------------------------------------------------------------------
; Range: 0x00100000 — 0x000EFFFFFFF
; Status: Solid Physical Real RAM / High-Speed Execution Space
; Use:   The primary cage for the Guest OS (Windows/Linux Kernel). Monitored 
;        and isolated dynamically using Identity-Mapped Extended Page Tables (EPT).

; [4] THE PCI HOLE / SYSTEM MMIO WINDOW
; ------------------------------------------------------------------------------
; Range: 0x000F0000000 — 0x000FFFFFFFF
; Status: CRITICAL SILICON BARRIER — ABSOLUTELY FORBIDDEN FOR RAM ALLOCATION
; Use:   Hardwired into motherboard components, local APIC matrices, and device MMIO.

; [5] UPPER EXTENDED RAM SPACE (Above 4GB Boundary)
; ------------------------------------------------------------------------------
; Range: 0x00100000000 — [Maximum Physical RAM Limit]
; Status: Fully Accessible 64-Bit Extended Paging Memory Space
; Use:   Dynamic EPT Paging expansion layers to support massive Guest memory configurations.
; ==============================================================================


;bootloader finish! part 1 start:

;Remember free memory space: 0x1000 to 0x9FFFF 
;this is how the VMWRITE works: VMWRITE Field_Encoding, Source_Register
Hypervisor_start:
trying_vmptrld:
mov rax, 0x01B22FE4 
mov cr4, rax

mov rax, 0x01
mov dq [Hypervisor_start], rax ;it is a verfication code to clean up all of the code here so 
                               ;we going to do verify if the code are there we cleaning all of the code 
                               ;for the l1 instruction cache so everything going to be clean and smooth
mov eax, 0x00B00408
mov dr7, eax

;Before we cleaning the bootloader so there gonna be clean time we need to rebuild the GDT:
VMCS_HYPERVISOR_GDT_BASE                        EQU 0x0004C000 ; Secure 4KB page for our permanent 64-bit GDT layout
VMCS_HYPERVISOR_GDTR_POINTER                    EQU 0x0004C500 ; Dedicated scratchpad block for the 10-byte GDTR register

Absolute_Sanitization_GDT_Relocation:
    ; -------------------------------------------------------------------------
    ; 1. Clear exactly 64 bytes for our monolithic descriptors (8 entries * 8 bytes)
    ; -------------------------------------------------------------------------
    mov edi, VMCS_HYPERVISOR_GDT_BASE   ; Destination Base RAM address: 0x4C000
    xor eax, eax                        ; Establish sterile zero reference anchor
    mov rcx, 8                          ; Allocate 8 quadwords footprint
    rep stosq                           ; Wipe memory block completely and cleanly

    ; -------------------------------------------------------------------------
    ; 2. Inject bare-metal 64-bit descriptors directly into the new 0x4C000 page
    ; -------------------------------------------------------------------------
    mov edi, VMCS_HYPERVISOR_GDT_BASE
    
    ; Entry 0: Null Descriptor (Enforced by Intel Silicon layout)
    mov qword [rdi + 0],  0x0000000000000000 
    
    ; Entry 1: Hypervisor Code Segment Descriptor (64-Bit, Ring 0, Present, Executable)
    mov qword [rdi + 8],  0x00209A0000000000 
    
    ; Entry 2: Hypervisor Data Segment Descriptor (64-Bit, Ring 0, Present, Read/Write)
    mov qword [rdi + 16], 0x0000920000000000 

    ; [Entries 3 and 4 are structurally reserved here 16-byte TSS Matrix later]

    ; -------------------------------------------------------------------------
    ; 3. Construct the strict 10-byte GDTR pointer layout in physical memory
    ; -------------------------------------------------------------------------
    mov rbx, VMCS_HYPERVISOR_GDTR_POINTER ; Address location: 0x4C500
    mov word  [rbx], 47                 ; Limit: (6 entries * 8 bytes) - 1 = 47 (0x2F)
    mov qword [rbx + 2], VMCS_HYPERVISOR_GDT_BASE ; Base: Points directly back to 0x4C000

    ; -------------------------------------------------------------------------
    ; 4. Force atomic silicon swap execution layout
    ; -------------------------------------------------------------------------
    lgdt [rbx]                          ; Reload the processor layout architecture instantly

;now after we rebuild our LGDT we can delete everything:
xor eax, eax 
mov rdi, 0x7C00
mov rcx, 64
stosq

mov rdi, 0x4000
mov rcx, 0x400 
rep stosq  

mov ebx, 0x10000 
mov dword [rbx], eax        
vmxon [rbx]    


mov ecx, 0x5000
mov dword [ecx], eax
vmclear [rcx]
vmptrld [rcx]

jmp $ ; DEBUGGING

; PART 2 HOST:
Host_area:    

    mov rax, VMCS_HOST_RSP          ;0x00006C14 
    mov rbx, 0x45000
    vmwrite rax, rbx          


    mov eax, VMCS_HOST_CR0          ;0x00006C00
    mov rbx, 0x80010031
    vmwrite rax, rbx 

    mov rax, VMCS_HOST_CR4          ;0x00006C04
    mov rbx, cr4
    or rbx, 0x01B22FE4              
    mov cr4, rbx
    vmwrite rax, rbx    

.continue:

    mov rax, 0x8000000000001000   
    mov cr3, rax                     ; PML4 

    mov eax, VMCS_HOST_CR3           ; 0x00006c02
    mov rbx, cr3
    vmwrite rax, rbx   

    mov eax, VMCS_HOST_RIP           ; 0x00006C16 
    mov ebx, VM_Exit_Handler                                 
    vmwrite rax, rbx

mov rbx, cs
and rbx, ~7                  
mov rax, VMCS_HOST_CS_SELECTOR          ; 0x00000C02
vmwrite rax, rbx           

mov rbx, ds
and rbx, ~7
mov rax, VMCS_HOST_DS_SELECTOR          ; 0x00000C06
vmwrite rax, rbx

mov rbx, es
and rbx, ~7
mov rax, VMCS_HOST_ES_SELECTOR          ; 0x00000C00
vmwrite rax, rbx

; ==============================================================================
; HARDWARE-ENFORCED VMX ARCHITECTURE INITIALIZATION LOOP
; ==============================================================================

setup_host_and_execution_controls:
    ; 1. Initialize Host Segment Selectors
    mov rbx, ss
    and rbx, ~7                         ; Strip Request Privilege Level (RPL) bits
    mov rax, VMCS_HOST_SS_SELECTOR      ; Encoding: 0x00000C04
    vmwrite rax, rbx

    xor rbx, rbx                        ; Clear selector for unused segment blocks
    mov rax, VMCS_HOST_FS_SELECTOR      ; Encoding: 0x00000C08
    vmwrite rax, rbx

    mov rax, VMCS_HOST_GS_SELECTOR      ; Encoding: 0x00000C0A
    vmwrite rax, rbx

    ; 2. Neutralize Legacy SysEnter Control Registers
    xor rbx, rbx                        ; Zero-out legacy execution paths
    mov rax, VMCS_HOST_SYSENTER_CS      ; Encoding: 0x00004C00
    vmwrite rax, rbx
    
    mov rax, VMCS_HOST_SYSENTER_ESP     ; Encoding: 0x00006C10
    vmwrite rax, rbx
    
    mov rax, VMCS_HOST_SYSENTER_EIP     ; Encoding: 0x00006C12
    vmwrite rax, rbx

    ; 3. Configure Active Task Register Selector
    mov rbx, 0x0008                     ; Set direct selector index pointing to Host GDT TSS descriptor
    mov rax, VMCS_HOST_TR_SELECTOR      ; Encoding: 0x00000C0C
    vmwrite rax, rbx

    ; 5. Sync Extended Feature Enable Register (IA32_EFER MSR)
    mov ecx, 0xC0000080                 ; MSR address parameter for IA32_EFER
    rdmsr                        
    shl rdx, 32
    or rdx, rax                         ; RDX now holds the full 64-bit combined MSR value
    
    mov rax, VMCS_HOST_IA32_EFER        ; Encoding: 0x00004C02
    vmwrite rax, rdx             
 
    ; 6. Commit Global VMX Transition Controls
    mov rbx, 0x00008200                 ; VM-Exit Control features configuration bitmask
    mov rax, VMCS_CTRL_VMEXIT_CONTROLS  ; Encoding: 0x0000400C (CORRECTED PARAMETER ORDER)
    vmwrite rax, rbx

    ; 1. Initialize Host Base Address Registers (FS and GS Bases)
    ; Replacing the unstable RCX-driven loop with direct, hardware-safe commits
    xor ecx, ecx                        ; Clear RCX to serve as a zero-base template
    
    mov rax, VMCS_HOST_FS_BASE          ; Encoding: 0x00006C06
    vmwrite rax, rcx            

    mov rax, VMCS_HOST_GS_BASE          ; Encoding: 0x00006C08
    vmwrite rax, rcx            

    ; 2. Configure Host Task Register Base Address
    mov rax, VMCS_HOST_TR_BASE          ; Encoding: 0x00006C0A
    vmwrite rax, rcx            

    ; 3. Extract and Commit Active Host GDTR Base Pointer
    mov rax, VMCS_HOST_GDTR_BASE        ; Encoding: 0x00006C0C 
    sub rsp, 16                         ; Enforce strict 16-byte stack alignment rules
    sgdt [rsp]                          ; Store active 80-bit GDTR descriptor block
    mov rbx, [rsp + 2]                  ; Extract the absolute 64-bit linear base address
    add rsp, 16                         ; Restore stack layout instantly
    vmwrite rax, rbx             

    ; 4. Lock Down Exception Virtualization Intercept Bitmask
    mov rax, VMCS_CTRL_EXCEPTION_BITMAP ; Encoding: 0x00004004 (Targeted diagnostic trap)
    mov rbx, 0x00227558                 ; Hard-intercept mask for internal page/debug faults
    vmwrite rax, rbx             

    ; 6. Commit Active Host Interrupt Descriptor Table Base (IDTR)
    mov rax, VMCS_HOST_IDTR_BASE        ; Encoding: 0x00006C0E
    lea rbx, [rel host_idt_table]       ; Resolve absolute address of host exception handlers
    vmwrite rax, rbx                        

    ; 7. Synchronize Host VMX Extended Feature Enable Register (IA32_EFER)
    mov ecx, 0xC0000080                 ; IA32_EFER MSR Address pointer
    rdmsr                       
    shl rdx, 32
    or  rdx, rax                        ; RDX now securely bundles the full 64-bit EFER layout
    mov rax, VMCS_HOST_IA32_EFER        ; Encoding: 0x00004C02
    vmwrite rax, rdx                    ; CORRECTED: Written from RDX context link

    ; 8. Commit Host Memory Type Range Control (IA32_PAT)
    mov ecx, 0x00000277                 ; IA32_CR_PAT MSR Address pointer
    rdmsr
    shl rdx, 32
    or  rdx, rax
    mov rax, VMCS_HOST_IA32_PAT         ; Encoding: 0x00002C00
    vmwrite rax, rdx            
      
    ; 9. Bind Host Core Architectural Performance Counter Control
    mov ecx, 0x0000038F                 ; IA32_PERF_GLOBAL_CTRL MSR Address pointer
    rdmsr                       
    shl rdx, 32                  
    or  rdx, rax               
    mov rax, VMCS_HOST_IA32_PERF_GLOBAL_CTRL ; Encoding: 0x00002C04          
    vmwrite rax, rdx             

    ; 10. Enforce Control-Flow Enforcement Technology (CET) Protection Layers
    ; Replacing loop indices with robust unrolled configurations to block stack spills
    xor rcx, rcx                        ; Zero-out validation matrix template
    
    mov rax, VMCS_HOST_IA32_S_CET       ; Encoding: 0x00006C18
    vmwrite rax, rcx          

    ; 11. Finalize MSR Lifecycle Boundaries
    mov rax, VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT ; Encoding: 0x00004010
    mov rcx, 1                          ; Establish single tracking boundary slot
    vmwrite rax, rcx        

    jmp $ ;DEBUGGING HOST 

    ;----- HOST FINISH DEBUGGING ONLY -----

;----------------- GUEST INITIALIZATION AND VMCS CONFIGURATION -------------

; ==============================================================================
; INTEL VMX GUEST-STATE ARCHITECTURE INITIALIZATION (PART 1)
; ==============================================================================

Guest_area:
    ; -------------------------------------------------------------------------
    ; Part 1: Intercepting and Storing the Guest IDTR Base Address & Core Masks
    ; -------------------------------------------------------------------------
    sub rsp, 16                         ; Enforce strict 16-byte stack alignment rules
    sidt [rsp]                          ; Store active IDTR descriptor block
    mov rbx, [rsp + 2]                  ; Extract the absolute 64-bit linear base address
    add rsp, 16                         ; Restore temporary stack layout instantly

    mov rax, VMCS_GUEST_IDTR_BASE       ; Encoding: 0x00006818 
    vmwrite rax, rbx                                   

    ; Capturing raw encodings 0x2000 and 0x2002 (Physical I/O Intercept Bitmaps)
    mov rbx, 0xFFFFFFFFFFFFFFFF         ; Hard-intercept all primary and secondary I/O ports
    mov rax, VMCS_CTRL_IO_BITMAP_A_ADDRESS ; Encoding: 0x00002000 
    vmwrite rax, rbx             

    mov rax, VMCS_CTRL_IO_BITMAP_B_ADDRESS ; Encoding: 0x00002002 
    vmwrite rax, rbx             

    mov rax, VMCS_CTRL_CR3_TARGET_COUNT ; Encoding: 0x0000400A 
    xor rbx, rbx                        ; Zero-out target count to force exits on unmapped CR3 switches
    vmwrite rax, rbx            

    ; -------------------------------------------------------------------------
    ; Part 2: Enforcing Instruction Pointer (RIP), Stack Pointer (RSP), and RFLAGS
    ; -------------------------------------------------------------------------
    lea rbx, [rel Guest_Code_Entry]     ; Enforce RIP-Relative addressing to prevent memory shifting
    mov rax, VMCS_GUEST_RIP             ; Encoding: 0x0000681E 
    vmwrite rax, rbx            

    xor rbx, rbx                        ; Clear Guest initial stack pointer context
    mov rax, VMCS_GUEST_RSP             ; Encoding: 0x0000681C 
    vmwrite rax, rbx           

    mov rbx, 0x00000002                 ; Enforce mandatory Intel bit alignment rules for RFLAGS
    mov rax, VMCS_GUEST_RFLAGS          ; Encoding: 0x00006820 
    vmwrite rax, rbx           

    ; -------------------------------------------------------------------------
    ; Part 3: Architecting Segment Isolation & Access Rights Protection Rules
    ; -------------------------------------------------------------------------
    
    ; 1. Configure active protected mode execution segments (Unlocking Long Mode)
    mov rbx, 0x0000209B                 ; Code Segment (CS) AR: Present + Ring 0 + Code + Long Mode
    mov rax, VMCS_GUEST_CS_ACCESS_RIGHTS ; Encoding: 0x00004816
    vmwrite rax, rbx            

    mov rbx, 0x00004093                 ; Stack Segment (SS) AR: Present + Ring 0 + Data + Read/Write
    mov rax, VMCS_GUEST_SS_ACCESS_RIGHTS ; Encoding: 0x00004818
    vmwrite rax, rbx

    ; 2. Enforce absolute isolation on remaining data segments (Unusable State)
    ; Replacing the unstable loop sequence with direct, hardware-safe unrolled commits
    mov rbx, 0x00010000                 ; Set Bit 16 (Segment Unusable Attribute Flag)
    
    mov rax, VMCS_GUEST_ES_ACCESS_RIGHTS ; Encoding: 0x00004814
    vmwrite rax, rbx            

    mov rax, VMCS_GUEST_DS_ACCESS_RIGHTS ; Encoding: 0x0000481A
    vmwrite rax, rbx            

    mov rax, VMCS_GUEST_FS_ACCESS_RIGHTS ; Encoding: 0x0000481C
    vmwrite rax, rbx            

    mov rax, VMCS_GUEST_GS_ACCESS_RIGHTS ; Encoding: 0x0000481E
    vmwrite rax, rbx            

; ==============================================================================
; INTEL VMX GUEST-STATE ARCHITECTURE INITIALIZATION (PART 2)
; ==============================================================================

Guest_state_segments_and_registers:
    ; -------------------------------------------------------------------------
    ; Part 4: Forcing Hardware Segment Selector Constraints via Silicon Register Mapping
    ; -------------------------------------------------------------------------
    xor rcx, rcx                        ; Enforce absolute zero context for data selectors
    
    mov rbx, cs
    and rbx, ~3                         ; Sanitize CPL/RPL Privilege Bits (Force Ring 0 baseline)
    
    mov rax, VMCS_GUEST_CS_SELECTOR     ; Encoding: 0x00000802
    vmwrite rax, rbx

    mov rax, VMCS_GUEST_SS_SELECTOR     ; Encoding: 0x00000804
    vmwrite rax, rbx

    mov rax, VMCS_GUEST_ES_SELECTOR     ; Encoding: 0x00000800
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_DS_SELECTOR     ; Encoding: 0x00000806
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_FS_SELECTOR     ; Encoding: 0x00000808
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_GS_SELECTOR     ; Encoding: 0x0000080A
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_LDTR_SELECTOR   ; Encoding: 0x0000080C
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_TR_SELECTOR     ; Encoding: 0x0000080E
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_INTERRUPT_STATUS ; Encoding: 0x00000810
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Part 5: Establishing Hardwired Secondary 64-Bit System Registers (Hex Dumps)
    ; -------------------------------------------------------------------------
    mov rbx, 0xFFFFFFFFFFFFFFFF         ; Non-functional shadow reference mapping pointer
    mov rax, VMCS_GUEST_VMCS_LINK_POINTER ; Encoding: 0x00002800
    vmwrite rax, rbx             

    mov rax, VMCS_GUEST_DEBUGCTL        ; Encoding: 0x00002802
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_PAT             ; Encoding: 0x00002804
    vmwrite rax, rcx             

    mov rbx, 0x0000000000000D01         ; Enforce Long Mode Active (LME=1, LMA=1, SCE=1 flags combined)
    mov rax, VMCS_GUEST_EFER            ; Encoding: 0x00002806
    vmwrite rax, rbx             

    mov rax, VMCS_GUEST_PERF_GLOBAL_CTRL ; Encoding: 0x00002808
    vmwrite rax, rcx             

    ; Note: PDPTE fields are omitted by the CPU in 64-bit mode, initialized to zero for security
    mov rax, VMCS_GUEST_PDPTE0          ; Encoding: 0x0000280A
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_PDPTE1          ; Encoding: 0x0000280C
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_PDPTE2          ; Encoding: 0x0000280E
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_PDPTE3          ; Encoding: 0x00002810
    vmwrite rax, rcx

; ==============================================================================
; INTEL VMX GUEST-STATE ARCHITECTURE INITIALIZATION (PART 3)
; ==============================================================================

Guest_Memory_Limits_Bases_And_Execution_Controls:
    ; -------------------------------------------------------------------------
    ; Part 6: Defining Flat Memory Addressing Boundaries (Limits and Bases)
    ; -------------------------------------------------------------------------
    mov rbx, 0xFFFFFFFF                 ; Max 32-bit limit value for flat memory segments
    
    mov rax, VMCS_GUEST_CS_LIMIT        ; Encoding: 0x00004802 (CORRECTED from 0x4402)
    vmwrite rax, rbx             

    mov rax, VMCS_GUEST_DS_LIMIT        ; Encoding: 0x00004806 (CORRECTED from 0x4406)
    vmwrite rax, rbx             

    mov rax, VMCS_GUEST_SS_LIMIT        ; Encoding: 0x00004804 (CORRECTED from 0x4408)
    vmwrite rax, rbx             

    ; Restoring strict zero context for unusable data segments limits
    xor ecx, ecx                        
    
    mov rax, VMCS_GUEST_ES_LIMIT        ; Encoding: 0x00004800
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_FS_LIMIT        ; Encoding: 0x00004808
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_GS_LIMIT        ; Encoding: 0x0000480A
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_LDTR_LIMIT      ; Encoding: 0x0000480C
    vmwrite rax, rcx             

    ; Enforcing zero-base linear execution space for flat 64-bit mode layout
    mov rax, VMCS_GUEST_ES_BASE         ; Encoding: 0x00006806 
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_CS_BASE         ; Encoding: 0x00006808
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_SS_BASE         ; Encoding: 0x0000680A
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_DS_BASE         ; Encoding: 0x0000680C
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_FS_BASE         ; Encoding: 0x0000680E
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_GS_BASE         ; Encoding: 0x00006810
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_LDTR_BASE       ; Encoding: 0x00006812
    vmwrite rax, rcx             

    mov rax, VMCS_GUEST_TR_BASE         ; Encoding: 0x00006814
    vmwrite rax, rcx             

    ; Neutralizing execution sub-registers and hardware trace components
    mov rax, VMCS_GUEST_SYSENTER_CS     ; Encoding: 0x0000482A
    vmwrite rax, rcx             
 
    mov rax, VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS ; Encoding: 0x00006822
    vmwrite rax, rcx             
 
    mov rax, VMCS_GUEST_SYSENTER_ESP    ; Encoding: 0x00006824
    vmwrite rax, rcx             
 
    mov rax, VMCS_GUEST_SYSENTER_EIP    ; Encoding: 0x00006826
    vmwrite rax, rcx             

    ; -------------------------------------------------------------------------
    ; Part 7: Extracting and Mirroring Descriptor Tables (GDTR/IDTR)
    ; -------------------------------------------------------------------------
    sub rsp, 16                         ; Maintain strict 16-byte stack frame alignment
    sgdt [rsp]                          ; Capture host GDT layout as base template for the guest
    mov rbx, [rsp + 2]                  ; Extract absolute 64-bit linear base address
    movzx rdx, word [rsp]               ; Extract 16-bit GDT structural limit size boundary
    add rsp, 16                         ; Clean temporary stack space instantly

    mov rax, VMCS_GUEST_GDTR_BASE       ; Encoding: 0x00006816
    vmwrite rax, rbx

    mov rax, VMCS_GUEST_GDTR_LIMIT      ; Encoding: 0x00004810 (CORRECTED from 0x4410)
    vmwrite rax, rdx

    mov rax, VMCS_GUEST_IDTR_LIMIT      ; Encoding: 0x00004812 (CORRECTED from 0x4412)
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Part 8: Silicon Core Infrastructure Controls & Security Enclaves
    ; -------------------------------------------------------------------------
    mov rbx, 0x00000400                 ; Enforce default standard hardware bit state for DR7
    mov rax, VMCS_GUEST_DR7             ; Encoding: 0x0000681A (CORRECTED from 0x4828)
    vmwrite rax, rbx            

    mov rax, VMCS_GUEST_INTERRUPTIBILITY_STATE ; Encoding: 0x00004824
    vmwrite rax, rcx             

    ; Note: Link pointer field is a 64-bit component initialized to zero for compliance
    mov rax, VMCS_CTRL_VMCS_LINK_POINTER ; Encoding: 0x00002800 (CORRECTED from 0x400E)
    mov rbx, 0xFFFFFFFFFFFFFFFF  
    vmwrite rax, rbx             
 
    ; Zero-out modern hardware tracking mitigation layers to enforce raw sandbox baseline
    ; (Addresses: 0x682C, 0x682E, 0x6830 matching Intel architectural specifications)
    mov rax, VMCS_GUEST_IA32_BNDCFGS                  ; Encoding: 0x0000682C
    vmwrite rax, rcx             
 
    mov rax, VMCS_GUEST_IA32_RTIT_CTL                 ; Encoding: 0x0000682E
    vmwrite rax, rcx             
 
    mov rax, VMCS_GUEST_IA32_LBR_CTL                 ; Encoding: 0x00006830
    vmwrite rax, rcx             

; ==============================================================================
; ADVANCED GUEST SYSTEM REGISTERS & SHADOW TRACKING DEFINITIONS (EQU SUPPLEMENT)
; ==============================================================================

; ==============================================================================
; INTEL VMX GUEST-STATE ARCHITECTURE INITIALIZATION (PART 4)
; ==============================================================================

Guest_Execution_Context_And_Speculation_Controls:
    xor ecx, ecx                        ; Establish absolute sterile zero context for security blocks

    ; -------------------------------------------------------------------------
    ; Part 9: Locking Down Guest Control-Flow Enforcement Technology (CET)
    ; -------------------------------------------------------------------------
    ; Unrolling the loops to fix the critical argument inversion bug (Field vs Value)
    mov rax, VMCS_GUEST_S_CET           ; Encoding: 0x0000686C
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_SSP             ; Encoding: 0x0000686E
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_INTR_SSP_TABLE  ; Encoding: 0x00006870
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Part 10: Enforcing Guest Activity States & SMBASE Mitigation
    ; -------------------------------------------------------------------------
    mov rax, VMCS_GUEST_ACTIVITY_STATE  ; Encoding: 0x00004826
    vmwrite rax, rcx

    mov rax, VMCS_GUEST_SMBASE          ; Encoding: 0x00004828 (Safe isolation allocation)
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Part 11: Speculation Defenses & VMX Architectural Timers
    ; -------------------------------------------------------------------------
    mov rax, VMCS_GUEST_IA32_SPEC_CTRL  ; Encoding: 0x00006844 (VERIFIED AUTHENTIC SILICON VALUE)
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VMX_PREEMPTION_TIMER_VALUE ; Encoding: 0x00004832
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Part 12: Neutralizing Virtual Interrupt and Extended Tracking Arrays
    ; -------------------------------------------------------------------------
    mov rax, VMCS_GUEST_PML_INDEX       ; Encoding: 0x00000812
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; Debug Boundary Checkpoint
    ; -------------------------------------------------------------------------
    jmp $                               ; Localized infinite loop for runtime verification

    ;this where you stop tommorow you gonna keep going good night
    
;GUEST FINISH! 

; ==============================================================================
; INTEL VMX EXECUTION CONTROL FIELDS INITIALIZATION (MASTER BLUEPRINT)
; ==============================================================================

VM_Execution_Control_Fields:
    ; -------------------------------------------------------------------------
    ; 1. Configure Pin-Based VM-Execution Controls
    ; -------------------------------------------------------------------------
    mov ecx, 0x0000048D                 ; IA32_VMX_TRUE_PINBASED_CTLS MSR
    rdmsr                       
    ; Formula: Value = (Allowed_1_Bits & Requested_Bits) | Mandatory_1_Bits
    and rdx, 0x000000A9                 ; Request continuous hardware clock tracking profiles
    or  rax, rdx                        ; RAX now holds the solid validated bitmask
    
    mov rcx, VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS ; Encoding: 0x00004000
    vmwrite rcx, rax         
          
    ; -------------------------------------------------------------------------
    ; 2. Configure Primary Processor-Based VM-Execution Controls
    ; -------------------------------------------------------------------------
    mov ecx, 0x0000048E                 ; IA32_VMX_TRUE_PROCBASED_CTLS MSR
    rdmsr                           
    mov r8, rdx                         ; R8 = Allowed 1 Bits tracking mask
    
    mov r9d, 0x11016280                 ; Requested: HLT, INVLPG, CR3, DR, I/O, MSR Bitmaps
    and r8, r9                          ; Enforce only hardware-allowed bits
    or  rax, r8                         ; Merge mandatory 1 bits with sanitized choices
    
    mov rcx, VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS ; Encoding: 0x00004002
    vmwrite rcx, rax           

    ; -------------------------------------------------------------------------
    ; 3. Configure Secondary Processor-Based VM-Execution Controls
    ; -------------------------------------------------------------------------
    mov ecx, 0x0000048B                 ; IA32_VMX_PROCBASED_CTLS2 MSR address pointer
    rdmsr                          
    mov r8, rdx                         ; R8 = Allowed 1 Bits baseline tracking mask
    
    ; Requested Profile: EPT(1), DescTables(2), VPID(5), WBINVD(6), RDRAND(11), 
    ;                    ENCLS(15), PML(17), MBEC(22), ENCLV(26), FLUSHBYASID(28)
    mov r9d, 0x144448E6                 ; UPDATED: Added Bit 22 for strict kernel-mode execution tracking
    and r8, r9                          ; Sanitize requested profile against hardware capabilities
    or  rax, r8                         ; Fuse mandatory 1 bits with optimized parameters
    
    mov rcx, VMCS_CTRL_SECONDARY_VM_EXEC_CONTROLS ; Encoding: 0x0000401E
    vmwrite rcx, rax              

    ; -------------------------------------------------------------------------
    ; 4. Configure Tertiary Processor-Based VM-Execution Controls
    ; -------------------------------------------------------------------------
    mov ecx, 0x0000049F                 ; IA32_VMX_PROCBASED_CTLS3 MSR
    rdmsr                           
    and rdx, 0x00000000                 ; Strict sandbox isolation (No advanced dynamic extensions)
    or  rax, rdx            

    mov rcx, VMCS_CTRL_TERTIARY_PROC_BASED_CONTROLS ; Encoding: 0x00002034 (CORRECTED architectural 64-bit field)
    vmwrite rcx, rax                

; -----------------------------------------------------------------------------
; Suffocation Protocols: Locking Down Telemetry, Interrupts, and Firmware Loops
; -----------------------------------------------------------------------------

Optimize_APIC_Interrupt_Speed:
    ; Zero out all EOI exit bitmaps to prevent execution lagging and maximize performance
    ; We going to give the interrupts to the kernel we want him to handle them 
    ; The Hypervisor going to handle the special interrupts
    xor ecx, ecx                         ; Enforce sterile zero register context
    
    mov rax, VMCS_CTRL_EOI_EXIT_BITMAP_0 ; Encoding: 0x0000201C
    vmwrite rax, rcx                

    mov rax, VMCS_CTRL_EOI_EXIT_BITMAP_1 ; Encoding: 0x0000201E
    vmwrite rax, rcx               

    mov rax, VMCS_CTRL_EOI_EXIT_BITMAP_2 ; Encoding: 0x00002020
    vmwrite rax, rcx               

    mov rax, VMCS_CTRL_EOI_EXIT_BITMAP_3 ; Encoding: 0x00002022
    vmwrite rax, rcx

Suffocate_SGX_And_Encryption:
    mov rbx, 0xFFFFFFFFFFFFFFFF         ; Force immediate exits on all secure enclaves and encryption calls
    
    mov rax, VMCS_CTRL_ENCLS_EXITING_BITMAP ; Encoding: 0x0000202E (VERIFIED AUTHENTIC SILICON VALUE)
    vmwrite rax, rbx                

    mov rax, VMCS_CTRL_PCONFIG_EXITING_BITMAP ; Encoding: 0x0000203E
    vmwrite rax, rbx               

    mov rax, VMCS_CTRL_XSS_EXITING_BITMAP ; Encoding: 0x0000202C
    vmwrite rax, rbx                


Suffocate_SPP_And_HLAT:
    xor ebx, ebx                        ; Clear pointer arrays to isolate secondary translation layers
    
    mov rax, 0x00002030                 ; VMCS_CTRL_SPP_TABLE_POINTER
    vmwrite rax, rbx               

    mov rax, VMCS_CTRL_HLAT_POINTER     ; Encoding: 0x00002040
    vmwrite rax, rbx               

    mov rax, 0x00002042                 ; VMCS_CTRL_SEAM_SHARED_EPTP
    vmwrite rax, rbx                

Suffocate_APIC_Timer:
    mov rax, 0x0000203A                 ; VMCS_GUEST_IA32_TSC_DEADLINE (Guest Deadline Shadow tracking register)
    vmwrite rax, rbx

; ==============================================================================
; INTEL VMX EXECUTION CONTROL FIELDS INITIALIZATION (PART 5)
; ==============================================================================

init_secondary_and_msr_controls:
    ; 1. Sync and Sanitize Secondary VM-Exit Hardware Controls
    mov ecx, 0x00000493                 ; IA32_VMX_EXIT_CTLS2 MSR address pointer
    rdmsr                                           
    and edx, eax                        ; Extract the baseline allowed hardware bitmask configuration
    
    ; Clear secondary exit masks to isolate execution environments safely
    xor ebx, ebx                        ; Establish sterile zero context anchor
    mov rax, VMCS_CTRL_SECONDARY_VM_EXIT_CONTROLS ; Encoding: 0x00002044
    vmwrite rax, rbx 

    ; 2. Initialize VM-Exit MSR Lifecycle Management Matrices
    ; Fixing the critical overlapping address-vs-count encoding bugs cleanly
    mov rax, VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS ; Encoding: 0x00002008 (64-Bit Address link)
    vmwrite rax, rbx

configure_vmcs_raw:
    ; -------------------------------------------------------------------------
    ; 3. Establish Core Execution Vector Anchors (Raw Controls Configuration)
    ; -------------------------------------------------------------------------
    
    ; --- Posted-Interrupt Notification Vector ---
    mov rbx, 0x00000002                 ; Assign hardwired vector interrupt slot index 2
    mov rax, VMCS_CTRL_POSTED_INTERRUPT_STATUS_VECTOR ; Encoding: 0x00000002     
    vmwrite rax, rbx        

; ==============================================================================
; INTEL VMX EXECUTION CONTROL FIELDS INITIALIZATION (PART 6 - FINAL ENTRY SET)
; ==============================================================================

init_vm_entry_control_fields:
VMENTRY_LOAD_IA32_FRED          EQU (1 << 23)

    ; -------------------------------------------------------------------------
    ; 1. Sync and Validate Hardware VM-Entry Controls
    ; -------------------------------------------------------------------------
    mov ecx, 0x0000048C                 ; IA32_VMX_TRUE_ENTRY_CTLS MSR address pointer
    rdmsr                          
    mov r8, rdx                         ; R8 = Allowed 1 Bits baseline tracking mask
    
    mov r9d, 0x00000204                 ; Requested: IA32e/Long-Mode Guest (Bit 2) + Isolation Controls
    and r8, r9                          ; Sanitize requested bits against physical capabilities
    or  rax, r8                         ; Fuse mandatory 1 bits with optimized parameters
    or rax, VMENTRY_LOAD_IA32_FRED
    mov rcx, VMCS_CTRL_VMENTRY_CONTROLS ; Encoding: 0x00004012
    vmwrite rcx, rax               

    ; -------------------------------------------------------------------------
    ; 2. Configure Guest Hardware Event Injection (Diagnostic Intercept Layer)
    ; -------------------------------------------------------------------------
    ; Note: Value 0x80000B0D forces an immediate hardware exception loop on launch.
    ; Initialized directly using unrolled execution vectors to preserve stackless flow.
    mov rbx, 0x0000000080000B0D         ; Active Injection Bitmask: Valid (Bit 31) + Hardware Exception + Vector 13
    mov rax, VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD ; Encoding: 0x00004016
    vmwrite rax, rbx 

; ---------------- The fields I forgot to do -----------------------

; Check it after the optimization because there can be some things you didnt consider

; ==============================================================================
; INTEL VMX 64-BIT HARDWARE CONTROLS INITIALIZATION (UNROLLED PIPELINE LAYER)
; ==============================================================================

configure_vmcs_64bit_controls_clean:
    ; Establish absolute sterile zero context for security mappings and offsets
    xor ecx, ecx                        
    
    ; -------------------------------------------------------------------------
    ; 2. Map Execution MSR Intercept Bitmaps and Structural Lifecycle Links
    ; -------------------------------------------------------------------------
    mov rbx, 0x000000000004D000         ; Physical tracking baseline layout for MSR read/write filtering
    mov rax, VMCS_CTRL_MSR_BITMAP_ADDRESS ; Encoding: 0x00002004
    vmwrite rax, rbx

    mov rbx, 0x000000000004E000         ; MSR exit store target boundary zone pointer
    mov rax, VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS ; Encoding: 0x00002006
    vmwrite rax, rbx

    mov rax, VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS ; Encoding: 0x0000200A                                                     
    vmwrite rax, rcx    

    ; -------------------------------------------------------------------------
    ; 3. Invalidating Secondary Shadow References & Activating Extended Paging
    ; -------------------------------------------------------------------------
    mov rbx, 0xFFFFFFFFFFFFFFFF         ; Break hardware shadow chain linkage explicitly
    mov rax, VMCS_CTRL_EXECUTIVE_VMCS_POINTER ; Encoding: 0x0000200C                                                  
    vmwrite rax, rbx

    ; -------------------------------------------------------------------------
    ; 4. Neutralizing Advanced Logging arrays, APIC Vectors and Telemetry Banks
    ; -------------------------------------------------------------------------
    mov rax, VMCS_CTRL_TSC_OFFSET       ; Encoding: 0x00002010
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VIRTUAL_APIC_ADDRESS ; Encoding: 0x00002012
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_APIC_ACCESS_ADDRESS ; Encoding: 0x00002014
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS ; Encoding: 0x00002016
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VMFUNC_CONTROLS  ; Encoding: 0x00002018
    vmwrite rax, rcx

configure_vmcs_64bit_controls_extended_clean:
    ; -------------------------------------------------------------------------
    ; 6. Isolating Sandbox Memory Bitmaps & Hardware Interception Layers
    ; -------------------------------------------------------------------------
    mov rax, VMCS_CTRL_VMREAD_BITMAP_ADDRESS ; Encoding: 0x00002026
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VMWRITE_BITMAP_ADDRESS ; Encoding: 0x00002028
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS ; Encoding: 0x0000202A
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_TSC_MULTIPLIER   ; Encoding: 0x00002032
    vmwrite rax, rcx

    ; ==============================================================================
; INTEL VMX EXECUTION CONTROL FIELDS INITIALIZATION (PART 7 - EXECUTION MATRICES)
; ==============================================================================

Commit_Core_Execution_Control_Attributes:
    ; -------------------------------------------------------------------------
    ; 1. Configure Hardware Page Fault Interception Match/Mask Matrices
    ; -------------------------------------------------------------------------
    mov rax, VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK ; Encoding: 0x00004006
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH ; Encoding: 0x00004008
    vmwrite rax, rcx    

    ; -------------------------------------------------------------------------
    ; 2. Enforce MSR Lifecycle Transition Multipliers and Guest Length Controls
    ; -------------------------------------------------------------------------
    mov rbx, 0x00000001                 ; Request exactly 1 MSR structure slot for transition
    mov rax, VMCS_CTRL_VMEXIT_MSR_STORE_COUNT ; Encoding: 0x0000400E 
    vmwrite rax, rbx

    mov rax, VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT ; Encoding: 0x00004014
    vmwrite rax, rcx                    ; Clear to zero to rely entirely on static host layout

    mov rax, VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE ; Encoding: 0x00004018
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH ; Encoding: 0x0000401A
    vmwrite rax, rcx

    ; -------------------------------------------------------------------------
    ; 3. Neutralizing APIC Thresholds and Modern APIC Virt Execution Windows
    ; -------------------------------------------------------------------------
    mov rax, VMCS_CTRL_TPR_THRESHOLD    ; Encoding: 0x0000401C
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_PLE_GAP          ; Encoding: 0x00004020
    vmwrite rax, rcx

    mov rax, VMCS_CTRL_PLE_WINDOW       ; Encoding: 0x00004022
    vmwrite rax, rcx

; -------------------------------------------------------------------------
;                     Defenses for the PC
; -------------------------------------------------------------------------



; ==============================================================================
; HARDWARE DEFENDER DEFINE MATRIX (EQU REFACTORING - PART 7)
; ==============================================================================
; Speculative Execution & Architecture Control Registers
MSR_IA32_SPEC_CTRL                              EQU 0x00000048 ; Spectre/Meltdown Silicon Mitigation Register
MSR_IA32_VMX_PROCBASED_CTLS2                    EQU 0x0000048B ; Secondary VMX Capabilities Core Identifier
MSR_IA32_VIRTUAL_EXCEPTION_INFO                 EQU 0x00000982 ; Global Intercept and Exception Subsystem Policy

; Physical Memory Structural Base Boundaries
VTD_IOMMU_BASE_ADDRESS                          EQU 0xFED90000 ; Root Hardware Location for IOMMU Motherboard Communication
VTD_PAGE_TABLE_ROOT                             EQU 0x00095000 ; Secure allocation for VT-d Page Directory Root
VTD_PAGE_TABLE_LEVEL2                           EQU 0x00096001 ; Secondary pointer matrix link target with valid attributes

EPT_PML4_BASE_ADDRESS                           EQU 0x00011000 ; Root Matrix for Sandbox Isolation Extended Page Tables
EPT_PDPT_BASE_ADDRESS                           EQU 0x00012000 ; Page Directory Pointer Table Memory Anchor
EPT_PD_ARRAY_START                              EQU 0x00013000 ; NEW: Start address of our 10 continuous PD pages

; Verified VMCS Encodings Supplement
VMCS_CTRL_EPT_POINTER                           EQU 0x0000201A ; 64-Bit VMCS Encoding link for Extended Page Table Pointer (EPTP)
VMCS_CTRL_EPTP_INDEX                            EQU 0x00002040 ; supplemental EPTP Index slot encoding anchor
VMCS_CTRL_EPT_POINTER_LIST_ADDRESS              EQU 0x00002024 ; Didnt got used

; ==============================================================================
;           INTEL SILICON ARCHITECTURE MSR (MODEL-SPECIFIC REGISTERS)
; ==============================================================================
MSR_IA32_MISC_ENABLE                            EQU 0x000001A0 ; Processor Feature Allocation and Hardware Feature Flags
MSR_IA32_EFER                                   EQU 0xC0000080 ; Extended Feature Enable Register (Long Mode Activation Control)

; Architectural Constants for Bitmask Alignment
MSR_IA32_MISC_ENABLE_CPUID_MAX_VAL_BIT          EQU 0x00000001 ; Hardware bit to enforce lock on CPUID limit modifications

; ==============================================================================
;      INTEL ABSOLUTE AUTHORITY HYPERVISOR CONTROL ENCODINGS
; ==============================================================================
VMCS_CTRL_SECONDARY_EXEC_MBEC                   EQU 0x00400000 ; Bit 22: Activates Mode-Based Execute Control (XS/XU Split)
VMCS_CTRL_SECONDARY_EXEC_HLAT                   EQU 0x00000002 ; Extended Bit: Activates Hypervisor-Managed Linear Translation

; HLAT Structural Table Pointers within the VMCS
VMCS_CTRL_HLAT_POINTER                          EQU 0x00002040 ; 64-Bit field pointing to our strict HLAT Root Table

; ==============================================================================
;      INTEL VT-d IOMMU HARDWARE REGISTER CORES ENCODINGS (MMIO BASE: 0xFED90000)
; ==============================================================================
VTD_IOMMU_MMIO_BASE                             EQU 0x00000000FED90000 ; Physical Motherboard MMIO Gate Address
VTD_IOMMU_VERSION_REG                           EQU 0x00               ; Read-Only: Architectural Version Offset
VTD_IOMMU_CAP_REG                               EQU 0x08               ; Read-Only: Hardware Capabilities Matrix (64-Bit)
VTD_IOMMU_EXT_CAP_REG                           EQU 0x10               ; Read-Only: Extended Capabilities Matrix (64-Bit)
VTD_IOMMU_GCMD_REG                              EQU 0x18               ; Read-Write: Global Command Register (Activation)
VTD_IOMMU_GSTS_REG                              EQU 0x1C               ; Read-Only: Global Status Register (Sync Polling)
VTD_IOMMU_RTADDR_REG                            EQU 0x20               ; Read-Write: Root Entry Table Address Pointer Register


; ==============================================================================
; INTEL CORE INITIALIZATION & BARE-METAL SANDBOX ISOLATION ENGINE (PART 7)
; ==============================================================================

init_hardware_defender_and_paging:
    ; -------------------------------------------------------------------------
    ; 1. Enforce Speculative Execution Mitigations (Spectre/Meltdown Shutter)
    ; -------------------------------------------------------------------------
    mov ecx, MSR_IA32_SPEC_CTRL         ; Target MSR: 0x00000048
    rdmsr                        
    or  eax, 0x00000003                 ; Assert strict hardware execution barrier bits
    xor edx, edx                        ; Isolate and clean the upper tracking channel
    wrmsr                        
Initialize_Intel_VTd_IOMMU_Hardware:
    ; -------------------------------------------------------------------------
    ; A. Clear exactly 8KB for VT-d Paging structures (0x95000 and 0x96000)
    ; -------------------------------------------------------------------------
    mov rdi, VTD_PAGE_TABLE_ROOT        ; Base Destination: 0x00095000
    xor eax, eax                        ; Sterile zero anchor registers context
    mov ecx, 1024                       ; 2 full pages * 512 entries = 1024 QWORDS
    rep stosq                           ; Wipe dirty legacy footprint cleanly

    ; -------------------------------------------------------------------------
    ; B. Weave the structural lifecycle links inside the VT-d matrices (128-bit Entries!)
    ; -------------------------------------------------------------------------
    ; 1. Root Entry (Bus 0): Point to Context Table at 0x96000. Bit 0 = Present
    mov rax, VTD_PAGE_TABLE_LEVEL2      ; 0x00096000
    or  rax, 1                          ; Set Present Bit
    mov [VTD_PAGE_TABLE_ROOT], rax      ; Lower 64-bit of Bus 0 Root Entry
    mov qword [VTD_PAGE_TABLE_ROOT + 8], 0 ; Upper 64-bit of Bus 0 Root Entry (Clear/Reserved)
    
    ; 2. Context Entry (Dev 0, Fn 0): Point to EPT PML4. 
    ; Translation Type = 0x1 (Multi-level page table) or EPT mapping based on ECAP
    mov rax, EPT_PML4_BASE_ADDRESS      ; Target: 0x00011000
    or  rax, 0x15                       ; Your synchronization and attribute flags (Ensure compatibility with T&AW)
    mov [VTD_PAGE_TABLE_LEVEL2], rax    ; Lower 64-bit of Context Entry
    ; In the upper 64-bit, we must set Domain ID (e.g., Domain 1) to isolate this space
    mov qword [VTD_PAGE_TABLE_LEVEL2 + 8], 0x0001 ; Domain ID = 1, Address Width, etc.

    ; -------------------------------------------------------------------------
    ; C. Flash Configuration Matrix directly to the physical Chipset Base
    ; -------------------------------------------------------------------------
    mov rbx, VTD_IOMMU_MMIO_BASE        ; RBX = 0xFED90000
    mov rax, VTD_PAGE_TABLE_ROOT        ; 0x00095000
    mov [rbx + VTD_IOMMU_RTADDR_REG], rax ; Set Root Table Address

    ; The operation we performed here is a direct write to MMIO (Memory-Mapped I/O).
    ; This is a specific physical memory window (0xFED90000) that Intel maps directly 
    ; to the chipsets internal silicon configuration registers rather than the RAM.
    ; By executing this MOV command, the CPU bypasses the cache and dispatches an 
    ; electrical control signal straight to the Intel VT-d hardware unit, forcing 
    ; the IOMMU to track and latch our custom 128-bit Root Table pointer.

    ; -------------------------------------------------------------------------
    ; C2. FORCE CHIPSET TO COMMIT ROOT TABLE POINTER (SRTP COMMAND)
    ; -------------------------------------------------------------------------
    mov eax, [rbx + VTD_IOMMU_GCMD_REG]
    or  eax, 0x40000000                 ; Assert Bit 30 (Set Root Table Pointer - SRTP)
    mov [rbx + VTD_IOMMU_GCMD_REG], eax

.vtd_srtp_sync_loop:
    mov eax, [rbx + VTD_IOMMU_GSTS_REG]
    and eax, 0x40000000                 ; Poll Bit 30 (Root Table Pointer Status - RTPS)
    jz  .vtd_srtp_sync_loop             ; Wait until Silicon locks the Root Table Pointer

    ; -------------------------------------------------------------------------
    ; D. Trigger and Enforce Active Global Hardware Synchronization Command
    ; -------------------------------------------------------------------------
    mov eax, [rbx + VTD_IOMMU_GCMD_REG] 
    or  eax, 0x80000000                 ; Assert bit 31 (Global Translation Enable - TE)
    mov [rbx + VTD_IOMMU_GCMD_REG], eax 

    ; -------------------------------------------------------------------------
    ; E. Strict Microarchitectural Polling Loop (Wait for Silicon Acknowledgement)
    ; -------------------------------------------------------------------------
.vtd_hardware_sync_loop:
    mov eax, [rbx + VTD_IOMMU_GSTS_REG] 
    and eax, 0x80000000                 ; Mask and isolate status bit 31 (Translation Status - TES)
    jz  .vtd_hardware_sync_loop         ; Loop until committed

    ; -------------------------------------------------------------------------
    ; 2. Construct Ultra-Defensive EPT Partition with Advanced Silicon Armoring
    ; -------------------------------------------------------------------------

Construct_Massive_10GB_EPT_Fortress:
    ; -------------------------------------------------------------------------
    ; 1. Clear exactly 48KB of RAM footprint (1 PML4 + 1 PDPT + 10 PD Pages = 12 Pages total)
    ; -------------------------------------------------------------------------
    mov rdi, EPT_PML4_BASE_ADDRESS      ; Start at 0x11000
    xor rax, rax                        ; Sterile zero reference anchor register
    mov rcx, 6144                       ; 12 pages * 512 QWORDS per page = 6144 entries
    rep stosq                           ; Wipe entire extended matrix footprint cleanly

    ; -------------------------------------------------------------------------
    ; 2. Link PML4 to PDPT Table with full permissions (0x07)
    ; -------------------------------------------------------------------------
    mov rax, EPT_PDPT_BASE_ADDRESS      ; Base: 0x12000
    or  rax, 0x07                       ; Read + Write + Execute
    mov [EPT_PML4_BASE_ADDRESS], rax

    ; -------------------------------------------------------------------------
    ; 3. Weave 10 independent pointer links inside the PDPT to bind our 10 PD Pages
    ; -------------------------------------------------------------------------
    mov edi, EPT_PDPT_BASE_ADDRESS      ; Start writing entries inside the PDPT (0x12000)
    mov eax, EPT_PD_ARRAY_START         ; Pointer targets the first PD page (0x13000)
    or  eax, 0x07                       ; Read + Write + Execute
    mov ecx, 10                         ; Loop counter to generate exactly 10 matrix links

.pdpt_link_loop:
    mov [rdi], rax                      ; Commit the 64-bit table linkage entry
    add rdi, 8                          ; Move to the next QWORD slot inside the PDPT
    add rax, 0x1000                     ; Point to the next sequential PD page frame (Stride by 4KB)
    dec rcx
    jnz .pdpt_link_loop

    ; -------------------------------------------------------------------------
    ; 4. Massive Double Loop: Map 10GB of Physical RAM via 5,120 entries of 2MB
    ; -------------------------------------------------------------------------
    mov edi, EPT_PD_ARRAY_START         ; Start writing directly at 0x13000
    xor edx, rdx                        ; RDX = Absolute physical RAM address offset tracker (Starts at 0x0)
    mov r8, 10                          ; Outer Loop: 10 full pages to generate

.outer_pd_page_loop:
    mov rcx, 512                        ; Inner Loop: 512 entries per single PD page row

.inner_2mb_mapping_loop:
    mov rax, rdx  
    or  rax, 0x0000000000000076         ; Enforce: 2MB Large Page (Bit 7) + Advanced Silicon Armoring Flags (0x76)
    mov [rdi], rax                      ; Commit the encrypted page walk block entry
    add rdi, 8                          ; Shift array pointer to next QWORD entry slot
    add rdx, 0x00200000                 ; Stride physical target address dynamically by exactly 2MB
    dec rcx
    jnz .inner_2mb_mapping_loop         ; Loop until the single 1GB page row is complete

    dec r8
    jnz .outer_pd_page_loop             ; Loop until all 10 pages are fully populated (10GB complete)

    ; -------------------------------------------------------------------------
    ; 5. Commit the finalized 10GB EPTP Master Pointer to the VMCS
    ; -------------------------------------------------------------------------
    mov rbx, EPT_PML4_BASE_ADDRESS      ; Target baseline: 0x11000
    or  rbx, 0x76                       ; getting the bits into rbx
    mov rax, VMCS_CTRL_EPT_POINTER      ; Encoding Field: 0x0000201A 
    vmwrite rax, rbx                    ; Injecting the bits

    ; -------------------------------------------------------------------------
    ; 3.                     GPT (GUEST PAGE TABLE)
    ; -------------------------------------------------------------------------

; ==============================================================================
;          GUEST PAGE TABLES (GPT) STRUCTURAL CONSTANTS (0x50000 MATRIX)
; ==============================================================================
GPT_PML4_BASE_ADDRESS                           EQU 0x000050000 ; Root Architectural Page Directory for the Guest
GPT_PDPT_BASE_ADDRESS                           EQU 0x000051000 ; Guest Page Directory Pointer Table Memory Anchor
GPT_PD_BASE_ADDRESS                             EQU 0x000052000 ; Guest Page Directory (Maps massive chunks)
GPT_PT_BASE_ADDRESS                             EQU 0x000053000 ; Guest Page Table (Maps exact 4KB frames)

; VMCS Guest Control Encoding Supplement

Construct_Sterile_Guest_Page_Tables:
    ; -------------------------------------------------------------------------
    ; 1. Clear exactly 16KB of RAM footprint (4 full pages from 0x50000 to 0x53FFF)
    ; -------------------------------------------------------------------------
    mov rdi, GPT_PML4_BASE_ADDRESS      ; Target Base address: 0x50000
    xor rax, rax                        ; Sterile zero anchor registers context
    mov rcx, 2048                       ; 4 pages * 512 QWORDS per page = 2048 entries
    rep stosq                           ; Atomic memory wipe to remove dirty legacy fragments

    ; -------------------------------------------------------------------------
    ; 2. Weave structural hierarchy links inside the Guest context matrices
    ; -------------------------------------------------------------------------
    ; Attributes: Present (Bit 0) + Read/Write (Bit 1) = 0x03
    mov rax, GPT_PDPT_BASE_ADDRESS      ; Target: 0x51000
    or  rax, 0x03                       ; Inject privilege attributes flags
    mov [GPT_PML4_BASE_ADDRESS], rax    ; Link Guest PML4 -> Guest PDPT

    mov rax, GPT_PD_BASE_ADDRESS        ; Target: 0x52000
    or  rax, 0x03                       
    mov [GPT_PDPT_BASE_ADDRESS], rax    ; Link Guest PDPT -> Guest PD

    mov rax, GPT_PT_BASE_ADDRESS        ; Target: 0x53000
    or  rax, 0x03                       
    mov [GPT_PD_BASE_ADDRESS], rax      ; Link Guest PD -> Guest PT

    ; -------------------------------------------------------------------------
    ; 3. Execute Loop mapping cycle inside Guest PT for first 512 x 4KB frames
    ; -------------------------------------------------------------------------
    mov rdi, GPT_PT_BASE_ADDRESS        ; Write pointer inside Guest Page Table (0x53000)
    mov rax, 0x0000000000000003         ; Base Physical RAM: 0x0 + flags (0x03)
    mov rcx, 512                        ; Fill one full page table row completely (Maps 2MB total)

.gpt_mapping_loop:
    mov [rdi], rax                      ; Write 64-bit Page Table Entry
    add rdi, 8                          ; Shift array pointer to next QWORD entry slot
    add rax, 0x1000                     ; Stride next target frame address by exactly 4KB
    dec rcx                             
    jnz .gpt_mapping_loop               

    ; -------------------------------------------------------------------------
    ; 4. Bind the finalized GPT Root to the Guest State inside the VMCS
    ; -------------------------------------------------------------------------
    mov rbx, GPT_PML4_BASE_ADDRESS      ; Base address value: 0x50000
    mov rax, VMCS_GUEST_CR3             ; Encoding Field Slot: 0x00002402
    vmwrite rax, rbx                    ; Enforce the master guest CR3 permanently

    ; I put it above our stack (0x4F500) and I did it because the EPT will need a lot of space
    ; to work properly so I gave him the space he needs while the GPT getting only 2 pages of PT
    ; the EPT going to get like 20 to 30 pages or just 10 it is about our OS or what you going to build
    ; or if you gonna use it you can choose how many pages you want I will choose probably 20 or 10

   
; ==============================================================================
; 4.    TSS VERIFICATION & INTERCEPT TIMING VALIDATION ENGINE 
; ==============================================================================

align 16
_tss_fragment_confirm:
    ; 1. Extract System Descriptor Tables without contaminating the stack
    str cx                       
    mov rdi, FORENSICS_GDTR_BUFFER      ; Point to stable secure memory zone: 0x00007100
    sgdt [rdi]                          ; Store active Global Descriptor Table Register status
    
    mov rbx, [rdi + 2]                  ; RBX = Absolute Physical Base Address of the GDT Matrix
    movzx rcx, cx                       ; Clear tracking channel and isolate the TR Selector Index
    add rbx, rcx                        ; RBX = Pointer pointing directly to the target TSS Descriptor Slot
    
    ; 2. Execute Atomic Reconstruction of the 64-Bit System TSS Base Address
    movzx edx, word [rbx + 2]           ; Extract Base bits 0–15
    mov eax, [rbx + 4]          
    and eax, 0xFF000000                 ; Extract and isolate Base bits 24–31
    or  edx, eax                 
    mov eax, [rbx + 7]          
    and eax, 0x00FF0000                 ; Extract and isolate Base bits 16–23
    or  edx, eax                        ; RDX holds the lower 32-bits of the absolute TSS Base address
    
    mov rsi, [rbx + 8]                  ; In 64-bit Long Mode, TSS Descriptors expand to 16 bytes
    shl rsi, 32                         ; Shift upper 32-bits of the base address (bits 32–63) into place
    or  rdx, rsi                        ; RDX = Unified 64-Bit Absolute Physical Base Address of the active TSS

    ; 3. Cross-Check Real Silicon States against VMCS Shadow Boundaries
    mov rsi, [rdx + 4]                  ; Extract raw hardware limit properties from the active TSS block
    mov rax, VMCS_GUEST_TR_LIMIT        ; Encoding Field: 0x0000481C
    vmread r8, rax                      ; R8 = Active limit assigned to the Guest inside the cage

    ; -------------------------------------------------------------------------
    ; 5. Intercept and Block CPUID Microarchitectural Spoofing Configurations
    ; -------------------------------------------------------------------------
    mov ecx, MSR_IA32_MISC_ENABLE       ; Target MSR Pointer: 0x000001A0
    rdmsr
    
    ; Enforce hardware lock layer blocking untrusted modifications
    or  edx, MSR_IA32_MISC_ENABLE_CPUID_MAX_VAL_BIT 
    wrmsr

    ; ==============================================================================
    ;                           FRED the new IDT
    ; ==============================================================================

FRED_FRAME_ERRCODE      EQU 0x00    ; 64-bit Error Code
FRED_FRAME_RIP          EQU 0x08    ; 64-bit Return RIP
FRED_FRAME_CS           EQU 0x10    ; 64-bit CS + Event Info
FRED_FRAME_RFLAGS       EQU 0x18    ; 64-bit RFLAGS
FRED_FRAME_RSP          EQU 0x20    ; 64-bit Previous RSP
FRED_FRAME_SS           EQU 0x28    ; 64-bit SS + Vector + Event Type
FRED_FRAME_EVENT_DATA   EQU 0x30    ; 64-bit Extra Event Data (e.g., CR2 on #PF)
FRED_FRAME_RESERVED     EQU 0x38    ; 64-bit Reserved (0)

MSR_IA32_FRED_RSP1      EQU 0x1CD
; Holds the Stack Pointer (RSP) for Ring 0 Stack Level 1 (used for standard interrupts/exceptions).
MSR_IA32_FRED_RSP2      EQU 0x1CE
; Holds the Stack Pointer (RSP) for Ring 0 Stack Level 2 (used for nested/higher-priority faults).
MSR_IA32_FRED_RSP3      EQU 0x1CF
; Holds the Stack Pointer (RSP) for Ring 0 Stack Level 3 (reserved for critical faults like #DF Double Fault or #MC).
MSR_IA32_FRED_STKLVLS   EQU 0x1D0
; A 64-bit bitmask (2 bits per vector for vectors 0–31) telling the CPU which stack level (0–3) to switch to when a specific exception fires.
MSR_IA32_FRED_CONFIG    EQU 0x1D4
; Holds the 4KB-aligned base address of your FRED handler code (Base + 0x0 for Ring 3, Base + 0x100 for Ring 0) plus configuration flags in bits 0–11.
CR4_FRED_BIT            EQU (1 << 32)
; Represents Bit 32 of Control Register 4 (CR4). Setting this bit to 1 turns on FRED mode and disables the legacy IDT.

; =========================================================================
; VMCS Field Encodings for FRED Host-State (64-bit Fields)
; =========================================================================
VMCS_HOST_IA32_FRED_CONFIG      EQU 0x00002C14
VMCS_HOST_IA32_FRED_RSP1        EQU 0x00002C16
VMCS_HOST_IA32_FRED_RSP2        EQU 0x00002C18
VMCS_HOST_IA32_FRED_RSP3        EQU 0x00002C1A
VMCS_HOST_IA32_FRED_SSP1        EQU 0x00002C1C
VMCS_HOST_IA32_FRED_SSP2        EQU 0x00002C1E
VMCS_HOST_IA32_FRED_SSP3        EQU 0x00002C20
VMCS_HOST_IA32_FRED_STKLVLS     EQU 0x00002C22

; =========================================================================
; VM-Exit Controls Encoding & Control Bit
; =========================================================================
VMCS_CTRL_VMEXIT_CONTROLS       EQU 0x0000400C
VMEXIT_LOAD_IA32_FRED           EQU (1 << 31)

; =========================================================================
; Stack Top Constants (0x90000 - 0x9F000 Layout)
; =========================================================================
FRED_STACK_LVL1_TOP             EQU 0x000000000009F000
FRED_STACK_LVL2_TOP             EQU 0x000000000009D000
FRED_STACK_LVL3_TOP             EQU 0x000000000009B000

VMCS_GUEST_IA32_FRED_CONFIG     EQU 0x0000281A
VMCS_GUEST_IA32_FRED_RSP1       EQU 0x0000281C
VMCS_GUEST_IA32_FRED_RSP2       EQU 0x0000281E
VMCS_GUEST_IA32_FRED_RSP3       EQU 0x00002820
VMCS_GUEST_IA32_FRED_SSP1       EQU 0x00002822
VMCS_GUEST_IA32_FRED_SSP2       EQU 0x00002824
VMCS_GUEST_IA32_FRED_SSP3       EQU 0x00002826
VMCS_GUEST_IA32_FRED_STKLVLS    EQU 0x00002828

VMCS_CTRL_VMENTRY_CONTROLS      EQU 0x00004012
;for activating it you need to use VMENTRY CONTROLS and use bit 23 
;the name for the constant is VMENTRY_LOAD_IA32_FRED




    ; Tommorow your work on the Defenses (EPT TSS IOMMU) and make them advance as possible you did EPT and you need to finish IOMMU
    ; but you need to double check them 
    ; and you didnt do TSS and IDT that tommorow problem and see if there any more things

    ;the defenses you need to build: IOMMU, EPT, TSS, IDT or FRED, MKTME, CET
    ;Key Locker, TDT, VPID, SMAP and SMEP, UMIP, APICv, MPK / PKEYS, LBR, MBEC(for EPT), 
    ;CR4.MCE, Virtualize TSC, Write-Protection Dirty Bits, HLAT, Bus Lock Detection, 
    ;LAM, LASS, BHI_DIS_S Controls, Enhanced VM-Entry, UCODE, TXT, 

;----------------- PART 8: LAUNCHING -----------------

vmlaunch_starting:
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp 
    xor edi, edi
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    vmlaunch     
    
HyperVisor_end:

VM_Exit_Handler:
push rax 
push rbx
push rcx 
push rdx



pop rdx
pop rcx
pop rbx 
pop rax
xor rbp, rbp

section .data
    align 4096

vmxon_region: 
    times 4096 db 0     

    vmxon_pointer: dq 0
    guest_stack_top: dq 0 

    align 16
host_idt_table: times 256 dq 0 

    Guest_Code_Entry:
    mov eax, 0xABCDEF  
    
section .bss
    align 16
guest_stack_bottom:
    resb 1024           
guest_stack_limit:
