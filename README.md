# Syscalls Extractor

Utility project to extract build information and syscall numbers from a host.

```
.\SyscallsExtractor.exe

[*] Platform ID: 2
[*] Build Number: 22000
[*] Major Version: 10
[*] Minor Version: 0
[*] Service Pack Major: 0
[*] Service Pack Minor: 0

[*] Syscalls

NtOpenProcess:           0x26
NtCreateThreadEx:        0xC5
NtWriteVirtualMemory:    0x3A
ZwAllocateVirtualMemory: 0x18
NtCreateSection:         0x4A
ZwMapViewOfSection:      0x28
NtCreateProcess:         0xBC
ZwProtectVirtualMemory:  0x50
ZwReadVirtualMemory:     0x3F
NtCreateThread:          0x4E
NtUnmapViewOfSection:    0x2A
NtCreateUserProcess:     0xCD
ZwFreeVirtualMemory:     0x1E
NtQueueApcThread:        0x45

[*] Done
```
