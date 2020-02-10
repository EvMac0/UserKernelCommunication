format PE64
entry start

include 'WIN64AX.INC'

struc _CWay {
  .Status          dq ? ;
  .A1              dq ? ;
  .A2              dq ? ;
  .PEBGame         dq ? ;
  .PBMI            dq ? ; pointer to _MEMORY_BASIC_INFORMATION
  .PFPatch         dq ? ; pointer to array of _FastPatch
  .Var1            dq ? ; temp var
  .Size            dd ? ;
  .PIDGame         dd ? ;
  .SleepInterval   dw ? ;
  .ControlCode     db ? ;
                   db ? ; padding 1b
                   dd ? ; padding 4 b = 5b padding

}

struc _MEMORY_BASIC_INFORMATION {
  ; MEMORY_BASIC_INFORMATION begin 48b len
  .BaseAddress       dq ? ;
  .AllocationBase    dq ? ;
  .AllocationProtect dd ? ;
                        dd ? ; padding 4b
  .RegionSize        dq ? ;
  .State             dd ? ;
  .Protect           dd ? ;
  .Type              dd ? ;
                        dd ? ; padding 4b
  ; MEMORY_BASIC_INFORMATION end
}

struc _FastPatch {
  .AddressToPatch                 dq ? ;
  .AddressFromPatch               dq ? ;
  .Size                           dd ? ;
                                  dd ? ; padding 4b
}

struc _ShellDataAddr {
  .CWay                           dq ? ;
  .HijackedAddrInStack            dq ? ;
  ;.MmGetPhysicalAddress          dq ? ;
  .MyMmUserProbeAddress           dq ? ;
  ;.MmMapIoSpace                  dq ? ;
  ;.MmUnmapIoSpace                dq ? ;
  .KeDelayExecutionThread         dq ? ;
  .PsLookupProcessByProcessId     dq ? ;
  .ObfDereferenceObject           dq ? ;
  .KeStackAttachProcess           dq ? ;
  .KeUnstackDetachProcess         dq ? ;
  .PsGetProcessPeb                dq ? ;
  .MmCopyVirtualMemory            dq ? ;
  .ZwQueryVirtualMemory           dq ? ;
}

struc _ShellData {
  .Arg0                           dq ? ;
  .CurrentEProcess                dq ? ;
  .TargetEProcess                 dq ? ;
  .Arg1                           dq ? ; used in MmCopyVirtualMemory, ZwQueryVirtualMemory
  .Arg2                           dq ? ; handle of user-mode Event for sync
  .APC_State                      rb 48 ; real size (43 == 8 * 4 = 32 - ApcListHead, 8 - Process, 1 - InProgressFlags, 1 - KernelApcPending, 1 - UserApcPending) padding - 5b
  .MBI                            rb 48 ; padding - 8b
}

virtual at 0
  CWay _CWay
end virtual

virtual at 0
  MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION
end virtual

virtual at 0
  FPatch _FastPatch
end virtual

virtual at 0
  ShellDataAddr _ShellDataAddr
end virtual

virtual at 0
  ShellData _ShellData
end virtual

;consts
Status_MapSetted_WaitForDriverGetCWay = 0xFF                    ; by userMode app.
Status_DriverGetCWay = 0xAA                                     ; by driver to userMode app.
Status_ShellCodeExecuted = 0xBB                                 ; by shellcode to userMode app


section '.text' code readable executable

start:
   ;sub rsp, 28h                                                  ; for local tests
  mov r12, 0101010101010101h                                    ; r12 - ShellDataAddr
  mov r13, 0101010101010101h                                    ; r13 - ShellData
  mov r14, [r12+ShellDataAddr.CWay]                             ; r14 - CWay

  ;метка которую необходимо заменять на что-то еще
  

  mov rcx, qword [r13+ShellData.CurrentEProcess]                ; put to rcx value in ShellData.CurrentEProcess
  call KeStackAttachProcessM                                    ; attach to ShellData.CurrentEProcess

  mov al, Status_ShellCodeExecuted
  mov byte [r14+CWay.Status], al                                ; send to userMode app Status_ShellCodeExecuted
shellRepeat:

  mov al, byte [r14+CWay.ControlCode]                           ; get ContolCode and check it below

  
  .if (al = 1)                                                  ; read memory

  ; memroy checking
  ;mov rax, [r14+CWay.A1]
  ;call RWMmCheckAddressM
  ;.if (rax > 0)
    ;mov rax, [r14+CWay.A2]
    ;call RWMmCheckAddressM
    ;.if (rax > 0)

      mov rdx, [r14+CWay.A1]                                      ; TargetAddress (read from)
      mov rcx, [r13+ShellData.TargetEProcess]                     ; TargetProcess

      .if (rcx > 0)
        mov r9, [r14+CWay.A2]                                     ; SourceAddress (read to)
        mov r8, [r13+ShellData.CurrentEProcess]                   ; SourceProcess

        xor rax, rax
        mov eax, [r14+CWay.Size]                                  ; move Size

        call MmCopyVirtualMemoryM
        .if (rax = 0)
          mov rbx, [r13+ShellData.Arg1]
          mov [r14+CWay.Size], ebx                                  ; save ReturnSize
          jmp noErrorRead
        .endif
      .endif

    ;.endif
  ;.endif


    mov al, -1
    movzx rax, al

    noErrorRead:
    mov [r14+CWay.Status], rax
    jmp competeRequest
  .endif



  .if (al = 2)                                                  ; write memory

  ;address checking
  ;mov rax, [r14+CWay.A1]
  ;call RWMmCheckAddressM
  ;.if (rax > 0)
    ;mov rax, [r14+CWay.A2]
    ;call RWMmCheckAddressM
    ;.if (rax > 0)

      mov r9, [r14+CWay.A1]                                       ; TargetAddress (write to)
      mov r8, [r13+ShellData.TargetEProcess]                      ; TargetProcess

      .if (r8 > 0)
        mov rdx, [r14+CWay.A2]                                    ; SourceAddress (write from)
        mov rcx, [r13+ShellData.CurrentEProcess]                  ; SourceProcess

        xor rax, rax
        mov eax, [r14+CWay.Size]                                  ; move Size

        call MmCopyVirtualMemoryM
        .if (rax = 0)
          mov rbx, [r13+ShellData.Arg1]
          mov [r14+CWay.Size], ebx                                  ; save ReturnSize
          jmp noErrorWrite
        .endif
      .endif

  ; .endif
  ;.endif


    mov al, -1
    movzx rax, al

    noErrorWrite:
    mov [r14+CWay.Status], rax
    jmp competeRequest
  .endif


  

  .if (al = 3)                                                  ; setup new PIDGame and get PEProcess for game process

    mov rcx, [r13+ShellData.TargetEProcess]                     ; put to rcx address of _EPROCESS
    .if (rcx > 0)                                               ; check if we already opened Process
      call ObfDereferenceObjectM                                ; deref
      mov [r13+ShellData.TargetEProcess], 0                     ;
      xor rcx, rcx
    .endif

    mov ecx, dword [r14+CWay.PIDGame]                           ; get PID of game from CWay
    lea rdx, [r13+ShellData.TargetEProcess]
    call PsLookupProcessByProcessIdM

    mov [r14+CWay.Status], rax                                  ; set Status from rax of PsLookupProcessByProcessId

    .if (rax = 0)                                               ; if success, get PEB address
      call PsGetProcessPebM
      mov [r14+CWay.PEBGame], rax
    .endif

    jmp competeRequest
  .endif


  

  .if (al = 5)                                                  ; get regions of game

    mov rax, [r14+CWay.PBMI]
    mov rax, [rax+MEMORY_BASIC_INFORMATION.BaseAddress]          ; get value in BaseAddress from userMode app
    mov qword [r13+ShellData.MBI+MEMORY_BASIC_INFORMATION.BaseAddress], rax


    call KeUnstackDetachProcessM                                ; unstack from currentProcess
    mov rcx, [r13+ShellData.TargetEProcess]
    call KeStackAttachProcessM                                  ; attach to targetProcess


    mov rdx, qword [r13+ShellData.MBI+MEMORY_BASIC_INFORMATION.BaseAddress] ; mov saved &BaseAddress to rdx for param of ZwQueryVirtualMemory
    call ZwQueryVirtualMemoryM
    mov [r13+ShellData.Arg0], rax                               ; save status of ZwQueryVirtualMemory in local kernel mem
                                                                ; Arg1 have RetLen of ZwQueryVirtualMemory

    call KeUnstackDetachProcessM                                ; unstack from targetProcess
    mov rcx, [r13+ShellData.CurrentEProcess]
    call KeStackAttachProcessM                                  ; attach to currentProcess

    ; copy from local to user
    lea rsi, qword [r13+ShellData.MBI]                          ; copy from
    mov rdi, qword [r14+CWay.PBMI]                              ; copy to(in PMBI stored address to userMod MBI
    mov ecx, 6                                                  ; 6 * 8 = 48b, repeat 6
    cld                                                         ; clear direction(DF=0 -> +8 in rsi and rdi) | std - setup direction(DF=1, -8 in rse, rdi)
    rep movsq                                                   ; rep - repeat. movsq - copy qword byte and dec ecx

    mov rax, [r13+ShellData.Arg0]                               ; save status of ZwQueryVirtualMemory to user mem
    mov [r14+CWay.Status], rax


    mov eax, dword [r13+ShellData.Arg1]                         ; save RetLength of ZwQueryVirtualMemory  to user mem
    mov [r14+CWay.Size], eax

    jmp competeRequest
  .endif


  

  .if (al = 6)                                                  ; release thread
    mov rcx, [r13+ShellData.TargetEProcess]                     ; put to rcx address of _EPROCESS
    .if (rcx > 0)                                               ; check if we already opened Process
      call ObfDereferenceObjectM                                ; deref
      mov [r13+ShellData.TargetEProcess], 0                     ;
      xor rcx, rcx
    .endif

    ;clear all data / random fill
    mov [r14+CWay.Status], 0
    mov byte [r14+CWay.ControlCode], 0                          ; zeroing ControlCode

    ;mov rcx, [r13+ShellData.Arg2]                               ; close hale of SyncEvent
    ;call ZwCloseM

    call KeUnstackDetachProcessM                                ; unstack from attached process

    jmp [r12+ShellDataAddr.HijackedAddrInStack]                     ; jump to releaser
  .endif


  

  ; here if ControlCode == 0
  xor r8, r8
  mov r8d, dword [r14+CWay.SleepInterval]
  call KeDelayExecutionThreadM


  

patchPlayerFlagsAndOther:
  ; patch
  mov rsi, [r14+CWay.PFPatch]
  .if (rsi > 0)
    mov rdi, 0 ; counter of cycle

    ; it's first element == playerFlags. Need read and cmp flags!

   ; xor rbx, rbx
   ; mov ebx, [rsi+FPatch.Size] ; move site to check address
   ; mov rax, [rsi+FPatch.AddressToPatch]
  ;  call MmCheckAddressM
  ;  .if (rax > 0)
   ;   mov rax, [rsi+FPatch.AddressFromPatch]
   ;   call MmCheckAddressM
   ;   .if (rax > 0)


    mov rdx, [rsi+FPatch.AddressToPatch] ; TargetAddress (read from) FIRST ELEMENT - playerFlags
    mov rcx, [r13+ShellData.TargetEProcess] ; TargetProcess

    .if (rcx > 0)
      mov r9, [rsi+FPatch.AddressFromPatch] ; SourceAddress (read to)
      mov r8, [r13+ShellData.CurrentEProcess] ; SourceProcess

      xor rax, rax
      mov eax, [rsi+FPatch.Size] ; move Size

      call MmCopyVirtualMemoryM

      .if (rax = 0) ; read success?
        mov rdx, [rsi+FPatch.AddressFromPatch]
        mov eax, dword [rdx] ; mov readed value to eax

        mov ebx, eax  ; for IsDeveloper check
        mov ecx, eax  ; save original flag

        and eax, 4 ; if isAdmin exists in playerFlags, eax will be contain 4
        .if (eax <> 4)
          add ecx, 4 ; add 4(Admin) if it have not
        .endif

        and ebx, 128 ; if isDeveloper exists, ebx will be contain 128
        .if (ebx <> 128)
          add ecx, 128
        .endif

        mov eax, dword [rdx] ; copy readed value to eax again
        .if (eax <> ecx) ; compare old value and new value of playerFlags
          mov [rdx], ecx ; value is different, write to [[rsi+FPatch.AddressFromPatch]]
        .endif

      .endif

    .endif

 ;end of MmGetPhysicalAddress
 ;.endif
 ;.endif


  

cycleRepeat:
    mov r9, [rsi+FPatch.AddressToPatch+rdi] ;  TargetAddress (write to)

    .if (r9 = 0) ; if address in element == 0, exit from cycle
      jmp shellRepeat
    .endif

   ; xor rbx, rbx
   ; mov ebx, [rsi+FPatch.Size+rdi]
   ; mov rax, r9
   ; call MmCheckAddressM
   ; .if (rax > 0)
   ;   mov rax, [rsi+FPatch.AddressFromPatch+rdi]
   ;   call MmCheckAddressM
   ;   .if (rax > 0)

    mov r9, [rsi+FPatch.AddressToPatch+rdi] ;  TargetAddress (write to)  AGAIN(after check addr)

    mov r8, [r13+ShellData.TargetEProcess] ; TargetProcess

    .if (r8 > 0)
      mov rdx, [rsi+FPatch.AddressFromPatch+rdi] ; SourceAddress (write from)
      mov rcx, [r13+ShellData.CurrentEProcess] ; SourceProcess

      xor rax, rax
      mov eax, [rsi+FPatch.Size+rdi]                                 ; move Size

      call MmCopyVirtualMemoryM
    .endif

    add rdi, 24                                                 ; size of struct FPatch to next element

    .if (rdi < 120)                                             ; 120 - last of 5 elem
      jmp cycleRepeat
    .endif

   ; .endif ; end of MmGetPhysicalAddress
  ; .endif

  .endif  ; end of rsi > 0

  jmp  shellRepeat



competeRequest:
  mov byte [r14+CWay.ControlCode], 0                            ; signal to userMode app that requiest has been completed
  xor r8, r8
  mov r8d, 4 ; 4 ms to sleep for fast check
  call KeDelayExecutionThreadM


  

  ; jump to patchPlayerFlags after sleeping 4ms
  jmp patchPlayerFlagsAndOther


;competeRequest:
;  xor r8, r8                                                    ; sleep small time for "smart" checking next ControlCode if exists
;  mov r8d, 5h
;  call KeDelayExecutionThreadM
;  jmp shellRepeat


; function release below:


KeStackAttachProcessM:                                          ; KeStackAttachProcess(rcx - &EProcess, rdx - &APC_State)
  sub rsp, 28h
  lea rdx, qword [r13+ShellData.APC_State]                      ; put to rdx address of APC_State
  mov r15, qword [r12+ShellDataAddr.KeStackAttachProcess]
  call r15
  add rsp, 28h
  ret

KeUnstackDetachProcessM:                                        ; KeUnstackDetachProcess(rcx - &APC_State)
  sub rsp, 28h
  lea rcx, qword [r13+ShellData.APC_State]                      ; put to rcx address of APC_State
  mov r15, qword [r12+ShellDataAddr.KeUnstackDetachProcess]
  call r15
  add rsp, 28h
  ret

PsLookupProcessByProcessIdM:                                    ; PsLookupProcessByProcessId(rcx - PID, rdx - &EPROCESS)
  sub rsp, 28h
  mov r15, qword [r12+ShellDataAddr.PsLookupProcessByProcessId]
  call r15
  add rsp, 28h
  ret

ObfDereferenceObjectM:                                          ; ObfDereferenceObject(rcx - &Object)
  sub rsp, 28h
  mov r15, qword [r12+ShellDataAddr.ObfDereferenceObject]
  call r15
  add rsp, 28h
  ret

PsGetProcessPebM:                                                ; PsGetProcessPeb(rcx - EPROCESS)
  sub rsp, 28h
  mov rcx, [r13+ShellData.TargetEProcess]
  mov r15, [r12+ShellDataAddr.PsGetProcessPeb]
  call r15
  add rsp, 28h
  ret


; MmCopyVirtualMemory(rcx - sourceProcess, rdx - sourceAddress, r8 - targetProcess, r9 - targetAddress, SIZE_T bufferSize, KPROCESSOR_MODE PreviousMode, SIZE_T *returnSize))
MmCopyVirtualMemoryM:
  sub rsp, 58h

  mov [rsp+20h], rax                                             ; Size

  mov byte [rsp+28h], 0                                          ; PreviousMode (0 - KernelMode, 1 - UserMode)

  lea rax, [r13+ShellData.Arg1]
  mov [rsp+30h], rax                                             ; &ReturnSize

  ; TargetAddress, Process | SourceAddress, process here

  ; check address
  mov rbx, [rsp+20h] ; size

  mov rax, rdx
  call MmCheckAddressM
  .if (rax = 0)
    jmp AddrErrorM
  .endif

  mov rax, r9
  call MmCheckAddressM
  .if (rax = 0)
    jmp AddrErrorM
  .endif


  mov r15, [r12+ShellDataAddr.MmCopyVirtualMemory]
  call r15
  jmp NormalExitM

AddrErrorM:
  xor rax, rax
  mov al, -1

NormalExitM:

  add rsp, 58h
  ret

;MmGetPhysicalAddress(rcx - BaseAddress)
;MmGetPhysicalAddressM:
;  sub rsp, 28h
;  mov r15, [r12+ShellDataAddr.MmGetPhysicalAddress]
;  call r15
;  add rsp, 28h
;  ret


;(rax - BaseAddress, rbx - Size)
;RWMmCheckAddressM:
  ;xor rbx, rbx
  ;mov ebx, dword [r14+CWay.Size]
  ;call MmCheckAddressM
  ;ret

;(rax - BaseAddress, rbx - Size)
MmCheckAddressM:
  mov r15, [r12+ShellDataAddr.MyMmUserProbeAddress]
  add rax, rbx ; BaseAddress + Size

  .if (rax > r15)
    jmp badExitM
  .endif
  .if (rax < 0)
    jmp badExitM
  .endif

  ;from 0 to MyMmUserProbeAddress - valid userSpace
  mov rax, 1
  ret

badExitM:
  xor rax, rax
  ret

;ZwWaitForSingleObjectM:                                         ; ZwWaitForSingleObject(rcx - handleObj, r8d - Timeout, edx - Alertable)
  ;sub rsp, 28h
  ;xor r8d, r8d                                                  ; Timeout
  ;xor edx, edx                                                  ; Alertable
  ;mov r15, [r12+ShellDataAddr.ZwWaitForSingleObject]
  ;call r15
  ;add rsp, 28h
  ;ret

;ZwSetEventM:                                                    ; ZwSetEvent(rcx - handleObj, rdx - PreviousState - NULL)
;  sub rsp, 28h
;  xor rdx, rdx
;  mov r15, [r12+ShellDataAddr.ZwSetEvent]
;  call r15
;  add rsp, 28h
;  ret

;ZwCloseM:                                                       ; ZwClose(rcx - handleObj)
  ;sub rsp, 28h
  ;mov rcx, [r13+ShellData.SyncObj]
  ;mov r15, [r12+ShellDataAddr.ZwClose]
  ;call r15
  ;add rsp, 28h
  ;ret



;DbgPrintExM:                                                    ; DbgPrintEx(edx - DPFLTR_ERROR_LEVEL, ecx - DPFLTR_IHVDRIVER_ID, r8 - &text)
;  xor edx, edx                                                  ; DPFLTR_ERROR_LEVEL
;  lea ecx, dword [rdx+4D]                                       ; DPFLTR_IHVDRIVER_ID
;  mov r15, qword [r12+ShellDataAddr.DbgPrintEx]
;  call r15
;  ret


KeDelayExecutionThreadM:                                        ; KeDelayExecutionThread(edx - Alertable, ecx - WaitMode, r8 - &LARGE_INTEGER.QuadPart/&time)
  sub rsp, 28h
  xor edx, edx                                                  ; Alertable
  xor ecx, ecx                                                  ; WaitMode

  imul r8, -10000                                               ; r8 = r8*-10000
  mov [r13+ShellData.Arg0], qword r8                            ; save imul result to ShellData.TimeComputed
  lea r8, qword [r13+ShellData.Arg0]                            ; put &LARGE_INTEGER.Quadpart to r8

  mov r15, qword [r12+ShellDataAddr.KeDelayExecutionThread]
  call r15
  add rsp, 28h
  ret

ZwQueryVirtualMemoryM:                                           ; ZwQueryVirtualMemory(rcx - ProcessHandle, rdx - &BaseAddress, r8d - MEMORY_INFORMATION_CLASS(0), r9 - &MemoryInformation, qword ptr [rsp+20h] - sizeof(MemoryInformation), qword ptr [rsp+28h] - &RetVal)
  sub     rsp, 58h

  lea rax, [r13+ShellData.Arg1]
  mov [rsp+28h], rax                                             ; &RetLength

;lea rsi, qword [r13+ShellData.MBI+MEMORY_BASIC_INFORMATION.BaseAddress]
  mov qword [rsp+20h], 30h                                       ; sizeof(MemoryInformation)
  lea r9, [r13+ShellData.MBI]                                    ; address of begin struct MEMORY_BASIC_INFORMATION
  xor r8d, r8d                                                   ; MEMORY_INFORMATION_CLASS.MemoryBasicInformation
  mov rcx, 0FFFFFFFFFFFFFFFFh                                    ; ProcessHandle
  mov r15, [r12+ShellDataAddr.ZwQueryVirtualMemory]
  call r15

  add rsp, 58h
  ret





