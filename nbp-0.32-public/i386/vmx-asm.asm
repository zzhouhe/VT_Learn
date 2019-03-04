; /*
;   * Implemented by cini 2007 8
;   * Email:coosty@163.com
;   */
;
;extern	g_PageMapBasePhysicalAddress:QWORD

;extern	HvmEventCallback:PROC
;extern	McCloak:PROC


.686p
.model flat,StdCall
option casemap:none

EXTERN	 HvmEventCallback@16:PROC  


vmx_call MACRO
	BYTE	0Fh, 01h, 0C1h
ENDM

vmx_clear MACRO
	BYTE	066h, 0Fh, 0C7h
ENDM

vmx_ptrld MACRO
	BYTE	0Fh, 0C7h
ENDM

vmx_ptrst MACRO
	BYTE	0Fh, 0C7h
ENDM

vmx_read MACRO
	BYTE	0Fh, 078h
ENDM

vmx_write MACRO
	BYTE	0Fh, 079h
ENDM

vmx_on MACRO
	BYTE	0F3h, 0Fh, 0C7h
ENDM

vmx_off MACRO
	BYTE	0Fh, 01h, 0C4h
ENDM

vmx_resume MACRO
	BYTE	0Fh, 01h, 0C3h
ENDM

vmx_launch MACRO
	BYTE	0Fh, 01h, 0C2h
ENDM





MODRM_EAX_06 MACRO   ;/* [EAX], with reg/opcode: /6 */
	BYTE	030h
ENDM

MODRM_EAX_07 MACRO   ;/* [EAX], with reg/opcode: /7 */
	BYTE	038h
ENDM

MODRM_EAX_ECX MACRO  ;/* [EAX], [ECX] */
	BYTE	0C1h
ENDM



HVM_SAVE_ALL_NOSEGREGS MACRO
        push edi
        push esi
        push ebp
        push ebp ;        push esp
        push ebx
        push edx
        push ecx
        push eax
ENDM

HVM_RESTORE_ALL_NOSEGREGS MACRO
        pop eax
        pop ecx
        pop edx
        pop ebx
        pop ebp ;        pop esp
        pop ebp
        pop esi
        pop edi        
ENDM






.CODE





;void vmxPtrld(u64 addr)
VmxPtrld PROC StdCall _addr_low,_addr_high
	mov eax,8
	add eax,ebp
	vmx_ptrld
	MODRM_EAX_06
	ret
VmxPtrld ENDP

;void vmxPtrst(u64 addr)
VmxPtrst PROC StdCall _addr_low,_addr_high
	mov eax,8
	add eax,ebp
	vmx_ptrst
	MODRM_EAX_07
	ret
VmxPtrst ENDP

;void vmxClear(u64 addr)
VmxClear PROC StdCall _addr_low,_addr_high
	mov eax,8
	add eax,ebp
	vmx_clear
	MODRM_EAX_06
	ret
VmxClear ENDP

; vmxRead( field)
VmxRead PROC StdCall _field_low,_field_high
	mov eax,_field_low
	vmx_read
	MODRM_EAX_ECX  ;read value stored in ecx
	mov eax,ecx    ;return value stored in eax, so pull ecx to eax
	mov edx,0
	ret
VmxRead ENDP

; void vmxWrite( field,value)
VmxWrite PROC StdCall _field_low,_field_high,value_low,value_high
	mov eax,_field_low
	mov ecx,value_low	
	vmx_write
	MODRM_EAX_ECX  ;read value stored in ecx
	ret
VmxWrite ENDP

;_vmxOff()
VmxTurnOff PROC 
	vmx_off
	ret
VmxTurnOff ENDP

;void vmxOn(addr)
VmxTurnOn PROC StdCall _addr_low,_addr_high
	mov eax,8
	add eax,ebp
	vmx_on
	MODRM_EAX_06
	ret
VmxTurnOn ENDP

VmxVmCall PROC StdCall _HypercallNumber
	mov edx,_HypercallNumber
	vmx_call
	ret
VmxVmCall ENDP


;get_cr4()
get_cr4 PROC 
	mov eax,cr4
	ret
get_cr4 ENDP


; void set_in_cr4(mask)
set_in_cr4 PROC StdCall _mask
	mov eax,_mask
	mov ecx,cr4
	or  ecx,eax
	mov cr4,ecx	
	ret
set_in_cr4 ENDP

; void clear_in_cr4(mask)
clear_in_cr4 PROC StdCall _mask
	mov eax,_mask
	mov ecx,cr4
	not eax
	and ecx,eax
	mov cr4,ecx	
	ret
clear_in_cr4 ENDP





; Stack layout for vmxVmrun() call:
;
; ^                              ^
; |                              |
; | lots of pages for host stack |
; |                              |
; |------------------------------|   <- HostStackBottom(rcx) points here
; |         struct CPU           |
; --------------------------------

; vmxVmrun(PVOID HostStackBottom (rcx))

VmxLaunch PROC	
	vmx_launch
	ret
VmxLaunch ENDP

VmxResume PROC 	
	vmx_resume
	ret
VmxResume ENDP



;HvmEventCallback(PCPU Cpu,PGUEST_REGS GuestRegs,ULONG64 Ticks1)
VmxVmexitHandler PROC   StdCall  
	HVM_SAVE_ALL_NOSEGREGS
	
	mov     ecx,[esp + 20h]     ;PCUP
	mov 	ebx,esp		;ebx=GuestRegs
	;rdtsc
	
	push	edx     ;Tsc high --Ticks1 argv
	push	eax     ;Tsc low  --Ticks1 argv
	push	ebx     ;GuestRegs	
	push    ecx	;PCUP
	call	HvmEventCallback@16
	
	HVM_RESTORE_ALL_NOSEGREGS	
	vmx_resume
	ret

VmxVmexitHandler ENDP

END
