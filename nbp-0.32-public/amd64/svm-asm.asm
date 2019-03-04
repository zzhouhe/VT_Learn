; 
; Copyright holder: Invisible Things Lab
; 
; This software is protected by domestic and International
; copyright laws. Any use (including publishing and
; distribution) of this software requires a valid license
; from the copyright holder.
;
; This software is provided for the educational use only
; during the Black Hat training. This software should not
; be used on production systems.
;
;

extern	g_PageMapBasePhysicalAddress:QWORD
extern	HvmEventCallback:PROC


svm_vmload MACRO
	BYTE	0Fh, 01h, 0DAh
ENDM


svm_vmsave MACRO
	BYTE	0Fh, 01h, 0DBh
ENDM


svm_vmrun MACRO
	BYTE	0Fh, 01h, 0D8h
ENDM


svm_vmmcall MACRO
	BYTE	0Fh, 01h, 0D9h
ENDM


.CODE

; SvmVmsave (PHYSICAL_ADDRESS vmcb_pa (rcx) );

SvmVmsave PROC
	mov		rax, rcx
	svm_vmsave
	ret
SvmVmsave ENDP

; SvmVmload (PHYSICAL_ADDRESS vmcb_pa (rcx) );

SvmVmload PROC
	mov		rax, rcx
	svm_vmload
	ret
SvmVmload ENDP


; Stack layout for SvmVmrun() call:

;        ^                ^
;        |                |
;RSP --> ------------------
;        |                |  (5*8)
;        ------------------
;        |                |
;        | GUEST_REGS     |  (16*8)
;        |                |
;        ------------------ <- HostStackBottom(rcx) points here
;        |                |
;        | CPU            |
;        |                |
;        ------------------

; SvmVmrun(PVOID HostStackBottom (rcx))
SvmVmrun PROC


	lea		rsp, [rcx-16*8-5*8]		; backup 14 regs and leave space for FASTCALL call

	mov		rax, [g_PageMapBasePhysicalAddress]
	mov		cr3, rax

	mov		rax, [rsp+16*8+5*8+8]	; CPU.Svm.VmcbToContinuePA
	svm_vmload

@loop:
	mov		rax, [rsp+16*8+5*8+8]	; CPU.Svm.VmcbToContinuePA

	svm_vmrun

	; save guest state
	mov		[rsp+5*8+08h], rcx
	mov		[rsp+5*8+10h], rdx
	mov		[rsp+5*8+18h], rbx
	mov		[rsp+5*8+28h], rbp
	mov		[rsp+5*8+30h], rsi
	mov		[rsp+5*8+38h], rdi
	mov		[rsp+5*8+40h], r8
	mov		[rsp+5*8+48h], r9
	mov		[rsp+5*8+50h], r10
	mov		[rsp+5*8+58h], r11
	mov		[rsp+5*8+60h], r12
	mov		[rsp+5*8+68h], r13
	mov		[rsp+5*8+70h], r14
	mov		[rsp+5*8+78h], r15

	lea		rdx, [rsp+5*8]			; PGUEST_REGS
	lea		rcx, [rsp+16*8+5*8]		; PCPU
	call		HvmEventCallback

	; restore guest state (HvmEventCallback migth have alternated the guest state)

	mov		rcx, [rsp+5*8+08h]
	mov		rdx, [rsp+5*8+10h]
	mov		rbx, [rsp+5*8+18h]
	mov		rbp, [rsp+5*8+28h]
	mov		rsi, [rsp+5*8+30h]
	mov		rdi, [rsp+5*8+38h]
	mov		r8, [rsp+5*8+40h]
	mov		r9, [rsp+5*8+48h]
	mov		r10, [rsp+5*8+50h]
	mov		r11, [rsp+5*8+58h]
	mov		r12, [rsp+5*8+60h]
	mov		r13, [rsp+5*8+68h]
	mov		r14, [rsp+5*8+70h]
	mov		r15, [rsp+5*8+78h]
	
	jmp		@loop

SvmVmrun ENDP



END
