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

.686p
.model flat,StdCall
option casemap:none

extern	g_PageMapBasePhysicalAddress:QWORD
EXTERN	HvmEventCallback@16:PROC  
extern	McCloak@0:PROC


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

SvmVmsave PROC	StdCall _vmcb_pa_low,_vmcb_pa_high
	mov		eax, _vmcb_pa_low
	svm_vmsave
	ret
SvmVmsave ENDP

; SvmVmload (PHYSICAL_ADDRESS vmcb_pa (rcx) );

SvmVmload PROC	StdCall _vmcb_pa_low,_vmcb_pa_high
	mov		eax, _vmcb_pa_low
	svm_vmload
	ret
SvmVmload ENDP


; Stack layout for SvmVmrun() call:
;
; ^                              ^
; |                              |
; | lots of pages for host stack |
; |                              |
; |------------------------------|   <- HostStackBottom(rcx) points here
; |         struct CPU           |
; --------------------------------

; SvmVmrun(PVOID HostStackBottom (rcx))

SvmVmrun PROC PROC StdCall _HostStackBottom
	ret
SvmVmrun ENDP



END
