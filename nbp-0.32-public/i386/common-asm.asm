.686p
.model flat,StdCall
option casemap:none

EXTERN	 HvmSubvertCpu@4:PROC  
EXTERN	 HvmResumeGuest@0 : PROC



CM_SAVE_ALL_NOSEGREGS MACRO
        push edi
        push esi
        push ebp
        push ebp ;        push esp
        push ebx
        push edx
        push ecx
        push eax
ENDM

CM_RESTORE_ALL_NOSEGREGS MACRO
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

cm_clgi MACRO
	BYTE	0Fh, 01h, 0DDh
ENDM

cm_stgi MACRO
	BYTE	0Fh, 01h, 0DCh
ENDM


CmClgi PROC
	cm_clgi
	ret
CmClgi ENDP

CmStgi PROC
	cm_stgi
	ret
CmStgi ENDP

CmCli PROC
	cli
	ret
CmCli  ENDP

CmSti PROC
	sti
	ret
CmSti ENDP

CmDebugBreak PROC
	int	3
	ret
CmDebugBreak ENDP

; CmReloadGdtr (PVOID GdtBase (rcx), ULONG GdtLimit (rdx) );

CmReloadGdtr PROC StdCall _GdtBase,_GdtLimit
	push	_GdtBase
	shl	_GdtLimit, 16
	push	_GdtLimit
	lgdt	fword ptr [esp+2]	; do not try to modify stack selector with this ;)
	pop	eax
	pop	eax
	ret
CmReloadGdtr ENDP

; CmReloadIdtr (PVOID IdtBase (rcx), ULONG IdtLimit (rdx) );

CmReloadIdtr PROC StdCall _IdtBase,_IdtLimit
	push	_IdtBase
	shl	_IdtLimit, 16
	push	_IdtLimit
	lidt	fword ptr [esp+2]	; do not try to modify stack selector with this ;)
	pop	eax
	pop	eax
	ret
CmReloadIdtr ENDP

; CmSetBluepillESDS ();

CmSetBluepillESDS PROC
	mov		eax, 18h			; this must be equal to BP_GDT64_DATA (bluepill.h)
	mov		ds, eax
	mov		es, eax
	ret
CmSetBluepillESDS ENDP

; CmSetBluepillGS ();

CmSetBluepillGS PROC
	mov		eax, 18h			; this must be equal to BP_GDT64_PCR (bluepill.h)
	mov		gs, eax
	ret
CmSetBluepillGS ENDP

; CmSetDS (ULONG Selector (rcx) );

CmSetDS PROC StdCall _Selector
	mov		eax,_Selector
	mov		ds, eax
	ret
CmSetDS ENDP

; CmSetES (ULONG Selector (rcx) );

CmSetES PROC StdCall _Selector
	mov		eax,_Selector
	mov		es, eax
	ret
CmSetES ENDP

; CmInvalidatePage (PVOID PageVA (rcx) );

CmInvalidatePage PROC StdCall _PageVA
	invlpg	[_PageVA]
	ret
CmInvalidatePage ENDP


; CmSubvert (PVOID  GuestRsp);
CmSubvert PROC StdCall _GuestRsp


	CM_SAVE_ALL_NOSEGREGS


	mov	eax,esp
	push	eax        ;setup esp to argv[0]
	call	HvmSubvertCpu@4
	ret

CmSubvert ENDP

; CmSlipIntoMatrix (PVOID  GuestRsp);
CmSlipIntoMatrix PROC StdCall _GuestRsp
	pop	ebp	
	call   HvmResumeGuest@0
	CM_RESTORE_ALL_NOSEGREGS	
	ret

CmSlipIntoMatrix ENDP



;CmIOIn(Port)
CmIOIn PROC StdCall _Port
	mov edx,_Port
	in  eax,dx
	ret

CmIOIn ENDP

;CmIOOUT(Port,Data)
CmIOOutB PROC StdCall _Port,_Data
	mov  eax,_Data
	mov  edx,_Port
	out  dx,al
	ret
CmIOOutB ENDP

CmIOOutW PROC StdCall _Port,_Data
	mov  eax,_Data
	mov  edx,_Port
	out  dx,ax
	ret
CmIOOutW ENDP

CmIOOutD PROC StdCall _Port,_Data
	mov  eax,_Data
	mov  edx,_Port
	out  dx,eax
	ret
CmIOOutD ENDP





CmInitSpinLock PROC StdCall BpSpinLock
	mov	eax,BpSpinLock
	and	dword ptr [eax], 0
	ret
CmInitSpinLock ENDP


CmAcquireSpinLock PROC StdCall BpSpinLock
	mov	eax,BpSpinLock
loop_down:
	lock	bts dword ptr [eax], 0
	jb	loop_down
	ret
CmAcquireSpinLock ENDP


CmReleaseSpinLock PROC StdCall BpSpinLock
	mov	eax,BpSpinLock
	lock	btr dword ptr [eax], 0
	ret
CmReleaseSpinLock ENDP


END
