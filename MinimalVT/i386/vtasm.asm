.686p
.model flat, stdcall
option casemap:none

.data

.code

Asm_CPUID	Proc	uses ebx esi edi fn:dword, ret_eax:dword, ret_ebx:dword, ret_ecx:dword, ret_edx:dword
        mov	eax, fn
        cpuid
        mov	esi, ret_eax
        mov	dword ptr [esi], eax
        mov	esi, ret_ebx
        mov	dword ptr [esi], ebx
        mov	esi, ret_ecx
        mov	dword ptr [esi], ecx
        mov	esi, ret_edx
        mov	dword ptr [esi], edx
        ret
Asm_CPUID 	Endp

Asm_ReadMsr		Proc	Index:dword
        mov	ecx,Index
        rdmsr
        ret
Asm_ReadMsr		Endp

Asm_WriteMsr	Proc	Index:dword,LowPart,HighPart
        mov	ecx, Index
        mov	eax, LowPart
        mov	edx, HighPart
        wrmsr
        ret
Asm_WriteMsr 	Endp

Asm_Invd Proc
        invd
        ret
Asm_Invd Endp

Asm_GetCs PROC
        mov		eax, cs
        ret
Asm_GetCs ENDP

Asm_GetDs PROC
        mov		eax, ds
        ret
Asm_GetDs ENDP

Asm_GetEs PROC
        mov		eax, es
        ret
Asm_GetEs ENDP

Asm_GetSs PROC
        mov		eax, ss
        ret
Asm_GetSs ENDP

Asm_GetFs PROC
        mov		eax, fs
        ret
Asm_GetFs ENDP

Asm_GetGs PROC
        mov		eax, gs
        ret
Asm_GetGs ENDP

Asm_GetCr0		Proc
        mov 	eax, cr0
        ret
Asm_GetCr0 		Endp

Asm_GetCr3		Proc
        mov 	eax, cr3
        ret
Asm_GetCr3 		Endp

Asm_GetCr4		Proc
        mov 	eax, cr4
        ret
Asm_GetCr4 		Endp

Asm_SetCr0		Proc 	NewCr0:dword
        mov 	eax, NewCr0
        mov	cr0, eax
        ret
Asm_SetCr0 		Endp

Asm_SetCr2		Proc 	NewCr2:dword
        mov 	eax, NewCr2
        mov	cr2, eax
        ret
Asm_SetCr2 		Endp

Asm_SetCr3		Proc 	NewCr3:dword
        mov 	eax, NewCr3
        mov	cr3, eax
        ret
Asm_SetCr3 		Endp

Asm_SetCr4		Proc	NewCr4:dword
        mov 	eax,NewCr4
        mov 	cr4, eax
        ret
Asm_SetCr4 		Endp

Asm_GetDr0 PROC
        mov		eax, dr0
        ret
Asm_GetDr0 ENDP

Asm_GetDr1 PROC
        mov		eax, dr1
        ret
Asm_GetDr1 ENDP

Asm_GetDr2 PROC
        mov		eax, dr2
        ret
Asm_GetDr2 ENDP

Asm_GetDr3 PROC
        mov		eax, dr3
        ret
Asm_GetDr3 ENDP

Asm_GetDr6 PROC
        mov		eax, dr6
        ret
Asm_GetDr6 ENDP

Asm_GetDr7 PROC
        mov		eax, dr7
        ret
Asm_GetDr7 ENDP

Asm_SetDr0 PROC
        mov		dr0, ecx
        ret
Asm_SetDr0 ENDP

Asm_SetDr1 PROC
        mov		dr1, ecx
        ret
Asm_SetDr1 ENDP

Asm_SetDr2 PROC
        mov		dr2, ecx
        ret
Asm_SetDr2 ENDP

Asm_SetDr3 PROC
        mov		dr3, ecx
        ret
Asm_SetDr3 ENDP

Asm_SetDr6 PROC nNewDr6:DWORD
        mov eax,nNewDr6
        mov		dr6, eax
        ret
Asm_SetDr6 ENDP

Asm_SetDr7 PROC	nNewDr7:DWORD
        mov eax,nNewDr7
        mov		dr7, eax
        ret
Asm_SetDr7 ENDP

Asm_GetEflags PROC
        pushfd
        pop		eax
        ret
Asm_GetEflags ENDP

Asm_GetIdtBase PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        mov		eax, dword PTR idtr[2]
        ret
Asm_GetIdtBase ENDP

Asm_GetIdtLimit PROC
        LOCAL	idtr[10]:BYTE
        sidt	idtr
        mov		ax, WORD PTR idtr[0]
        ret
Asm_GetIdtLimit ENDP

Asm_GetGdtBase PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov		eax, dword PTR gdtr[2]
        ret
Asm_GetGdtBase ENDP

Asm_GetGdtLimit PROC
        LOCAL	gdtr[10]:BYTE
        sgdt	gdtr
        mov		ax, WORD PTR gdtr[0]
        ret
Asm_GetGdtLimit ENDP

Asm_GetLdtr PROC
        sldt	eax
        ret
Asm_GetLdtr ENDP

Asm_GetTr PROC
        str	eax
        ret
Asm_GetTr ENDP

Vmx_VmxOn Proc LowPart:dword,HighPart:dword
        push HighPart
        push LowPart
        Vmxon qword ptr [esp]
        add esp,8
        ret
Vmx_VmxOn Endp

Vmx_VmxOff Proc
        Vmxoff
        ret
Vmx_VmxOff Endp

Vmx_VmPtrld Proc LowPart:dword,HighPart:dword
        push HighPart
        push LowPart
        vmptrld qword ptr [esp]
        add esp,8
        ret
Vmx_VmPtrld endp

Vmx_VmClear Proc LowPart:dword,HighPart:dword
        push HighPart
        push LowPart
        vmclear qword ptr [esp]
        add esp,8
        ret
Vmx_VmClear endp

Vmx_VmRead Proc uses ecx Field:dword
        mov eax,Field
        vmread ecx,eax
        mov eax,ecx
        ret
Vmx_VmRead endp

Vmx_VmWrite Proc uses ecx Field:dword,Value:dword
        mov eax,Field
        mov ecx,Value
        vmwrite eax,ecx
        ret
Vmx_VmWrite endp

Vmx_VmCall Proc
        vmcall
        ret
Vmx_VmCall endp

Vmx_VmLaunch Proc
        vmlaunch
        ret
Vmx_VmLaunch endp

Vmx_VmResume Proc
        vmresume
        ret
Vmx_VmResume endp


END
