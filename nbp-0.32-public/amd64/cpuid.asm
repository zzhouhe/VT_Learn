.CODE
GetCpuIdInfo PROC
	push	rbp
	mov		rbp, rsp
	push	rbx
	push	rsi

	mov		[rbp+18h], rdx
	mov		eax, ecx
	cpuid
	mov		rsi, [rbp+18h]
	mov		[rsi], eax
	mov		[r8], ebx
	mov		[r9], ecx
	mov		rsi, [rbp+30h]
	mov		[rsi], edx	

	pop		rsi
	pop		rbx
	mov		rsp, rbp
	pop		rbp
	ret
GetCpuIdInfo ENDP


; CpuidWithEcxEdx (PULONG32 ecx (rcx), PULONG32 edx (rdx));
CpuidWithEcxEdx PROC
	mov		r9, rcx
	mov		r10, rdx

	mov		ecx, dword ptr [rcx]
	mov		edx, dword ptr [rdx]
	push		rbx
	cpuid
	pop		rbx
	mov		[r9], ecx	
	mov		[r10], edx
	ret
CpuidWithEcxEdx ENDP

END

