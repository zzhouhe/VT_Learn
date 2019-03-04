; only some boring stuff here...


.CODE

RegGetTSC PROC
;	rdtscp
	rdtsc
	shl		rdx, 32
	or		rax, rdx
	ret
RegGetTSC ENDP

RegGetRax PROC
	mov		rax, rax
	ret
RegGetRax ENDP


RegGetRbx PROC
	mov		rax, rbx
	ret
RegGetRbx ENDP


RegGetCs PROC
	mov		rax, cs
	ret
RegGetCs ENDP

RegGetDs PROC
	mov		rax, ds
	ret
RegGetDs ENDP

RegGetEs PROC
	mov		rax, es
	ret
RegGetEs ENDP

RegGetSs PROC
	mov		rax, ss
	ret
RegGetSs ENDP

RegGetFs PROC
	mov		rax, fs
	ret
RegGetFs ENDP

RegGetGs PROC
	mov		rax, gs
	ret
RegGetGs ENDP

RegGetCr0 PROC
	mov		rax, cr0
	ret
RegGetCr0 ENDP

RegGetCr2 PROC
	mov		rax, cr2
	ret
RegGetCr2 ENDP

RegGetCr3 PROC
	mov		rax, cr3
	ret
RegGetCr3 ENDP

RegSetCr3 PROC
	mov		cr3, rcx
	ret
RegSetCr3 ENDP

RegGetCr4 PROC
	mov		rax, cr4
	ret
RegGetCr4 ENDP

RegGetCr8 PROC
	mov		rax, cr8
	ret
RegGetCr8 ENDP

RegSetCr8 PROC
	mov		cr8, rcx
	ret
RegSetCr8 ENDP

RegGetDr6 PROC
	mov		rax, dr6
	ret
RegGetDr6 ENDP

RegGetDr0 PROC
	mov		rax, dr0
	ret
RegGetDr0 ENDP

RegGetDr1 PROC
	mov		rax, dr1
	ret
RegGetDr1 ENDP

RegGetDr2 PROC
	mov		rax, dr2
	ret
RegGetDr2 ENDP

RegGetDr3 PROC
	mov		rax, dr3
	ret
RegGetDr3 ENDP

RegSetDr0 PROC
	mov		dr0, rcx
	ret
RegSetDr0 ENDP

RegSetDr1 PROC
	mov		dr1, rcx
	ret
RegSetDr1 ENDP

RegSetDr2 PROC
	mov		dr2, rcx
	ret
RegSetDr2 ENDP

RegSetDr3 PROC
	mov		dr3, rcx
	ret
RegSetDr3 ENDP

RegGetRflags PROC
	pushfq
	pop		rax
	ret
RegGetRflags ENDP

RegGetRsp PROC
	mov		rax, rsp
	add		rax, 8
	ret
RegGetRsp ENDP

GetIdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
GetIdtBase ENDP

GetIdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
GetIdtLimit ENDP

GetGdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
GetGdtBase ENDP

GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP

;add by cini
GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP

;add end

GetTrSelector PROC
	str	rax
	ret
GetTrSelector ENDP



END
