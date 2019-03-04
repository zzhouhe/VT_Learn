.686p
.model flat,StdCall
option casemap:none

; only some boring stuff here...


.CODE

RegGetTSC PROC
	rdtsc
	ret
RegGetTSC ENDP

RegGetRax PROC
	mov		eax, eax
	mov		edx, 0
	ret
RegGetRax ENDP


RegGetRbx PROC
	mov		eax, ebx
	mov		edx, 0
	ret
RegGetRbx ENDP





RegGetCs PROC
	mov		eax, cs
	ret
RegGetCs ENDP

RegGetDs PROC
	mov		eax, ds
	ret
RegGetDs ENDP

RegGetEs PROC
	mov		eax, es
	ret
RegGetEs ENDP

RegGetSs PROC
	mov		eax, ss
	ret
RegGetSs ENDP

RegGetFs PROC
	mov		eax, fs
	ret
RegGetFs ENDP

RegGetGs PROC
	mov		eax, gs
	ret
RegGetGs ENDP

RegSetCr3 PROC StdCall _CR3
	mov		eax, _CR3
	mov		cr3, eax
	ret
RegSetCr3 ENDP

RegGetCr0 PROC
	mov		eax, cr0
	ret
RegGetCr0 ENDP

RegGetCr2 PROC
	mov		eax, cr2
	ret
RegGetCr2 ENDP

RegGetCr3 PROC
	mov		eax, cr3
	ret
RegGetCr3 ENDP

RegGetCr4 PROC
	mov		eax, cr4
	ret
RegGetCr4 ENDP

RegGetDr0 PROC
	mov		eax, dr0
	ret
RegGetDr0 ENDP

RegGetDr1 PROC
	mov		eax, dr1
	ret
RegGetDr1 ENDP

RegGetDr2 PROC
	mov		eax, dr2
	ret
RegGetDr2 ENDP

RegGetDr3 PROC
	mov		eax, dr3
	ret
RegGetDr3 ENDP

RegSetDr0 PROC
;	mov		dr0, rcx
	ret
RegSetDr0 ENDP

RegSetDr1 PROC
;	mov		dr1, rcx
	ret
RegSetDr1 ENDP

RegSetDr2 PROC
;	mov		dr2, rcx
	ret
RegSetDr2 ENDP

RegSetDr3 PROC
;	mov		dr3, rcx
	ret
RegSetDr3 ENDP

RegGetRflags PROC
	pushfd
	pop		eax
	ret
RegGetRflags ENDP

RegGetRsp PROC
	mov		eax, esp
	add		eax, 4
	ret
RegGetRsp ENDP



RegSetRsp PROC StdCall _ESP
	mov	esp, _ESP
	ret
RegSetRsp ENDP

GetIdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		eax, DWORD PTR idtr[2]
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
	mov		eax, DWORD PTR gdtr[2]
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

	sldt	eax
	ret
GetLdtr ENDP

;add end

GetTrSelector PROC
	str	eax
	ret
GetTrSelector ENDP



END
