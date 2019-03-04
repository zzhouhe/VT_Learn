.CODE


EXTERN	InHandleException:PROC
EXTERN	InHandleInterrupt:PROC


; InGeneralProtection()

; stack frame on entry:
; [TOS]			error code
; [TOS+0x08]	rip
; [TOS+0x10]	cs
; [TOS+0x18]	rflags
; [TOS+0x20]	rsp
; [TOS+0x28]	ss

InGeneralProtection PROC

	sub		rsp, 5*8+18*8

	mov		[rsp+5*8+00h], rcx
	mov		[rsp+5*8+08h], rdx
	mov		[rsp+5*8+10h], r8
	mov		[rsp+5*8+18h], r9
	mov		[rsp+5*8+20h], r10
	mov		[rsp+5*8+28h], r11
	mov		[rsp+5*8+30h], r12
	mov		[rsp+5*8+38h], r13
	mov		[rsp+5*8+40h], r14
	mov		[rsp+5*8+48h], r15
	mov		[rsp+5*8+50h], rdi
	mov		[rsp+5*8+58h], rsi
	mov		[rsp+5*8+60h], rbx
	mov		[rsp+5*8+68h], rbp

	mov		[rsp+5*8+78h], rax

	mov		rax, [rsp+5*8+18*8+20h]			; frame rsp
	mov		[rsp+5*8+70h], rax				; TRAP_FRAME.rsp

	mov		rax, [rsp+5*8+18*8+18h]			; frame rflags
	mov		[rsp+5*8+80h], rax				; TRAP_FRAME.rflags

	mov		rax, [rsp+5*8+18*8+08h]			; rip
	mov		[rsp+5*8+88h], rax				; TRAP_FRAME.rip
	

;	mov		rcx, gs:[0]					; CPU.SelfPointer
	lea		rdx, [rsp+5*8]
	mov		r8, 13							; #GP
	mov		r9, [rsp+5*8+18*8]
	call	InHandleException


	mov		rax, [rsp+5*8+70h]
	mov		[rsp+5*8+18*8+20h], rax			; frame rsp
	
	mov		rax, [rsp+5*8+80h]
	mov		[rsp+5*8+18*8+18h], rax			; frame rflags

	mov		rax, [rsp+5*8+88h]
	mov		[rsp+5*8+18*8+08h], rax			; rip

	mov		rcx, [rsp+5*8+00h]
	mov		rdx, [rsp+5*8+08h]
	mov		r8,  [rsp+5*8+10h]
	mov		r9,  [rsp+5*8+18h]
	mov		r10, [rsp+5*8+20h]
	mov		r11, [rsp+5*8+28h]
	mov		r12, [rsp+5*8+30h]
	mov		r13, [rsp+5*8+38h]
	mov		r14, [rsp+5*8+40h]
	mov		r15, [rsp+5*8+48h]
	mov		rdi, [rsp+5*8+50h]
	mov		rsi, [rsp+5*8+58h]
	mov		rbx, [rsp+5*8+60h]
	mov		rbp, [rsp+5*8+68h]

	mov		rax, [rsp+5*8+78h]

	add		rsp, 5*8+18*8+8

	iretq

InGeneralProtection ENDP


END