.686p
.model flat,StdCall
option casemap:none


.CODE




; InGeneralProtection()

; stack frame on entry:
; [TOS]			error code
; [TOS+0x08]	rip
; [TOS+0x10]	cs
; [TOS+0x18]	rflags
; [TOS+0x20]	rsp
; [TOS+0x28]	ss

InGeneralProtection PROC



InGeneralProtection ENDP

InDispatcher PROC


InDispatcher ENDP






END
