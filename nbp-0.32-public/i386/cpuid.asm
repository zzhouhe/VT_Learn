.686p
.model flat 
option casemap:none
.CODE
GetCpuIdInfo PROC StdCall _fn,ret_eax,ret_ebx,ret_ecx,ret_edx
    push eax
    push ebx
    push ecx
    push edx
    push esi
    
    mov eax,ret_ecx
    mov ecx,[eax]

    mov eax,_fn
    
    cpuid
    
    mov esi,ret_eax
    mov [esi], eax
    
    mov esi,ret_ebx
    mov [esi], ebx
    
    mov esi,ret_ecx
    mov [esi], ecx
    
    mov esi,ret_edx
    mov [esi], edx
    
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax    
ret
GetCpuIdInfo ENDP
END
