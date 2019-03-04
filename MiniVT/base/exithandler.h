#pragma once

GUEST_REGS g_GuestRegs;

void HandleCPUID()
{
	if (g_GuestRegs.eax == 'Mini')
	{
		g_GuestRegs.ebx = 0x88888888;
		g_GuestRegs.ecx = 0x11111111;
		g_GuestRegs.edx = 0x12345678;
	}
	else Asm_CPUID(g_GuestRegs.eax,&g_GuestRegs.eax,&g_GuestRegs.ebx,&g_GuestRegs.ecx,&g_GuestRegs.edx);
}

void HandleInvd()
{
	Asm_Invd();
}

void HandleVmCall()
{
	ULONG JmpEIP;
	if (g_GuestRegs.eax == 'SVT')
	{
		JmpEIP = g_GuestRegs.eip + Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);
		Vmx_VmxOff();
		
		Asm_AfterVMXOff(g_GuestRegs.esp,JmpEIP);
	}
}

void HandleMsrRead()
{
	switch(g_GuestRegs.ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		{
			g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_CS);
			break;
		}
	case MSR_IA32_SYSENTER_ESP:
		{
			g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_ESP);
			break;
		}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
		{
			g_GuestRegs.eax = Vmx_VmRead(GUEST_SYSENTER_EIP);
			break;
		}
	default:
		g_GuestRegs.eax = Asm_ReadMsr(g_GuestRegs.ecx);
	}

}

void HandleMsrWrite()
{
	switch(g_GuestRegs.ecx)
	{
	case MSR_IA32_SYSENTER_CS:
		{
			Vmx_VmWrite(GUEST_SYSENTER_CS,g_GuestRegs.eax);
			break;
		}
	case MSR_IA32_SYSENTER_ESP:
		{
			Vmx_VmWrite(GUEST_SYSENTER_ESP,g_GuestRegs.eax);
			break;
		}
	case MSR_IA32_SYSENTER_EIP:	// KiFastCallEntry
		{
			Vmx_VmWrite(GUEST_SYSENTER_EIP,g_GuestRegs.eax);
			break;
		}
	default:
		Asm_WriteMsr(g_GuestRegs.ecx,g_GuestRegs.eax,g_GuestRegs.edx);
	}
}

void HandleCrAccess()
{
	ULONG		movcrControlRegister;
	ULONG		movcrAccessType;
	ULONG		movcrOperandType;
	ULONG		movcrGeneralPurposeRegister;
	ULONG		movcrLMSWSourceData;
	ULONG		ExitQualification;

	ExitQualification = Vmx_VmRead(EXIT_QUALIFICATION) ;
	movcrControlRegister = ( ExitQualification & 0x0000000F );
	movcrAccessType = ( ( ExitQualification & 0x00000030 ) >> 4 );
	movcrOperandType = ( ( ExitQualification & 0x00000040 ) >> 6 );
	movcrGeneralPurposeRegister = ( ( ExitQualification & 0x00000F00 ) >> 8 );

	//	Control Register Access (CR3 <-- reg32)
	//
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.eax );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ecx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.edx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ebx );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.esp );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.ebp );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.esi );
	}
	if( movcrControlRegister == 3 && movcrAccessType == 0 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
	{
		Vmx_VmWrite( GUEST_CR3, g_GuestRegs.edi );
	}
	//	Control Register Access (reg32 <-- CR3)
	//
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 0 )
	{
		g_GuestRegs.eax = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 1 )
	{
		g_GuestRegs.ecx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 2 )
	{
		g_GuestRegs.edx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 3 )
	{
		g_GuestRegs.ebx = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 4 )
	{
		g_GuestRegs.esp = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 5 )
	{
		g_GuestRegs.ebp = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 6 )
	{
		g_GuestRegs.esi = g_GuestRegs.cr3;
	}
	if( movcrControlRegister == 3 && movcrAccessType == 1 && movcrOperandType == 0 && movcrGeneralPurposeRegister == 7 )
	{
		g_GuestRegs.edi = g_GuestRegs.cr3;
	}  
}

extern "C" ULONG GetGuestRegsAddress()
{
	return (ULONG)&g_GuestRegs;
}

extern "C" void VMMEntryPoint()
{
	ULONG ExitReason;
	ULONG ExitInstructionLength;
	ULONG GuestResumeEIP;

	ExitReason = Vmx_VmRead(VM_EXIT_REASON);
	ExitInstructionLength = Vmx_VmRead(VM_EXIT_INSTRUCTION_LEN);

	g_GuestRegs.esp = Vmx_VmRead(GUEST_RSP);
	g_GuestRegs.eip = Vmx_VmRead(GUEST_RIP);
	g_GuestRegs.cr3 = Vmx_VmRead(GUEST_CR3);

	switch(ExitReason)
	{
	case EXIT_REASON_CPUID:
		{
			HandleCPUID();
			break;
		}
	case EXIT_REASON_INVD:
		{
			HandleInvd();
			break;
		}
	case EXIT_REASON_VMCALL:
		{
			HandleVmCall();
			break;
		}
	case EXIT_REASON_MSR_READ:
		{
			HandleMsrRead();
			break;
		}
	case EXIT_REASON_MSR_WRITE:
		{
			HandleMsrWrite();
			break;
		}
	case EXIT_REASON_CR_ACCESS:
		{
			HandleCrAccess();
			break;
		}
	default:
		break;
	}

Resume:
	GuestResumeEIP = g_GuestRegs.eip+ExitInstructionLength;
	Vmx_VmWrite(GUEST_RIP,GuestResumeEIP);
	Vmx_VmWrite(GUEST_RSP,g_GuestRegs.esp);
}