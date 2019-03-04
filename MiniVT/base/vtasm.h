/*
Author:Xiaobao
QQ:1121402724
*/
#pragma  once

typedef struct _MSR
{
	ULONG LowPart;
	ULONG HighPart;
}MSR,*PMSR;

typedef union
{
	struct
	{
		unsigned PE:1;
		unsigned MP:1;
		unsigned EM:1;
		unsigned TS:1;
		unsigned ET:1;
		unsigned NE:1;
		unsigned Reserved_1:10;
		unsigned WP:1;
		unsigned Reserved_2:1;
		unsigned AM:1;
		unsigned Reserved_3:10;
		unsigned NW:1;
		unsigned CD:1;
		unsigned PG:1;
		//unsigned Reserved_64:32;
	};

}_CR0;

typedef union
{
	struct{
		unsigned VME:1;
		unsigned PVI:1;
		unsigned TSD:1;
		unsigned DE:1;
		unsigned PSE:1;
		unsigned PAE:1;
		unsigned MCE:1;
		unsigned PGE:1;
		unsigned PCE:1;
		unsigned OSFXSR:1;
		unsigned PSXMMEXCPT:1;
		unsigned UNKONOWN_1:1;		//These are zero
		unsigned UNKONOWN_2:1;		//These are zero
		unsigned VMXE:1;			//It's zero in normal
		unsigned Reserved:18;		//These are zero
		//unsigned Reserved_64:32;
	};
}_CR4;

typedef union
{
	struct
	{
		unsigned CF:1;
		unsigned Unknown_1:1;	//Always 1
		unsigned PF:1;
		unsigned Unknown_2:1;	//Always 0
		unsigned AF:1;
		unsigned Unknown_3:1;	//Always 0
		unsigned ZF:1;
		unsigned SF:1;
		unsigned TF:1;
		unsigned IF:1;
		unsigned DF:1;
		unsigned OF:1;
		unsigned TOPL:2;
		unsigned NT:1;
		unsigned Unknown_4:1;
		unsigned RF:1;
		unsigned VM:1;
		unsigned AC:1;
		unsigned VIF:1;
		unsigned VIP:1;
		unsigned ID:1;
		unsigned Reserved:10;	//Always 0
		//unsigned Reserved_64:32;	//Always 0
	};
}_EFLAGS;

typedef union
{
	struct
	{
		unsigned SSE3:1;
		unsigned PCLMULQDQ:1;
		unsigned DTES64:1;
		unsigned MONITOR:1;
		unsigned DS_CPL:1;
		unsigned VMX:1;
		unsigned SMX:1;
		unsigned EIST:1;
		unsigned TM2:1;
		unsigned SSSE3:1;
		unsigned Reserved:22;
	};

}_CPUID_ECX;

typedef struct _IA32_FEATURE_CONTROL_MSR
{
	unsigned Lock			:1;		// Bit 0 is the lock bit - cannot be modified once lock is set
	unsigned Reserved1		:1;		// Undefined
	unsigned EnableVmxon	:1;		// Bit 2. If this bit is clear, VMXON causes a general protection exception
	unsigned Reserved2		:29;	// Undefined
	unsigned Reserved3		:32;	// Undefined

} IA32_FEATURE_CONTROL_MSR;

typedef struct _VMX_BASIC_MSR
{
	unsigned RevId: 32;//∞Ê±æ∫≈–≈œ¢
	unsigned szVmxOnRegion: 12;
	unsigned ClearBit: 1;
	unsigned Reserved: 3;
	unsigned PhysicalWidth: 1;
	unsigned DualMonitor: 1;
	unsigned MemoryType: 4;
	unsigned VmExitInformation: 1;
	unsigned Reserved2: 9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;

extern "C" ULONG Asm_GetEflags();
extern "C" ULONG Asm_GetCs();
extern "C" ULONG Asm_GetDs();
extern "C" ULONG Asm_GetEs();
extern "C" ULONG Asm_GetFs();
extern "C" ULONG Asm_GetGs();
extern "C" ULONG Asm_GetSs();
extern "C" ULONG Asm_GetLdtr();
extern "C" ULONG Asm_GetTr();

extern "C" void Asm_SetGdtr(ULONG uBase,ULONG uLimit);
extern "C" void Asm_SetIdtr(ULONG uBase,ULONG uLimit);

extern "C" ULONG Asm_GetGdtBase();
extern "C" ULONG Asm_GetIdtBase();
extern "C" ULONG Asm_GetGdtLimit();
extern "C" ULONG Asm_GetIdtLimit();

extern "C" ULONG Asm_GetCr0();
extern "C" ULONG Asm_GetCr2();
extern "C" ULONG Asm_GetCr3();
extern "C" ULONG Asm_GetCr4();
extern "C" void Asm_SetCr0(ULONG uNewCr0);
extern "C" void Asm_SetCr2(ULONG uNewCr2);
extern "C" void Asm_SetCr3(ULONG uNewCr3);
extern "C" void Asm_SetCr4(ULONG uNewCr4);

extern "C" ULONG Asm_GetDr0();
extern "C" ULONG Asm_GetDr1();
extern "C" ULONG Asm_GetDr2();
extern "C" ULONG Asm_GetDr3();
extern "C" ULONG Asm_GetDr6();
extern "C" ULONG Asm_GetDr7();
extern "C" void Asm_SetDr0(ULONG uNewDr0);
extern "C" void Asm_SetDr1(ULONG uNewDr1);
extern "C" void Asm_SetDr2(ULONG uNewDr2);
extern "C" void Asm_SetDr3(ULONG uNewDr3);
extern "C" void Asm_SetDr6(ULONG uNewDr6);
extern "C" void Asm_SetDr7(ULONG uNewDr7);

extern "C" _CR0 Asm_GetCr0Ex();
extern "C" _CR4 Asm_GetCr4Ex();
extern "C" _EFLAGS Asm_GetEflagsEx();
extern "C" void Asm_SetCr0Ex(_CR0 cr0);
extern "C" void Asm_SetCr4Ex(_CR4 cr4);

extern "C" ULONG64 Asm_ReadMsr(ULONG uIndex);
extern "C" void Asm_ReadMsrEx(ULONG uIndex,PMSR msr);
extern "C" void Asm_WriteMsr(ULONG uIndex,ULONG LowPart,ULONG HighPart);

extern "C" void Asm_CPUID(ULONG uFn,PULONG uRet_EAX,PULONG uRet_EBX,PULONG uRet_ECX,PULONG uRet_EDX);
extern "C" void Asm_Invd();

extern "C" void Vmx_VmxOn(ULONG LowPart,ULONG HighPart);
extern "C" void Vmx_VmxOff();
extern "C" void Vmx_VmClear(ULONG LowPart,ULONG HighPart);
extern "C" void Vmx_VmPtrld(ULONG LowPart,ULONG HighPart);
extern "C" ULONG Vmx_VmRead(ULONG uField);
extern "C" void Vmx_VmWrite(ULONG uField,ULONG uValue);
extern "C" void Vmx_VmLaunch();
extern "C" void Vmx_VmResume();
extern "C" void Vmx_VmCall(ULONG uCallNumber);

extern "C" void Asm_VMMEntryPoint();

extern "C" void Asm_SetupVMCS();

extern "C" ULONG Asm_GetGuestReturn();
extern "C" ULONG Asm_GetGuestESP();

extern "C" void Asm_AfterVMXOff(ULONG JmpESP,ULONG JmpEIP);