#ifndef VTASM_H
#define VTASM_H

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
    unsigned RevId: 32;
    unsigned szVmxOnRegion: 12;
    unsigned ClearBit: 1;
    unsigned Reserved: 3;
    unsigned PhysicalWidth: 1;
    unsigned DualMonitor: 1;
    unsigned MemoryType: 4;
    unsigned VmExitInformation: 1;
    unsigned Reserved2: 9;
} VMX_BASIC_MSR, *PVMX_BASIC_MSR;

ULONG Asm_GetEflags();
ULONG Asm_GetCs();
ULONG Asm_GetDs();
ULONG Asm_GetEs();
ULONG Asm_GetFs();
ULONG Asm_GetGs();
ULONG Asm_GetSs();
ULONG Asm_GetLdtr();
ULONG Asm_GetTr();

void Asm_SetGdtr(ULONG uBase,ULONG uLimit);
void Asm_SetIdtr(ULONG uBase,ULONG uLimit);

ULONG Asm_GetGdtBase();
ULONG Asm_GetIdtBase();
ULONG Asm_GetGdtLimit();
ULONG Asm_GetIdtLimit();

ULONG Asm_GetCr0();
ULONG Asm_GetCr2();
ULONG Asm_GetCr3();
ULONG Asm_GetCr4();
void Asm_SetCr0(ULONG uNewCr0);
void Asm_SetCr2(ULONG uNewCr2);
void Asm_SetCr3(ULONG uNewCr3);
void Asm_SetCr4(ULONG uNewCr4);

ULONG Asm_GetDr0();
ULONG Asm_GetDr1();
ULONG Asm_GetDr2();
ULONG Asm_GetDr3();
ULONG Asm_GetDr6();
ULONG Asm_GetDr7();
void Asm_SetDr0(ULONG uNewDr0);
void Asm_SetDr1(ULONG uNewDr1);
void Asm_SetDr2(ULONG uNewDr2);
void Asm_SetDr3(ULONG uNewDr3);
void Asm_SetDr6(ULONG uNewDr6);
void Asm_SetDr7(ULONG uNewDr7);

ULONG64 Asm_ReadMsr(ULONG uIndex);
void Asm_WriteMsr(ULONG uIndex,ULONG LowPart,ULONG HighPart);

void Asm_CPUID(ULONG uFn,PULONG uRet_EAX,PULONG uRet_EBX,PULONG uRet_ECX,PULONG uRet_EDX);

void Vmx_VmxOn(ULONG LowPart,ULONG HighPart);
void Vmx_VmxOff();
void Vmx_VmClear(ULONG LowPart,ULONG HighPart);
void Vmx_VmPtrld(ULONG LowPart,ULONG HighPart);
ULONG Vmx_VmRead(ULONG uField);
void Vmx_VmWrite(ULONG uField,ULONG uValue);
void Vmx_VmLaunch();
void Vmx_VmResume();
void Vmx_VmCall();

#endif
