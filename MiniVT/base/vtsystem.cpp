#include "stdafx.h"
#include "vtsystem.h"
#include "vtasm.h"
#include "exithandler.h"
#include "common.h"

VMX_CPU g_VMXCPU;

NTSTATUS AllocateVMXRegion()
{
	PVOID pVMXONRegion;
	PVOID pVMCSRegion;
	PVOID pHostEsp;

	pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool,0x1000,'vmon'); //4KB
	if (!pVMXONRegion)
	{
		Log("ERROR:申请VMXON内存区域失败!",0);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMXONRegion,0x1000);

	pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool,0x1000,'vmcs');
	if (!pVMCSRegion)
	{
		Log("ERROR:申请VMCS内存区域失败!",0);
		ExFreePoolWithTag(pVMXONRegion,0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMCSRegion,0x1000);

	pHostEsp = ExAllocatePoolWithTag(NonPagedPool,0x2000,'mini');
	if (!pHostEsp)
	{
		Log("ERROR:申请宿主机堆载区域失败!",0);
		ExFreePoolWithTag(pVMXONRegion,0x1000);
		ExFreePoolWithTag(pVMCSRegion,0x1000);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pHostEsp,0x2000);

	Log("TIP:VMXON内存区域地址",pVMXONRegion);
	Log("TIP:VMCS内存区域地址",pVMCSRegion);
	Log("TIP:宿主机堆载区域地址",pHostEsp);

	g_VMXCPU.pVMXONRegion = pVMXONRegion;
	g_VMXCPU.pVMXONRegion_PA = MmGetPhysicalAddress(pVMXONRegion);
	g_VMXCPU.pVMCSRegion = pVMCSRegion;
	g_VMXCPU.pVMCSRegion_PA = MmGetPhysicalAddress(pVMCSRegion);
	g_VMXCPU.pHostEsp = pHostEsp;
	return STATUS_SUCCESS;
}

void SetupVMXRegion()
{
	VMX_BASIC_MSR Msr;
	ULONG uRevId;
	_CR4 uCr4;
	_EFLAGS uEflags;

	RtlZeroMemory(&Msr,sizeof(Msr));

	*((PULONG)&Msr) = Asm_ReadMsr(MSR_IA32_VMX_BASIC);
	uRevId = Msr.RevId;

	*((PULONG)g_VMXCPU.pVMXONRegion) = uRevId;
	*((PULONG)g_VMXCPU.pVMCSRegion) = uRevId;

	Log("TIP:VMX版本号信息",uRevId);

	*((PULONG)&uCr4) = Asm_GetCr4();
	uCr4.VMXE = 1;
	Asm_SetCr4(*((PULONG)&uCr4));

	Vmx_VmxOn(g_VMXCPU.pVMXONRegion_PA.LowPart,g_VMXCPU.pVMXONRegion_PA.HighPart);
	*((PULONG)&uEflags) = Asm_GetEflags();
	if (uEflags.CF != 0)
	{
		Log("ERROR:VMXON指令调用失败!",0);
		return;
	}
	Log("SUCCESS:VMXON指令调用成功!",0);
}

extern "C" void SetupVMCS()
{
	_EFLAGS uEflags;
	ULONG GdtBase,IdtBase;
	SEGMENT_SELECTOR SegmentSelector;
	ULONG uCPUBase,uExceptionBitmap;

	Vmx_VmClear(g_VMXCPU.pVMCSRegion_PA.LowPart,g_VMXCPU.pVMCSRegion_PA.HighPart);
	*((PULONG)&uEflags) = Asm_GetEflags();
	if (uEflags.CF != 0 || uEflags.ZF != 0)
	{
		Log("ERROR:VMCLEAR指令调用失败!",0);
		return;
	}
	Log("SUCCESS:VMCLEAR指令调用成功!",0);
	Vmx_VmPtrld(g_VMXCPU.pVMCSRegion_PA.LowPart,g_VMXCPU.pVMCSRegion_PA.HighPart);

	GdtBase = Asm_GetGdtBase();
	IdtBase = Asm_GetIdtBase();

	//
	// 1.Guest State Area
	//
	Vmx_VmWrite(GUEST_CR0,Asm_GetCr0());
	Vmx_VmWrite(GUEST_CR3,Asm_GetCr3());
	Vmx_VmWrite(GUEST_CR4,Asm_GetCr4());

	Vmx_VmWrite(GUEST_DR7,0x400);
	Vmx_VmWrite(GUEST_RFLAGS,Asm_GetEflags());

	FillGuestSelectorData(GdtBase,ES,Asm_GetEs());
	FillGuestSelectorData(GdtBase,FS,Asm_GetFs());
	FillGuestSelectorData(GdtBase,DS,Asm_GetDs());
	FillGuestSelectorData(GdtBase,CS,Asm_GetCs());
	FillGuestSelectorData(GdtBase,SS,Asm_GetSs());
	FillGuestSelectorData(GdtBase,GS,Asm_GetGs());
	FillGuestSelectorData(GdtBase,TR,Asm_GetTr());
	FillGuestSelectorData(GdtBase,LDTR,Asm_GetLdtr());

	Vmx_VmWrite(GUEST_GDTR_BASE,GdtBase);
	Vmx_VmWrite(GUEST_GDTR_LIMIT,Asm_GetGdtLimit());
	Vmx_VmWrite(GUEST_IDTR_BASE,IdtBase);
	Vmx_VmWrite(GUEST_IDTR_LIMIT,Asm_GetIdtLimit());

	Vmx_VmWrite(GUEST_IA32_DEBUGCTL,Asm_ReadMsr(MSR_IA32_DEBUGCTL)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH,Asm_ReadMsr(MSR_IA32_DEBUGCTL)>>32);

	Vmx_VmWrite(GUEST_SYSENTER_CS,Asm_ReadMsr(MSR_IA32_SYSENTER_CS)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_ESP,Asm_ReadMsr(MSR_IA32_SYSENTER_ESP)&0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_EIP,Asm_ReadMsr(MSR_IA32_SYSENTER_EIP)&0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(GUEST_RSP,Asm_GetGuestESP());
	Vmx_VmWrite(GUEST_RIP,Asm_GetGuestReturn());// 指定vmlaunch客户机的入口点 这里我们让客户机继续执行加载驱动的代码

	Vmx_VmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	Vmx_VmWrite(GUEST_ACTIVITY_STATE, 0);
	Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);
	Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//
	// 2.Host State Area
	//
	Vmx_VmWrite(HOST_CR0,Asm_GetCr0());
	Vmx_VmWrite(HOST_CR3,Asm_GetCr3());
	Vmx_VmWrite(HOST_CR4,Asm_GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR,Asm_GetEs() & 0xFFF8);
	Vmx_VmWrite(HOST_CS_SELECTOR,Asm_GetCs() & 0xFFF8);
	Vmx_VmWrite(HOST_DS_SELECTOR,Asm_GetDs() & 0xFFF8);
	Vmx_VmWrite(HOST_FS_SELECTOR,Asm_GetFs() & 0xFFF8);
	Vmx_VmWrite(HOST_GS_SELECTOR,Asm_GetGs() & 0xFFF8);
	Vmx_VmWrite(HOST_SS_SELECTOR,Asm_GetSs() & 0xFFF8);
	Vmx_VmWrite(HOST_TR_SELECTOR,Asm_GetTr() & 0xFFF8);

	InitializeSegmentSelector(&SegmentSelector,Asm_GetFs(),GdtBase);
	Vmx_VmWrite(HOST_FS_BASE,SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector,Asm_GetGs(),GdtBase);
	Vmx_VmWrite(HOST_GS_BASE,SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector,Asm_GetTr(),GdtBase);
	Vmx_VmWrite(HOST_TR_BASE,SegmentSelector.base);

	Vmx_VmWrite(HOST_GDTR_BASE,GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE,IdtBase);

	Vmx_VmWrite(HOST_IA32_SYSENTER_CS,Asm_ReadMsr(MSR_IA32_SYSENTER_CS)&0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP,Asm_ReadMsr(MSR_IA32_SYSENTER_ESP)&0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP,Asm_ReadMsr(MSR_IA32_SYSENTER_EIP)&0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP,((ULONG)g_VMXCPU.pHostEsp) + 0x1FFF);//8KB 0x2000
	Vmx_VmWrite(HOST_RIP,(ULONG)&Asm_VMMEntryPoint);//这里定义我们的VMM处理程序入口

	//
	// 3.虚拟机运行控制域
	//
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL,VmxAdjustControls(0,MSR_IA32_VMX_PINBASED_CTLS));

	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MASK,0);
	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MATCH,0);
	Vmx_VmWrite(TSC_OFFSET,0);
	Vmx_VmWrite(TSC_OFFSET_HIGH,0);

	uCPUBase = VmxAdjustControls(0,MSR_IA32_VMX_PROCBASED_CTLS);

	//uCPUBase |= CPU_BASED_MOV_DR_EXITING; // 拦截调试寄存器操作
	//uCPUBase |= CPU_BASED_USE_IO_BITMAPS; // 拦截键盘鼠标消息
	//uCPUBase |= CPU_BASED_ACTIVATE_MSR_BITMAP; // 拦截MSR操作

	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL,uCPUBase);

	/*
	Vmx_VmWrite(IO_BITMAP_A,0);
	Vmx_VmWrite(IO_BITMAP_A_HIGH,0);
	Vmx_VmWrite(IO_BITMAP_B,0);
	Vmx_VmWrite(IO_BITMAP_B_HIGH,0);
	*/

	Vmx_VmWrite(CR3_TARGET_COUNT,0);
	Vmx_VmWrite(CR3_TARGET_VALUE0,0);
	Vmx_VmWrite(CR3_TARGET_VALUE1,0);
	Vmx_VmWrite(CR3_TARGET_VALUE2,0);
	Vmx_VmWrite(CR3_TARGET_VALUE3,0);

	//
	// 4.VMEntry运行控制域
	//
	Vmx_VmWrite(VM_ENTRY_CONTROLS,VmxAdjustControls(0,MSR_IA32_VMX_ENTRY_CTLS));
	Vmx_VmWrite(VM_ENTRY_MSR_LOAD_COUNT,0);
	Vmx_VmWrite(VM_ENTRY_INTR_INFO_FIELD,0);


	//
	// 5.VMExit运行控制域
	//
	Vmx_VmWrite(VM_EXIT_CONTROLS,VmxAdjustControls(VM_EXIT_ACK_INTR_ON_EXIT,MSR_IA32_VMX_EXIT_CTLS));
	Vmx_VmWrite(VM_EXIT_MSR_LOAD_COUNT,0);
	Vmx_VmWrite(VM_EXIT_MSR_STORE_COUNT,0);

	Vmx_VmLaunch();

	g_VMXCPU.bVTStartSuccess = FALSE;

	Log("ERROR:VmLaunch指令调用失败!",Vmx_VmRead(VM_INSTRUCTION_ERROR));
}

NTSTATUS StartVirtualTechnology()
{
	NTSTATUS status = STATUS_SUCCESS;
	if (!IsVTEnabled())
		return STATUS_NOT_SUPPORTED;

	status = AllocateVMXRegion();
	if (!NT_SUCCESS(status))
	{
		Log("ERROR:VMX内存区域申请失败",0);
		return STATUS_UNSUCCESSFUL;
	}
	Log("SUCCESS:VMX内存区域申请成功!",0);

	SetupVMXRegion();
	g_VMXCPU.bVTStartSuccess = TRUE;

	Asm_SetupVMCS();

	if (g_VMXCPU.bVTStartSuccess)
	{
		Log("SUCCESS:开启VT成功!",0);
		Log("SUCCESS:现在这个CPU进入了VMX模式.",0);
		return STATUS_SUCCESS;
	}
	else Log("ERROR:开启VT失败!",0);
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS StopVirtualTechnology()
{
	_CR4 uCr4;
	if(g_VMXCPU.bVTStartSuccess)
	{
		Vmx_VmCall('SVT');
		
		*((PULONG)&uCr4) = Asm_GetCr4();
		uCr4.VMXE = 0;
		Asm_SetCr4(*((PULONG)&uCr4));

		ExFreePoolWithTag(g_VMXCPU.pVMXONRegion,'vmon');
		ExFreePoolWithTag(g_VMXCPU.pVMCSRegion,'vmcs');
		ExFreePoolWithTag(g_VMXCPU.pHostEsp,'mini');

		Log("SUCCESS:关闭VT成功!",0);
		Log("SUCCESS:现在这个CPU退出了VMX模式.",0);
	}

	return STATUS_SUCCESS;
}

BOOLEAN IsVTEnabled()
{
	ULONG uRet_EAX,uRet_ECX,uRet_EDX,uRet_EBX;
	_CPUID_ECX uCPUID;
	_CR0 uCr0;
	_CR4 uCr4;
	IA32_FEATURE_CONTROL_MSR msr;
	//1. CPUID
	Asm_CPUID(1,&uRet_EAX,&uRet_EBX,&uRet_ECX,&uRet_EDX);
	*((PULONG)&uCPUID) = uRet_ECX;

	if (uCPUID.VMX != 1)
	{
		Log("ERROR:这个CPU不支持VT!",0);
		return FALSE;
	}

	// 2. CR0 CR4
	*((PULONG)&uCr0) = Asm_GetCr0();
	*((PULONG)&uCr4) = Asm_GetCr4();

	if (uCr0.PE != 1||uCr0.PG!=1||uCr0.NE!=1)
	{
		Log("ERROR:这个CPU没有开启VT!",0);
		return FALSE;
	}

	if (uCr4.VMXE == 1)
	{
		Log("ERROR:这个CPU已经开启了VT!",0);
		Log("可能是别的驱动已经占用了VT，你必须关闭它后才能开启。",0);
		return FALSE;
	}

	// 3. MSR
	*((PULONG)&msr) = Asm_ReadMsr(MSR_IA32_FEATURE_CONTROL);
	if (msr.Lock!=1)
	{
		Log("ERROR:VT指令未被锁定!",0);
		return FALSE;
	}
	Log("SUCCESS:这个CPU支持VT!",0);
	return TRUE;
}