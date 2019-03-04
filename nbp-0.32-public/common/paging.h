/* 
 * Copyright holder: Invisible Things Lab
 * 
 * This software is protected by domestic and International
 * copyright laws. Any use (including publishing and
 * distribution) of this software requires a valid license
 * from the copyright holder.
 *
 * This software is provided for the educational use only
 * during the Black Hat training. This software should not
 * be used on production systems.
 *
 */

#pragma once

#include <ntddk.h>
#include "common.h"

#define AP_PAGETABLE	1  //表示是宿主机的页表
#define AP_PT		2      //*****************//
#define AP_PD		4      //分别表示作为
#define AP_PDP		8      //各级页表的内存页
#define AP_PML4		16     //*****************//

typedef enum
{
  PAT_DONT_FREE = 0, //表示这个内存页面不是单独分配的，是在一大块连续内存的中间位置，不能被释放
  PAT_POOL,//表示这个内存页面是通过调用ExAllocatePoolWithTag()从非分页池中分配的第一个页面
  PAT_CONTIGUOUS //表示这个内存页面是通过调用MmAllocateContiguousMemorySpecifyCache()分配的第一个页面
} PAGE_ALLOCATION_TYPE;

//函数MmSavePage分配如下结构体保存物理地址、宿主机虚拟地址和客户机虚拟地址的对应关系
typedef struct _ALLOCATED_PAGE
{

  LIST_ENTRY le; //链表头，链接到g_PageTableList

  ULONG Flags; //标志

  PAGE_ALLOCATION_TYPE AllocationType; //分配类型(见上)
  ULONG uNumberOfPages;         // for PAT_CONTIGUOUS only分配内存页数

  PHYSICAL_ADDRESS PhysicalAddress; //物理地址
  PVOID HostAddress; //宿主机虚拟地址
  PVOID GuestAddress; //客户机虚拟地址

} ALLOCATED_PAGE,*PALLOCATED_PAGE;

NTSTATUS NTAPI MmCreateMapping (
  PHYSICAL_ADDRESS PhysicalAddress,
  PVOID VirtualAddress,
  BOOLEAN bLargePage
);

PVOID NTAPI MmAllocateContiguousPages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
);

PVOID NTAPI MmAllocateContiguousPagesSpecifyCache (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA,
  ULONG CacheType
);

PVOID NTAPI MmAllocatePages (
  ULONG uNumberOfPages,
  PPHYSICAL_ADDRESS pFirstPagePA
);

NTSTATUS NTAPI MmMapGuestPages (
  PVOID FirstPage,
  ULONG uNumberOfPages
);

NTSTATUS NTAPI MmMapGuestKernelPages (
);

NTSTATUS NTAPI MmMapGuestTSS64 (
  PVOID Tss64,
  USHORT Tss64Limit
);

NTSTATUS NTAPI MmInitManager (
);

NTSTATUS NTAPI MmShutdownManager (
);

NTSTATUS NTAPI MmInitIdentityPageTable (
);
