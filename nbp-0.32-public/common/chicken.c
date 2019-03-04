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

#include "common.h"
#include "hvm.h"
#include "regs.h"

#ifdef BLUE_CHICKEN

static ULONG64 ChQueueDequeue (
  PCPU Cpu
)
{
  ULONG64 x;
  if (Cpu->ChickenQueueSize == 0) {
    _KdPrint (("Chicken Queue Error: Attempt to dequeue element from empty queue!\n"));
    return -1;
  }
  x = Cpu->ChickenQueueTable[Cpu->ChickenQueueHead];
  if (Cpu->ChickenQueueHead == CHICKEN_QUEUE_SZ - 1)
    Cpu->ChickenQueueHead = 0;
  else
    Cpu->ChickenQueueHead++;

  Cpu->ChickenQueueSize--;
  return x;
}

static VOID ChQueueEnqueue (
  PCPU Cpu,
  ULONG64 x
)
{
  if (Cpu->ChickenQueueSize == CHICKEN_QUEUE_SZ) {
    _KdPrint (("Chicken Queue Error: Attempt to enqueue element to already full queue!\n"));
    return;
  }
  Cpu->ChickenQueueTable[Cpu->ChickenQueueTail] = x;
  if (Cpu->ChickenQueueTail == CHICKEN_QUEUE_SZ - 1)
    Cpu->ChickenQueueTail = 0;
  else
    Cpu->ChickenQueueTail++;
  Cpu->ChickenQueueSize++;
}

static ULONG64 ChQueueGetFirst (
  PCPU Cpu
)
{
  if (Cpu->ChickenQueueSize == 0) {
    _KdPrint (("Chicken Queue Error: Attempt to get element from empty queue!\n"));
    return -1;
  }
  return Cpu->ChickenQueueTable[Cpu->ChickenQueueHead];
}

static ULONG64 ChQueueGetLast (
  PCPU Cpu
)
{
  int indx;
  if (Cpu->ChickenQueueSize == 0) {
    _KdPrint (("Chicken Queue Error: Attempt to get element from empty queue!\n"));
    return -1;
  }
  if (Cpu->ChickenQueueTail == 0)
    indx = CHICKEN_QUEUE_SZ - 1;
  else
    indx = Cpu->ChickenQueueTail - 1;
  return Cpu->ChickenQueueTable[indx];
}

VOID NTAPI ChickenAddInterceptTsc (
  PCPU Cpu
)
{

  ULONG64 Tsc = RegGetTSC ();
  if (Cpu->ChickenQueueSize == CHICKEN_QUEUE_SZ)
    ChQueueDequeue (Cpu);       // make space
  ChQueueEnqueue (Cpu, Tsc);

}

BOOLEAN NTAPI ChickenShouldUninstall (
  PCPU Cpu
)
{
  ULONG64 t = ChQueueGetLast (Cpu) - ChQueueGetFirst (Cpu);
  if ((Cpu->ChickenQueueSize == CHICKEN_QUEUE_SZ) && (t <= CHICKEN_TSC_THRESHOLD))
    return TRUE;                // we better get out from here!
  else
    return FALSE;
}

#endif
