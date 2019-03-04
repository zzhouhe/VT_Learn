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

#include "comprint.h"

static BPSPIN_LOCK g_ComSpinLock;
static ULONG64 LastTsc = 0;     // TODO: move it to the CPU struct
UCHAR g_BpId = 0;

BOOLEAN g_bDisableComOutput = FALSE;

#ifdef COMPRINT_OVERFLOW_PROTECTION
static int QueueSize = 0;
static ULONG64 QueueTable[COMPRINT_QUEUE_SZ];
static int QueueHead = 0, QueueTail = 0;
static int SkippedLines = 0;

static ULONG64 QueueDequeue (
)
{
  ULONG64 x;
  if (QueueSize == 0) {
    //      _KdPrint (("ComPrint Queue Error: Attempt to dequeue element from empty queue!\n"));
    return -1;
  }
  x = QueueTable[QueueHead];
  if (QueueHead == COMPRINT_QUEUE_SZ - 1)
    QueueHead = 0;
  else
    QueueHead++;

  QueueSize--;
  return x;
}

static VOID QueueEnqueue (
  ULONG64 x
)
{
  if (QueueSize == COMPRINT_QUEUE_SZ) {
    //_KdPrint (("ComPrint Queue Error: Attempt to enqueue element to already full queue!\n"));
    return;
  }
  QueueTable[QueueTail] = x;
  if (QueueTail == COMPRINT_QUEUE_SZ - 1)
    QueueTail = 0;
  else
    QueueTail++;
  QueueSize++;
}

static ULONG64 QueueGetFirst (
)
{
  if (QueueSize == 0) {
    //_KdPrint (("Chicken Queue Error: Attempt to get element from empty queue!\n"));
    return -1;
  }
  return QueueTable[QueueHead];
}

static ULONG64 QueueGetLast (
)
{
  int indx;
  if (QueueSize == 0) {
    // _KdPrint (("ComPrint Queue Error: Attempt to get element from empty queue!\n"));
    return -1;
  }
  if (QueueTail == 0)
    indx = COMPRINT_QUEUE_SZ - 1;
  else
    indx = QueueTail - 1;
  return QueueTable[indx];
}

#endif // COMPRINT_OVERFLOW_PROTECTION

static VOID NTAPI _ComPrint (
  PUCHAR str
)
{

#ifdef USE_COM_PRINTS
  int i;
  for (i = 0; i < strlen (str); i++)
    PioOutByte (str[i]);
#endif
#ifdef USE_LOCAL_DBGPRINTS
  DbgPrintString (str);
#endif

}

VOID NTAPI ComPrint (
  PUCHAR fmt,
  ...
)
{
  va_list args;
  UCHAR str[1024] = { 0 };
  int i, len, j;
  ULONG64 tsc = RegGetTSC ();

#ifdef USE_COM_PRINTS
  if (g_bDisableComOutput)
    return;
#endif

  va_start (args, fmt);
  CmAcquireSpinLock (&g_ComSpinLock);

#ifdef COMPRINT_OVERFLOW_PROTECTION

  if (SkippedLines) {
    if (tsc - QueueGetLast () <= COMPRINT_SLEEP) {
      SkippedLines++;
      //if (SkippedLines % 100 == 0) _ComPrint (">>> still skipping...\n");
      CmReleaseSpinLock (&g_ComSpinLock);
      return;
    } else {
      QueueSize = 0;
      QueueHead = QueueTail = 0;
      snprintf ((PUCHAR) & str, sizeof (str), ">>> %d lines skipped, continuing normal output...\n", SkippedLines);
      _ComPrint (str);
      str[0] = 0;
      SkippedLines = 0;

    }

  }

  if ((QueueSize == COMPRINT_QUEUE_SZ)
      && (tsc - QueueGetFirst () <= COMPRINT_QUEUE_TH)) {
    // suppress Com output...
    if (!SkippedLines)
      _ComPrint (">>> Supressing further output temporarily...\n");
    SkippedLines++;
    CmReleaseSpinLock (&g_ComSpinLock);
    return;
  }

  if (QueueSize == COMPRINT_QUEUE_SZ)
    QueueDequeue ();            // make space
  QueueEnqueue (tsc);

#endif

  tsc >>= 10;                   // don't be too precise when displaying the time deltas...

#ifndef USE_LOCAL_DBGPRINTS
  if (tsc > LastTsc)
    snprintf ((PUCHAR) & str, sizeof (str), "+% 8x <%02X>:  ", tsc - LastTsc, g_BpId);
  else
    snprintf ((PUCHAR) & str, sizeof (str), "-% 8x <%02X>:  ", LastTsc - tsc, g_BpId);

  len = (int) strlen (str);
  _ComPrint (str);
#endif

  vsnprintf ((PUCHAR) & str, sizeof (str), (PUCHAR) fmt, args);
  len = (int) strlen (str);

  _ComPrint (str);
  LastTsc = tsc;
  CmReleaseSpinLock (&g_ComSpinLock);
}

VOID NTAPI ComInit (
)
{
  g_BpId = (UCHAR) RegGetTSC ();
  CmInitSpinLock (&g_ComSpinLock);
}
