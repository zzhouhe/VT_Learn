#ifndef EXITHANDLER_H
#define EXITHANDLER_H

void HandleCPUID();
void HandleVmCall();
void HandleCrAccess();
void VMMEntryPoint(void);

#endif
