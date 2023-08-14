{.emit: """

#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* pfnGetProcessMitigationPolicy)(
    HANDLE hProcess,
    PROCESS_MITIGATION_POLICY MitigationPolicy,
    PVOID lpBuffer,
    SIZE_T dwLength);

BOOL IsControlFlowGuardEnabled() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 != NULL) {
        pfnGetProcessMitigationPolicy GetProcessMitigationPolicyPtr =
            (pfnGetProcessMitigationPolicy)GetProcAddress(hKernel32, "GetProcessMitigationPolicy");
        if (GetProcessMitigationPolicyPtr) {
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policyInfo;

            if (GetProcessMitigationPolicyPtr(
                    GetCurrentProcess(),
                    ProcessControlFlowGuardPolicy,
                    &policyInfo,
                    sizeof(policyInfo))) {
                return policyInfo.EnableControlFlowGuard;
            } else {
                DWORD error = GetLastError();
                printf("Error retrieving mitigation policy: %lu\n", error);
            }
        } else {
            DWORD error = GetLastError();
            printf("Error getting function address: %lu\n", error);
        }
    } else {
        DWORD error = GetLastError();
        printf("Error getting module handle: %lu\n", error);
    }
    return FALSE;  // Error occurred while checking
}

""".}

proc isControlFlowGuardEnabled*(): bool {.importc: "IsControlFlowGuardEnabled", nodecl.}