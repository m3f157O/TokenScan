// EnableDebug.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <sddl.h>
#include <strsafe.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <tchar.h>
#pragma comment(lib, "advapi32.lib")
DWORD GetTokenInfoLength(HANDLE hTok, TOKEN_INFORMATION_CLASS tokClass) {
    DWORD dwRetLength = 0x0;

    GetTokenInformation(hTok, tokClass, NULL, 0x0, &dwRetLength);

    return dwRetLength;
}
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.

    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}


LPDWORD PrintTokenSessionId(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenSessionId);
    DWORD dwRetLen;

    LPDWORD lpSessionId = (LPDWORD)VirtualAlloc(nullptr, dwTokLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!GetTokenInformation(hTok, TokenSessionId, lpSessionId, dwTokLen, &dwRetLen)) {
        printf("error\n");
    }
    else {
        printf("[+] Logon Session ID : ");
        printf("%d",*lpSessionId);
    }

    VirtualFree(lpSessionId, 0x0, MEM_RELEASE);
    return lpSessionId;
}




LPWSTR SIDSerialize(PSID pSid) {
    LPWSTR lpSid = nullptr;
    return lpSid;
}

/// <summary>
/// Get the account name and domain name from the SID
/// </summary>
/// <param name="pSid">Pointer to SID</param>
/// <param name="lpAccountName">Preallocated pointer to receive the account name</param>
/// <param name="lpDomainName">Preallocated pointer to recieve the domian name</param>
/// <param name="pSidType">Pointer to receieve the Sid Type</param>
/// <returns></returns>
BOOL GetDomainAccount(PSID pSid, LPWSTR lpAccountName, LPWSTR lpDomainName, PSID_NAME_USE eSidType) {
    DWORD dwAccount, dwDomain;
    dwAccount = dwDomain = MAX_PATH;

    if (!LookupAccountSidW(nullptr, pSid, lpAccountName, &dwAccount, lpDomainName, &dwDomain, eSidType)) {
        VirtualFree(lpAccountName, 0x0, MEM_RELEASE);
        VirtualFree(lpDomainName, 0x0, MEM_RELEASE);
        lpAccountName = lpDomainName = nullptr;
        return FALSE;
    }

    return TRUE;
}



VOID PrintTokenUser(HANDLE hTok) {
    DWORD dwTokLength = GetTokenInfoLength(hTok, TokenUser);
    DWORD dwRetLen;

    PTOKEN_USER tu = (PTOKEN_USER)VirtualAlloc(NULL, dwTokLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (tu == nullptr) {
        printf("VirtualAlloc()");
        return;
    }
    printf("[+] User Details\n");
    if (!GetTokenInformation(hTok, TokenUser, (LPVOID)tu, dwTokLength, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    LPWSTR lpSid = SIDSerialize(tu->User.Sid);
    if (lpSid == nullptr) {
        printf("SIDSerialize()");
    }
    else {
        printf("SID: ");
        printf("%s\n", lpSid);
    }
    LocalFree(lpSid);
    lpSid = nullptr;

    WCHAR wAcc[MAX_PATH], wDom[MAX_PATH];
    SID_NAME_USE eSidType;
    if (!GetDomainAccount(tu->User.Sid, wAcc, wDom, &eSidType)) {
        printf("GetDomainAccount()");
    }
    else {
        printf("\tDomain\\Account(Type) :");
        wprintf(L"%s\n", wDom);
        wprintf(L"%s\n", wAcc);

    }

    VirtualFree(tu, 0x0, MEM_RELEASE);
    tu = nullptr;
}
VOID PrintTokenType(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenType);
    DWORD dwRetLen;

    PTOKEN_TYPE t = (PTOKEN_TYPE)VirtualAlloc(nullptr, dwTokLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    PSECURITY_IMPERSONATION_LEVEL il = (PSECURITY_IMPERSONATION_LEVEL)VirtualAlloc(nullptr, dwTokLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!GetTokenInformation(hTok, TokenType, (LPVOID)t, dwTokLen, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    printf("[+] Token Type: ");

    switch (*t) {
    case TokenPrimary:
        printf("Primary\n");
        break;
    case TokenImpersonation:
        printf("Impersonate\n");
        // If it's an impersonation token, then print the level of impersonation
        dwTokLen = GetTokenInfoLength(hTok, TokenImpersonationLevel);
        if (!GetTokenInformation(hTok, TokenImpersonationLevel, (LPVOID)il, dwTokLen, &dwRetLen)) {
            printf("GetTokenInformation()");
        }
        else {
            printf("[+] Impersonation Level: ");
            switch (*il) {
            case SecurityAnonymous:
                printf("Anonymous - Cannot obtain identification information about the client\n");
                break;
            case SecurityIdentification:
                printf("Identification - Can obtain information about the client, but not impersonate it\n");
                break;
            case SecurityImpersonation:
                printf("Impersonation - Can impersonate the client's security context on its local system\n");
                break;
            case SecurityDelegation:
                printf("Delegation - Can impersonate the client's security context on remote systems\n");
                break;
            default:
                printf("N/A\n");
                break;
            }
        }
        break;
    default:
        printf("N/A\n");
    }

    VirtualFree(t, 0x0, MEM_RELEASE);
    t = nullptr;
    VirtualFree(il, 0x0, MEM_RELEASE);
    il = nullptr;
}

VOID PrintTokenPrivilege(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenPrivileges);
    DWORD dwRetLen;

    PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(dwTokLen); // (NULL, dwTokLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!GetTokenInformation(hTok, TokenPrivileges, (LPVOID)tp, dwTokLen, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    printf("[+] Token Privileges\n");

    for (DWORD c = 0; c < tp->PrivilegeCount; c++) {
        LPWSTR lpName = (LPWSTR)VirtualAlloc(NULL, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        LPWSTR lpDisplayName = (LPWSTR)VirtualAlloc(NULL, 1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        DWORD dwName, dwLangId, dwDisplayName;
        dwName = dwDisplayName = 1000;


        // Get the name of the privilege from LUID
        if (!LookupPrivilegeNameW(NULL, &tp->Privileges[c].Luid, lpName, &dwName)) {
            printf("LookupPrivilegeNameW()");
            continue;
        }


        // Get the description / display for the privilege by its name
        if (!LookupPrivilegeDisplayNameW(NULL, lpName, lpDisplayName, &dwDisplayName, &dwLangId)) {
            printf("LookupPrivilegeNameW()");
            continue;
        }

        printf("Name: ");
        wprintf(L"%s    ", lpName);
        switch (tp->Privileges[c].Attributes) {
        case SE_PRIVILEGE_ENABLED:
            printf("Status: Enabled\n");
            break;
        case SE_PRIVILEGE_ENABLED_BY_DEFAULT:
            printf("Status: Enabled by Default\n");
            break;
        case SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT:
            printf("Status: Enabled by Default\n");
            break;
        case SE_PRIVILEGE_REMOVED:
            printf("Status: Removed\n");
            break;
        case SE_PRIVILEGE_USED_FOR_ACCESS:
            printf("Status: Used for Access\n");
            break;
        case 0x0:
            printf("Status: Disabled\n");
            break;
        default:
            printf("Status: N/A\n\n");
        }

        printf("Description: ");
        wprintf(L"%s\n\n", lpDisplayName);

        VirtualFree(lpName, 0x0, MEM_RELEASE);
        VirtualFree(lpDisplayName, 0x0, MEM_RELEASE);
        lpName = nullptr;
        lpDisplayName = nullptr;
    }

    VirtualFree(tp, 0x0, MEM_RELEASE);
    tp = nullptr;
}

VOID PrintTokenSource(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenSource);
    DWORD dwRetLen;

    PTOKEN_SOURCE ts = (PTOKEN_SOURCE)VirtualAlloc(nullptr, dwTokLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!GetTokenInformation(hTok, TokenSource, (LPVOID)ts, dwTokLen, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    printf("[+] Token Source ");
    printf("\tSource Name: %s\n", ts->SourceName);
    printf("\tSource ID: %x-%x\n", ts->SourceIdentifier.HighPart , ts->SourceIdentifier.LowPart);

    VirtualFree(ts, 0x0, MEM_RELEASE);
    ts = nullptr;
}
VOID PrintTokenIsRestricted(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenHasRestrictions);
    DWORD dwRetLen;

    LPDWORD lpHasRestriction = (LPDWORD)VirtualAlloc(nullptr, dwTokLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!GetTokenInformation(hTok, TokenHasRestrictions, (LPVOID)lpHasRestriction, dwTokLen, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    if (*lpHasRestriction) {
        printf("[+] Is Token Restricted: Yes\n");
    }
    else {
        printf("[+] Is Token Restricted: No\n");
    }

    VirtualFree(lpHasRestriction, 0x0, MEM_RELEASE);
    lpHasRestriction = nullptr;
}

VOID PrintTokenElevation(HANDLE hTok) {
    DWORD dwTokLen = GetTokenInfoLength(hTok, TokenElevation);
    DWORD dwRetLen;

    PTOKEN_ELEVATION te = (PTOKEN_ELEVATION)VirtualAlloc(nullptr, dwTokLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!GetTokenInformation(hTok, TokenElevation, (LPVOID)te, dwTokLen, &dwRetLen)) {
        printf("GetTokenInformation()");
        return;
    }

    printf("[+] Token Elevation");
    if (te->TokenIsElevated) {
        // If the process is elevated, then get the elevation type
       printf("\tStatus: Elevated");
        dwTokLen = GetTokenInfoLength(hTok, TokenElevationType);

        PTOKEN_ELEVATION_TYPE t = (PTOKEN_ELEVATION_TYPE)VirtualAlloc(nullptr, dwTokLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!GetTokenInformation(hTok, TokenElevationType, (LPVOID)t, dwTokLen, &dwRetLen)) {
            printf("GetTokenInformation()");
        }
        else {
            switch (*t) {
            case TokenElevationTypeDefault:
               printf("\tType: Default - The token does not have a linked token\n");
                break;
            case TokenElevationTypeFull:
               printf("\tType: Full - The token is an elevated token\n");
                break;
            case TokenElevationTypeLimited:
               printf("\tType: Limited - The token is a limited token\n");
                break;
            default:
                break;
            }
        }
        VirtualFree(t, 0x0, MEM_RELEASE);
        t = nullptr;
    }
    else {
       printf("\tStatus: Not Elevated" );
    }

    VirtualFree(te, 0x0, MEM_RELEASE);
    te = nullptr;
}
int Exploit(void) {

    HANDLE hSystemToken, hSystemProcess;
    HANDLE dupSystemToken = NULL;
    HANDLE hProcess, hThread;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    int pid = 0;
    TOKEN_INFORMATION_CLASS TokClass;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // open high privileged process
    if (pid = GetCurrentProcessId())
        hSystemProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    else
        return -1;

    // extract high privileged token
    if (!OpenProcessToken(hSystemProcess, TOKEN_ALL_ACCESS, &hSystemToken)) {
        CloseHandle(hSystemProcess);
        return -1;
    }


    LPDWORD TokSession=PrintTokenSessionId(hSystemToken);
    SetPrivilege(hSystemToken, SE_DEBUG_NAME, true);
    //PrintTokenUser(hSystemToken);
    PrintTokenPrivilege(hSystemToken);
    //PrintTokenSource(hSystemToken);
    //PrintTokenType(hSystemToken);
    //PrintTokenIsRestricted(hSystemToken);
    //PrintTokenElevation(hSystemToken);
    // make a copy of a token
    DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupSystemToken);

    return 0;
}


void main() {

    /*    
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
    if (hProc == NULL || hProc == INVALID_HANDLE_VALUE) {
        hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
        if (hProc == NULL || hProc == INVALID_HANDLE_VALUE) {
            PrintError(L"OpenProcess()", FALSE);
        }
    }*/
    Exploit();

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
