// SPDX-License-Identifier: GPL-3.0-only

#include "pch.h"
#include <cstdio>
#include <string>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")


typedef struct hostent* (WSAAPI* GETHOSTBYNAME)(const char*);
static GETHOSTBYNAME g_realGethostbyname = NULL;

static struct hostent* WSAAPI MyGethostbyname(const char* name)
{
    if (g_realGethostbyname) {
        if (name && strstr(name, ".ea.com") != NULL) {
            return g_realGethostbyname("eahub.eu");
        }
        return g_realGethostbyname(name);
    }

    WSASetLastError(WSANO_RECOVERY);
    return NULL;
}

static BOOL HookIAT(const char* targetModule,
    const char* targetFunc,     /* NULL if matching by ordinal */
    WORD        targetOrdinal,  /* 0 to ignore, else match this */
    void* hookFunc, void** originalFunc)
{
    BYTE* base = (BYTE*)GetModuleHandleA(NULL);
    if (!base) return FALSE;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY d =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (d.VirtualAddress == 0) return FALSE;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + d.VirtualAddress);

    for (; imp->Name; ++imp)
    {
        if (_stricmp((const char*)(base + imp->Name), targetModule) != 0)
            continue;

        IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        if (imp->OriginalFirstThunk == 0) orig = iat;

        for (; orig->u1.AddressOfData; ++orig, ++iat)
        {
            BOOL match = FALSE;

            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                /* imported by ordinal */
                WORD ord = (WORD)IMAGE_ORDINAL(orig->u1.Ordinal);
                if (targetOrdinal && ord == targetOrdinal)
                    match = TRUE;
            }
            else if (targetFunc)
            {
                /* imported by name */
                IMAGE_IMPORT_BY_NAME* ibn =
                    (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
                if (strcmp((const char*)ibn->Name, targetFunc) == 0)
                    match = TRUE;
            }

            if (!match) continue;

            void** slot = (void**)&iat->u1.Function;
            DWORD  oldProtect;
            if (!VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
                return FALSE;
            if (originalFunc) *originalFunc = *slot;
            *slot = hookFunc;
            VirtualProtect(slot, sizeof(void*), oldProtect, &oldProtect);
            return TRUE;
        }
    }
    return FALSE;
}


void DllThread()
{
#ifdef _DEBUG
    AllocConsole();
    std::ignore = freopen("CONOUT$", "w", stdout);
    std::ignore = freopen("CONIN$", "r", stdin);
#endif

    void* original = NULL;

    HMODULE hModule = GetModuleHandle(NULL);

    if (!HookIAT("ws2_32.dll", "gethostbyname", 52,
        MyGethostbyname, (void**)&g_realGethostbyname))
    {
        printf("Failed to hook, again\n");
        if (HookIAT("wsock32.dll", "gethostbyname", 52,
            MyGethostbyname, (void**)&g_realGethostbyname)) {
            printf("Failed to hook2\n");
        }
    }
}

extern "C" __declspec(dllexport)
void InitializeASI()
{
    CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DllThread, NULL, NULL, NULL);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        //CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)DllThread, NULL, NULL, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

