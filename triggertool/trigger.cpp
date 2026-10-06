// trigger.cpp
// 由 AppInit_DLLs 加载进游戏进程，按 ctl.txt 里的指令触发 RenderDoc 抓帧。
// 只对 Client-Win64-Shipping.exe 生效。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "renderdoc_app.h"

static const wchar_t* kLogFile  = L"I:\\tinecmatool-new\\captures\\trigger.log";
static const wchar_t* kCtlFile  = L"I:\\tinecmatool-new\\captures\\ctl.txt";
static const wchar_t* kRdocDll  = L"I:\\tinecmatool-new\\TinecmaTool.dll";
static const char*    kTemplate = "I:\\tinecmatool-new\\captures\\wuwa";

static void LogF(const char* fmt, ...)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, kLogFile, L"a, ccs=UTF-8") != 0 || !f)
        return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static RENDERDOC_API_1_6_0* g_api = NULL;

static bool TryGetApi()
{
    HMODULE h = GetModuleHandleW(L"TinecmaTool.dll");
    bool injected = (h != NULL);
    if (!h)
        h = LoadLibraryW(kRdocDll);
    if (!h)
        return false;

    pTINECMATOOL_GetAPI getApi = (pTINECMATOOL_GetAPI)GetProcAddress(h, "TINECMATOOL_GetAPI");
    if (!getApi)
        getApi = (pTINECMATOOL_GetAPI)GetProcAddress(h, "RENDERDOC_GetAPI");
    if (!getApi)
    {
        LogF("module loaded but no TINECMATOOL_GetAPI");
        return false;
    }

    if (!getApi(eRENDERDOC_API_Version_1_6_0, (void**)&g_api) || !g_api)
    {
        LogF("TINECMATOOL_GetAPI returned nothing");
        return false;
    }

    LogF("api ready (%s)", injected ? "already in process" : "loaded by trigger");
    return true;
}

static void WriteCtl(const char* text)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, kCtlFile, L"wb") == 0 && f)
    {
        fputs(text, f);
        fclose(f);
    }
}

static DWORD WINAPI Worker(LPVOID)
{
    LogF("worker start, pid=%lu", (unsigned long)GetCurrentProcessId());

    for (int i = 0; i < 900 && !g_api; i++)
    {
        if (!TryGetApi())
            Sleep(1000);
    }
    if (!g_api)
    {
        LogF("worker: no api, giving up");
        return 0;
    }

    g_api->SetCaptureFilePathTemplate(kTemplate);
    LogF("capture template = %s", kTemplate);
    WriteCtl("idle");

    for (;;)
    {
        Sleep(400);

        FILE* f = NULL;
        if (_wfopen_s(&f, kCtlFile, L"rb") != 0 || !f)
            continue;
        char buf[64] = {0};
        fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);

        char* p = buf;
        while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t')
            p++;

        if (_strnicmp(p, "cap", 3) == 0)
        {
            LogF("ctl=cap -> TriggerCapture");
            WriteCtl("busy");
            g_api->TriggerCapture();
            LogF("capture queued");
            WriteCtl("idle");
        }
        else if (_strnicmp(p, "exit", 4) == 0)
        {
            LogF("ctl=exit -> worker stop");
            WriteCtl("idle");
            return 0;
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);

        wchar_t exe[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        if (wcsstr(exe, L"Client-Win64-Shipping.exe") != NULL)
        {
            HANDLE t = CreateThread(NULL, 0, Worker, NULL, 0, NULL);
            if (t)
                CloseHandle(t);
        }
    }
    return TRUE;
}
