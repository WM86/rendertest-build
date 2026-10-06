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
    char body[512];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(body, sizeof(body) - 1, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n < 0)
        n = 0;

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[640];
    int m = _snprintf_s(line, sizeof(line), _TRUNCATE, "[%02d:%02d:%02d] %s\r\n",
                        st.wHour, st.wMinute, st.wSecond, body);
    if (m < 0)
        return;

    HANDLE h = CreateFileW(kLogFile, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return;
    DWORD wrote = 0;
    WriteFile(h, line, (DWORD)m, &wrote, NULL);
    CloseHandle(h);
}

static RENDERDOC_API_1_6_0* g_api = NULL;

static bool TryGetApi(bool allowLoad)
{
    HMODULE h = GetModuleHandleW(L"TinecmaTool.dll");
    bool injected = (h != NULL);
    if (!h && allowLoad)
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

    // phase 1: only look for a module that was injected - never load it ourselves
    // while the game is still coming up (loading renderdoc this early kills it).
    for (int i = 0; i < 120 && !g_api; i++)
    {
        if (!TryGetApi(false) && (i % 10) == 0)
            LogF("phase1 waiting for injected module, %ds", i);
        Sleep(1000);
    }

    // phase 2: nothing showed up, fall back to loading it ourselves
    for (int i = 0; i < 780 && !g_api; i++)
    {
        if (!TryGetApi(true) && (i % 10) == 0)
            LogF("phase2 trying self-load, %ds", i);
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
