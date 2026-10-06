// trigger / dxgi proxy: waits inside the game process, watches a control file,
// and drives RenderDoc's in-app capture API when told to.
#include <windows.h>
#include <atomic>
#include <string>
#include <thread>
#include <cstdio>
#include <cstring>

#include "renderdoc_app.h"

typedef void (*pRENDERDOC_GetAPI_t)(int, void**);

static const wchar_t* kLogPath  = L"I:\\tinecmatool-new\\captures\\trg.log";
static const wchar_t* kCtlPath  = L"I:\\tinecmatool-new\\captures\\ctl.txt";
static const wchar_t* kTemplate = L"I:\\tinecmatool-new\\captures\\wuwa";
static const wchar_t* kRdModule = L"TinecmaTool.dll";

static std::atomic<bool> g_stop(false);

static void LogLine(const std::string& s)
{
    FILE* f = _wfopen(kLogPath, L"ab");
    if (!f) return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    char head[64];
    sprintf_s(head, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    fwrite(head, 1, strlen(head), f);
    fwrite(s.c_str(), 1, s.size(), f);
    fwrite("\r\n", 1, 2, f);
    fclose(f);
}

static std::string Narrow(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, NULL, NULL);
    return s;
}

static std::wstring ExeName()
{
    wchar_t buf[MAX_PATH] = L"";
    DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring s(buf, n);
    size_t p = s.find_last_of(L"\\/");
    return (p == std::wstring::npos) ? s : s.substr(p + 1);
}

static std::string ReadCtl()
{
    FILE* f = _wfopen(kCtlPath, L"rb");
    if (!f) return std::string();
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    std::string s(buf, n);
    if (s.size() >= 3 && (unsigned char)s[0] == 0xEF && (unsigned char)s[1] == 0xBB &&
        (unsigned char)s[2] == 0xBF)
        s.erase(0, 3);
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' ||
                          s.back() == '\t' || s.back() == '\0'))
        s.pop_back();
    size_t a = s.find_first_not_of(" \t\r\n\0");
    if (a == std::string::npos) return std::string();
    return s.substr(a);
}

static void WriteCtl(const char* v)
{
    FILE* f = _wfopen(kCtlPath, L"wb");
    if (!f) return;
    fwrite(v, 1, strlen(v), f);
    fclose(f);
}

class Dispatcher
{
public:
    void Start()
    {
        std::thread([this]() { Run(); }).detach();
    }

    void Run()
    {
        std::wstring exe = ExeName();
        LogLine("attach pid=" + std::to_string(GetCurrentProcessId()) + " exe=" + Narrow(exe));

        if (_wcsicmp(exe.c_str(), L"Client-Win64-Shipping.exe") != 0)
        {
            LogLine("not the game process, idle");
            return;
        }

        // let the game get up before touching anything
        for (int i = 0; i < 6 && !g_stop; i++) Sleep(1000);

        RENDERDOC_API_1_6_0* api = nullptr;
        for (int attempt = 0; attempt < 30 && !g_stop && !api; attempt++)
        {
            HMODULE h = GetModuleHandleW(kRdModule);
            bool selfLoaded = false;
            if (!h)
            {
                h = LoadLibraryW(kRdModule);
                selfLoaded = true;
            }
            if (h)
            {
                pRENDERDOC_GetAPI_t getApi =
                    (pRENDERDOC_GetAPI_t)GetProcAddress(h, "RENDERDOC_GetAPI");
                if (getApi)
                {
                    void* out = nullptr;
                    if (getApi(eRENDERDOC_API_Version_1_6_0, &out) == 1 && out)
                    {
                        api = (RENDERDOC_API_1_6_0*)out;
                        LogLine(selfLoaded ? "renderdoc module self-loaded, api ok"
                                           : "renderdoc module present (injected), api ok");
                        break;
                    }
                }
            }
            LogLine("waiting for renderdoc module... attempt " + std::to_string(attempt));
            Sleep(3000);
        }

        if (!api)
        {
            LogLine("api unavailable, giving up watch loop");
            return;
        }

        api->SetCaptureFilePathTemplate(Narrow(kTemplate).c_str());
        api->MaskOverlayBits(~0U, 0U);
        WriteCtl("idle");
        LogLine("ready - watching control file");

        unsigned seen = 0;
        while (!g_stop)
        {
            std::string v = ReadCtl();
            if (v == "stop")
            {
                LogLine("stop requested");
                break;
            }
            if (v == "cap")
            {
                seen++;
                LogLine("capture requested #" + std::to_string(seen));
                api->TriggerCapture();
                WriteCtl("idle");
                LogLine("triggered, frames=" + std::to_string(api->GetNumCaptures()));
            }
            Sleep(400);
        }
        LogLine("watch loop exit");
    }
};

static Dispatcher* g_disp = nullptr;

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInst);
        g_disp = new Dispatcher();
        g_disp->Start();
    }
    return TRUE;
}
