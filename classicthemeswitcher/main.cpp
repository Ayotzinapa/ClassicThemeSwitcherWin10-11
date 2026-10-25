#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <string>
#pragma comment(lib, "advapi32.lib")


// NT API dont fry me

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS(NTAPI* PFN_NtOpenSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI* PFN_NtSetSecurityObject)(
    HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor);

typedef NTSTATUS(NTAPI* PFN_NtQuerySecurityObject)(
    HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded);

static PFN_NtOpenSection        pNtOpenSection = nullptr;
static PFN_NtSetSecurityObject  pNtSetSecurityObject = nullptr;
static PFN_NtQuerySecurityObject pNtQuerySecurityObject = nullptr;

// SDDL strings used by ClassicThemeTray
static const wchar_t* SDDL_ALLOW = L"O:BAG:SYD:(A;;CCLCRC;;;IU)(A;;CCDCLCSWRPSDRCWDWO;;;SY)"; // modern
static const wchar_t* SDDL_DENY = L"O:BAG:SYD:(A;;RC;;;IU)(A;;DCSWRPSDRCWDWO;;;SY)";         // classic


static HWND g_status = nullptr;
static bool g_classicEnabled = false;


static bool LoadNtApis()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;

    pNtOpenSection = (PFN_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    pNtSetSecurityObject = (PFN_NtSetSecurityObject)GetProcAddress(ntdll, "NtSetSecurityObject");
    pNtQuerySecurityObject = (PFN_NtQuerySecurityObject)GetProcAddress(ntdll, "NtQuerySecurityObject");

    return pNtOpenSection && pNtSetSecurityObject && pNtQuerySecurityObject;
}

static std::wstring GetThemeSectionPath()
{
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t path[256];
    swprintf_s(path, L"\\Sessions\\%u\\Windows\\ThemeSection", sessionId);
    return path;
}

static bool SetThemeSectionSecurity(const wchar_t* sddl)
{
    std::wstring path = GetThemeSectionPath();

    UNICODE_STRING us;
    us.Buffer = const_cast<PWSTR>(path.c_str());
    us.Length = (USHORT)(path.length() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hSection = nullptr;
    NTSTATUS status = pNtOpenSection(&hSection, WRITE_DAC, &oa);
    if (!NT_SUCCESS(status) || !hSection)
        return false;

    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, nullptr))
    {
        CloseHandle(hSection);
        return false;
    }

    status = pNtSetSecurityObject(hSection, DACL_SECURITY_INFORMATION, pSD);
    LocalFree(pSD);
    CloseHandle(hSection);

    return NT_SUCCESS(status);
}

static bool IsClassicEnabled()
{
    std::wstring path = GetThemeSectionPath();

    UNICODE_STRING us;
    us.Buffer = const_cast<PWSTR>(path.c_str());
    us.Length = (USHORT)(path.length() * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hSection = nullptr;
    NTSTATUS status = pNtOpenSection(&hSection, READ_CONTROL, &oa);
    if (!NT_SUCCESS(status) || !hSection)
        return false;

    ULONG needed = 0;
    pNtQuerySecurityObject(hSection, DACL_SECURITY_INFORMATION, nullptr, 0, &needed);

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, needed);
    if (!pSD)
    {
        CloseHandle(hSection);
        return false;
    }

    status = pNtQuerySecurityObject(hSection, DACL_SECURITY_INFORMATION, pSD, needed, &needed);
    CloseHandle(hSection);

    if (!NT_SUCCESS(status))
    {
        LocalFree(pSD);
        return false;
    }

    LPWSTR sddl = nullptr;
    ConvertSecurityDescriptorToStringSecurityDescriptorW(
        pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr);
    LocalFree(pSD);

    bool isClassic = false;
    if (sddl)
    {
        // The Classic (deny) version contains this ACE
        isClassic = (wcsstr(sddl, L"(A;;RC;;;IU)") != nullptr);
        LocalFree(sddl);
    }
    return isClassic;
}


static void SetStatus(const wchar_t* text)
{
    SetWindowTextW(g_status, text);
}

static void UpdateStatus()
{
    g_classicEnabled = IsClassicEnabled();
    if (g_classicEnabled)
        SetStatus(L"Classic Theme is currently ENABLED system-wide.");
    else
        SetStatus(L"Classic Theme is currently DISABLED (modern theme).");
}


static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        CreateWindowW(L"STATIC", L"Classic Theme Switcher",
            WS_CHILD | WS_VISIBLE,
            18, 16, 330, 28, hwnd, nullptr, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Enable Classic",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            18, 58, 145, 32, hwnd, (HMENU)101, nullptr, nullptr);

        CreateWindowW(L"BUTTON", L"Restore Windows",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            175, 58, 145, 32, hwnd, (HMENU)102, nullptr, nullptr);

        g_status = CreateWindowW(L"STATIC", L"Checking current state...",
            WS_CHILD | WS_VISIBLE,
            18, 108, 330, 50, hwnd, nullptr, nullptr, nullptr);

        UpdateStatus();
        return 0;

    case WM_COMMAND:
        if (LOWORD(wParam) == 101) // Enable Classic
        {
            if (SetThemeSectionSecurity(SDDL_DENY))
            {
                g_classicEnabled = true;
                SetStatus(L"Classic Theme ENABLED.\nNew programs will use Classic Theme.");
            }
            else
            {
                SetStatus(L"Failed to enable Classic Theme.\nTry running as Administrator.");
            }
        }
        else if (LOWORD(wParam) == 102) // Restore
        {
            if (SetThemeSectionSecurity(SDDL_ALLOW))
            {
                g_classicEnabled = false;
                SetStatus(L"Modern theme RESTORED.\nNew programs will use the normal theme.");
            }
            else
            {
                SetStatus(L"Failed to restore theme.\nTry running as Administrator.");
            }
        }
        return 0;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}


int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
    if (!LoadNtApis())
    {
        MessageBoxW(nullptr, L"Failed to load required NT APIs.", L"Error", MB_ICONERROR);
        return 1;
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"ClassicThemeSwitcherWindow";
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);

    if (!RegisterClassW(&wc))
        return 1;

    HWND hwnd = CreateWindowW(
        wc.lpszClassName,
        L"Classic Theme Switcher",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 380, 210,
        nullptr, nullptr, instance, nullptr);

    if (!hwnd)
        return 1;

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}