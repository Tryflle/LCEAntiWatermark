#include <windows.h>
#include <cstdint>
#include <cstring>
#include "MinHook.h"

// MSVC x64 std::wstring layout
struct MsvcWstring {
    union {
        wchar_t* ptr; // heap pointer (size > 7)
        wchar_t  buf[8]; // inline SSO buffer (size <= 7)
    };
    size_t size;
    size_t capacity;
};

static bool ZeroWstring(MsvcWstring* wstr)
{
    DWORD old;
    if (!VirtualProtect(wstr, sizeof(MsvcWstring), PAGE_EXECUTE_READWRITE, &old))
        return false;

    if (wstr->size > 7)
    {
        DWORD old2;
        if (VirtualProtect(wstr->ptr, sizeof(wchar_t), PAGE_EXECUTE_READWRITE, &old2))
        {
            wstr->ptr[0] = L'\0';
            VirtualProtect(wstr->ptr, sizeof(wchar_t), old2, &old2);
        }
    }
    else
    {
        wstr->buf[0] = L'\0';
    }

    wstr->size = 0;
    VirtualProtect(wstr, sizeof(MsvcWstring), old, &old);
    return true;
}

static void GetSections(uint8_t* mod,
    uint8_t** rdataBase, size_t* rdataSize,
    uint8_t** dataBase, size_t* dataSize)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(mod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (memcmp(sec->Name, ".rdata", 6) == 0)
        {
            *rdataBase = mod + sec->VirtualAddress;
            *rdataSize = sec->Misc.VirtualSize;
        }
        else if (memcmp(sec->Name, ".data", 5) == 0)
        {
            *dataBase = mod + sec->VirtualAddress;
            *dataSize = sec->Misc.VirtualSize;
        }
    }
}

// Scan for a wstring object whose content matches needle, also checks both heap-allocated and SSO cases.
static MsvcWstring* FindWstring(uint8_t* dataBase, size_t dataSize, const wchar_t* needle)
{
    size_t needleLen = wcslen(needle);
    size_t needleBytes = needleLen * sizeof(wchar_t);

    for (size_t i = 0; i + sizeof(MsvcWstring) <= dataSize; i += sizeof(uintptr_t))
    {
        auto* wstr = reinterpret_cast<MsvcWstring*>(dataBase + i);

        // Size must match
        if (wstr->size != needleLen)
            continue;

        if (needleLen > 7)
        {
            // Heap allocated — validate pointer then compare
            if (!wstr->ptr) continue;
            __try
            {
                if (memcmp(wstr->ptr, needle, needleBytes) == 0)
                    return wstr;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        else
        {
            // SSO — compare inline buffer
            if (memcmp(wstr->buf, needle, needleBytes) == 0)
                return wstr;
        }
    }
    return nullptr;
}

static bool PatchString(uint8_t* dataBase, size_t dataSize,
    const wchar_t* needle, const char* name)
{
    MsvcWstring* wstr = FindWstring(dataBase, dataSize, needle);
    if (!wstr)
    {
        OutputDebugStringA("[LceAntiWatermark] wstring not found: ");
        OutputDebugStringA(name);
        OutputDebugStringA("\n");
        return false;
    }
    return ZeroWstring(wstr);
}

static bool PatchVersionLines()
{
    auto* mod = reinterpret_cast<uint8_t*>(GetModuleHandle(nullptr));

    uint8_t* rdataBase = nullptr; size_t rdataSize = 0;
    uint8_t* dataBase = nullptr; size_t dataSize = 0;
    GetSections(mod, &rdataBase, &rdataSize, &dataBase, &dataSize);

    if (!dataBase)
    {
        OutputDebugStringA("[LceAntiWatermark] Could not find .data section.\n");
        return false;
    }

    // Update these if the displayed strings ever change
    bool ok = true;
    ok &= PatchString(dataBase, dataSize, L"Minecraft LCE d7596aa", "VERSION_STRING");
    ok &= PatchString(dataBase, dataSize, L"smartcmd/MinecraftConsoles/main", "BRANCH_STRING");
    return ok;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        MH_Initialize();

        if (!PatchVersionLines())
            OutputDebugStringA("[LceAntiWatermark] FAILED.\n");
        else
            OutputDebugStringA("[LceAntiWatermark] Zeroed strings.\n");
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
    }
    return TRUE;
}