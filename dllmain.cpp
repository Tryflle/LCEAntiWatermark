#include <windows.h>
#include "MinHook.h"
#include <cstdint>

static bool NopBytes(void* addr, SIZE_T len)
{
    DWORD old;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memset(addr, 0x90, len);
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// Resolves an absolute address from the exe's base + RVA
static void* FromRVA(uintptr_t rva)
{
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(GetModuleHandle(nullptr))
        - 0x140000000ULL  // subtract default x64 image base
        + rva
        );
}

static bool PatchVersionLines()
{
    // VERSION_STRING push_back call at 140247501
    // BRANCH_STRING  push_back call at 14024751c (capacity path)
    // BRANCH_STRING  push_back call at 140247540 (realloc path)
    //
    // Each is a 5-byte E8 relative CALL — NOP all three.

    const uintptr_t rvas[] = {
        0x140247501ULL,
        0x14024751CULL,
        0x140247540ULL,
    };

    for (uintptr_t rva : rvas)
    {
        void* addr = FromRVA(rva);

        // Sanity check — first byte should be E8 (CALL)
        if (*reinterpret_cast<uint8_t*>(addr) != 0xE8)
        {
            OutputDebugStringA("[Patch] Expected E8 at patch site — wrong address or ASLR issue.\n");
            return false;
        }

        if (!NopBytes(addr, 5))
            return false;
    }

    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        MH_Initialize();

        if (!PatchVersionLines())
            OutputDebugStringA("[Patch] FAILED to apply version string patch.\n");
        else
            OutputDebugStringA("[Patch] Version string lines successfully NOPed.\n");
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        MH_Uninitialize();
    }
    return TRUE;
}