#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <psapi.h>
#include <vector>
#include <algorithm>
#include <string_view>

using namespace std;

DWORD get_pid_by_process_name(std::string_view process_name)
{
    auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);

    bool has_next = Process32First(snap, &pe32);
    while (has_next) {
        if (pe32.szExeFile == process_name) {
            CloseHandle(snap);
            return pe32.th32ProcessID;
        }
        has_next = Process32Next(snap, &pe32);
    }

    return 0;
}

std::string to_lower_case(std::string s)
{
    for (auto& ch : s)
        if ('A' <= ch && ch <= 'Z')
            ch |= 32;
    return s;
}

size_t find_base(HANDLE proc, std::string name)
{
    size_t cur = 0;
    MEMORY_BASIC_INFORMATION mbf = {};
    char buffer[0x1000] = {};

    name = to_lower_case(name);

    while (VirtualQueryEx(proc, (LPVOID)cur, &mbf, sizeof(mbf)) != 0)
    {
        auto res = GetModuleBaseNameA(proc, (HMODULE)cur, buffer, sizeof(buffer));
        if (res != 0)
        {
            if (name.find(to_lower_case(buffer)) != std::string::npos)
                return cur;
        };
        cur += mbf.RegionSize;
    }

    return 0;
}

LPTHREAD_START_ROUTINE find_function(HANDLE proc, const std::string& library, const std::string& function)
{
    auto library_ptr = (size_t)LoadLibraryA(library.data());
    if (library_ptr == 0) return 0;
    auto addr = (size_t)GetProcAddress((HMODULE)library_ptr, function.data());
    auto base = find_base(proc, library);
    if (addr == 0 || base == 0) return 0;
    return reinterpret_cast<LPTHREAD_START_ROUTINE>(addr - library_ptr + base);
}

bool inject_dll(HANDLE proc, const std::string& name)
{
    auto str = VirtualAllocEx(proc, nullptr, name.size()+1, MEM_COMMIT, 0x40);
    if (str == nullptr) return false;
    WriteProcessMemory(proc, str, name.data(), name.size(), NULL);
    LPTHREAD_START_ROUTINE func = find_function(proc, "Kernel32.DLL", "LoadLibraryA");
    auto thread_handle = CreateRemoteThread(proc, nullptr, 0, func, str, 0, nullptr);
    WaitForSingleObject(thread_handle, INFINITE);
    return true;
}

bool is_dll_in_process(DWORD pid, string dll_path)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (NULL == hProcess)
        return false;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(*szModName)))
            {
                if (szModName == dll_path)
                    return true;
            }
        }
    }
    return false;
}

string get_injector_dir()
{
    char path[MAX_PATH];
    GetModuleFileName(nullptr, path, MAX_PATH);
    size_t last_delimiter_pos = 0;
    for (size_t i = 0; path[i]; ++i)
        if (path[i] == '\\')
            last_delimiter_pos = i;
    return string(path, path + last_delimiter_pos);
}

int main()
{
    using namespace std::chrono_literals;
    DWORD pid = get_pid_by_process_name("Spel2.exe");
    if (pid == 0) {
        std::cout << "Waiting for spel2.exe\n";
        while (!(pid = get_pid_by_process_name("Spel2.exe")))
            std::this_thread::sleep_for(100ms);
    }
    std::this_thread::sleep_for(500ms);

    cout << "found pid: " << pid << "\n";

    auto dll_path = get_injector_dir() + "\\spel2-online.dll";
    auto proc = OpenProcess(0x1FFFFF, false, pid);
    cout << boolalpha << inject_dll(proc, dll_path.c_str()) << std::endl;
    cout << "Dll Injection: " << (is_dll_in_process(pid, dll_path) ? "success" : "failed") << std::endl;
}
