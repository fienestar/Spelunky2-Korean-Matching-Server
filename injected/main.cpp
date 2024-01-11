#include <WS2tcpip.h>
#include <Windows.h>
#include <thread>
#include <TlHelp32.h>
#include <unordered_map>
#include <string_view>
#include <fstream>
#include "../detours/include/detours.h"

#pragma comment(lib, "../Detours/lib.X64/detours.lib")
#pragma comment(lib, "Ws2_32.lib")

using namespace std;

class DNS {
public:
    static unordered_map<string, string> dns_table;
    static unordered_map<string, string> rdns_table;

    static string get_address_by_hostname(string hostname)
    {
        if (auto it = dns_table.find(hostname); it != dns_table.end()) {
            return it->second;
        }

        auto res = gethostbyname(hostname.data());
        if (res) {
            string ip = inet_ntoa(**(in_addr**)res->h_addr_list);
            dns_table[hostname] = ip;
            rdns_table[ip] = hostname;
            return ip;
        }

        return {};
    }

    static string get_hostname_by_address(string ip)
    {
        if (auto it = rdns_table.find(ip); it != rdns_table.end()) {
            return it->second;
        }

        return {};
    }

    static void set_alias(string hostname, string alias)
    {
        auto ip = get_address_by_hostname(hostname);
        dns_table[alias] = ip;
        rdns_table[ip] = alias;
    }
};

unordered_map<string, string> DNS::dns_table;
unordered_map<string, string> DNS::rdns_table;

void fill_rdns_table_from_known_hostnames()
{
    string edge = "edge-00.spelunky2.net";
    string alias = "edge-00";
    for (size_t i = 1; i != 32; ++i) {
        edge[5] = i / 10 + '0';
        edge[6] = i % 10 + '0';

        DNS::set_alias(edge, edge.substr(0, 7));
    }

    DNS::set_alias("spelunky-v20.mmo.gratis", "main");
}

DWORD get_pid_by_process_name(string_view process_name)
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

decltype(sendto)* ws2_sendto = nullptr;
decltype(recvfrom)* ws2_recvfrom = nullptr;
decltype(bind)* ws2_bind = nullptr;
string logfile;

void update_server_txt(string content)
{
    static string before = "$";
    if (content != before) {
        if (!logfile.empty())
            ofstream(logfile) << content;
        before = content;
    }
}

static size_t hostname_update_index = 0;
void update_hostname(string hostname)
{
    update_server_txt(hostname);
    ++hostname_update_index;
}

void replace_server(const sockaddr* addr)
{
    char ip[46] = {};
    auto addr_in = (sockaddr_in*)addr;
    InetNtopA(addr_in->sin_family, &addr_in->sin_addr, ip, sizeof(ip));

    if (DNS::get_hostname_by_address(ip) == "main") {
        addr_in->sin_addr.s_addr = inet_addr(DNS::get_address_by_hostname("edge-09").c_str());
    }
}

void restore_server(const sockaddr* addr)
{
    using namespace std::string_literals;
    char ip[46] = {};
    auto addr_in = (sockaddr_in*)addr;
    InetNtopA(addr_in->sin_family, &addr_in->sin_addr, ip, sizeof(ip));

    if (DNS::get_hostname_by_address(ip) == "edge-09") {
        addr_in->sin_addr.s_addr = inet_addr(DNS::get_address_by_hostname("main").c_str());
    }
}

int m_sendto(SOCKET s, char* buf, int len, int flags, const sockaddr* to, int tolen)
{
    replace_server(to);

    auto ret = ws2_sendto(s, buf, len, flags, to, tolen);

    char ip[46] = {};
    auto addr_in = (const sockaddr_in*)to;
    InetNtopA(addr_in->sin_family, &addr_in->sin_addr, ip, sizeof(ip));

    if (len > 2) {
        auto hostname = DNS::get_hostname_by_address(ip);
        if (hostname[0] == 'e')
            update_hostname(hostname);
    }

    return ret;
}

int m_recvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
    replace_server(from);

    auto ret = ws2_recvfrom(s, buf, len, flags, from, fromlen);

    if (len == 512 && buf[0] < 32)
        restore_server(from);

    return ret;
}

int m_bind(SOCKET s, const sockaddr* name, int namelen)
{
    replace_server(name);

    auto ret = ws2_bind(s, name, namelen);

    return ret;
}

string get_spel2_exe_dir()
{
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    size_t last_delimiter_pos = 0;
    for (size_t i = 0; path[i]; ++i)
        if (path[i] == '\\')
            last_delimiter_pos = i;
    return string(path, path + last_delimiter_pos);
}

void observe_send_interval()
{
    size_t before = hostname_update_index;
    while (true) {
        this_thread::sleep_for(500ms);
        if (before == hostname_update_index)
            update_server_txt("");
        before = hostname_update_index;
    }
}

int main()
{
    this_thread::sleep_for(2s);
    fill_rdns_table_from_known_hostnames();
    logfile = get_spel2_exe_dir() + "\\server.txt";
    update_server_txt("");

    DetourRestoreAfterWith();
    DetourUpdateThread(GetCurrentThread());
    DetourTransactionBegin();
    auto ws2 = GetModuleHandleA("ws2_32.dll");
    if (ws2 == 0) throw std::runtime_error("cannot find ws2_32.dll");
    ws2_sendto = (decltype(ws2_sendto))GetProcAddress(ws2, "sendto");
    ws2_recvfrom = (decltype(ws2_recvfrom))GetProcAddress(ws2, "recvfrom");
    ws2_bind = (decltype(ws2_bind))GetProcAddress(ws2, "bind");
    DetourAttach((void**)&ws2_sendto, m_sendto);
    DetourAttach((void**)&ws2_recvfrom, m_recvfrom);
    DetourAttach((void**)&ws2_sendto, m_sendto);
    LONG error = DetourTransactionCommit();
    thread(observe_send_interval).detach();
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        thread(main).detach();
        break;
    case DLL_PROCESS_DETACH:
        update_server_txt("");
        break;
    }

    return TRUE;
}

