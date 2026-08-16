#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include "MobileUnlockService.h"

#if defined(_MSC_VER)
int wmain(int argc, wchar_t* argv[]) {
    return MobileUnlock::Service::MobileUnlockService::GetInstance().Run(argc, argv);
}
#else
int main(int /*argc*/, char* /*argv*/[]) {
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    int result = MobileUnlock::Service::MobileUnlockService::GetInstance().Run(wargc, wargv);
    if (wargv) LocalFree(wargv);
    return result;
}
#endif
