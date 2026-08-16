#include "UserSessionAgent.h"

#if defined(_MSC_VER)
int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
    MobileUnlock::Agent::UserSessionAgent agent;
    return agent.Run();
}
#else
int main(int /*argc*/, char* /*argv*/[]) {
    MobileUnlock::Agent::UserSessionAgent agent;
    return agent.Run();
}
#endif
