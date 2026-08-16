#include <thread>
#include <windows.h>
int main(){ std::thread t([]{}); t.join(); return 0; }
