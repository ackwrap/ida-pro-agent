#include <windows.h>
// A harmless, bounded target created exclusively by the integration runner.
// Exported addresses let IDA tests locate code/data without private symbols.
extern "C" __declspec(dllexport) volatile unsigned long ida_debugger_test_counter = 0;
extern "C" __declspec(dllexport) __declspec(noinline) void ida_debugger_test_tick()
{
  ++ida_debugger_test_counter;
}
int main()
{
  const ULONGLONG deadline = GetTickCount64() + 120000;
  while ( GetTickCount64() < deadline )
  {
    ida_debugger_test_tick();
    Sleep(25);
  }
  return 0;
}
