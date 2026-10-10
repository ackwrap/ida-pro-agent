// Owned, time-bounded fixture. Only the runner's specific IDAT PID may attach.
#include <sys/prctl.h>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>

extern "C"
{
__attribute__((visibility("default"))) volatile std::uint64_t ida_debugger_test_counter = 0;
__attribute__((visibility("default"), noinline)) void ida_debugger_test_tick()
{
  ++ida_debugger_test_counter;
}
}

int main(int argc, char **argv)
{
  if (argc == 2)
  {
    const auto ptracer = std::strtol(argv[1], nullptr, 10);
    if (ptracer <= 0 || prctl(PR_SET_PTRACER, ptracer, 0, 0, 0) != 0) return 1;
  }
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
  while (std::chrono::steady_clock::now() < deadline)
  {
    ida_debugger_test_tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  return 0;
}
