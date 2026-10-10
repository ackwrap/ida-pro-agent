#include <cstdint>

volatile std::uint64_t semantic_marker = 0;
#ifdef _WIN32
#define EXPORTED extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define EXPORTED extern "C" __attribute__((visibility("default"), noinline))
#endif
EXPORTED void semantic_sink(std::uint64_t n) { semantic_marker = n; }
EXPORTED void semantic_checked(std::uint64_t n, std::uint64_t cap)
{ if (n > cap) return; semantic_sink(n); ++semantic_marker; }
EXPORTED void semantic_diamond(std::uint64_t n, std::uint64_t cap)
{ if (n <= cap) ++semantic_marker; semantic_sink(n); ++semantic_marker; }
EXPORTED void semantic_overwritten(std::uint64_t n, std::uint64_t cap, std::uint64_t other)
{ if (n > cap) return; n = other; semantic_sink(n); ++semantic_marker; }
EXPORTED void semantic_converted(std::int64_t n, std::int64_t cap)
{ if (n > cap) return; semantic_sink(static_cast<std::uint32_t>(n)); ++semantic_marker; }
EXPORTED void semantic_merge(std::uint64_t n, std::uint64_t flag)
{ if (flag) n = 7; semantic_sink(n); ++semantic_marker; }
EXPORTED void semantic_constant() { semantic_sink(UINT64_MAX); ++semantic_marker; }
EXPORTED void semantic_leaf(std::uint64_t n) { semantic_sink(n); ++semantic_marker; }
EXPORTED void semantic_mid(std::uint64_t n) { semantic_leaf(n + 5); ++semantic_marker; }
EXPORTED void semantic_top_a() { semantic_mid(0x1122); ++semantic_marker; }
EXPORTED void semantic_top_b() { semantic_leaf(0x3344); ++semantic_marker; }
EXPORTED void semantic_recursive(std::uint64_t n)
{ if (n == 0) return; semantic_recursive(n - 1); ++semantic_marker; }
EXPORTED void semantic_with_handler(std::uint64_t n)
{
  try { if (n == 42) throw 1; }
  catch (int) { ++semantic_marker; }
  semantic_sink(n); ++semantic_marker;
}
int main()
{
  semantic_checked(1, 4); semantic_diamond(5, 4); semantic_overwritten(1, 4, 100);
  semantic_converted(-1, 4); semantic_merge(3, 1); semantic_constant();
  semantic_top_a(); semantic_top_b(); semantic_recursive(3); semantic_with_handler(42); return 0;
}
