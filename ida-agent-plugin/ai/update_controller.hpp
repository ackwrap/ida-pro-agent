#pragma once

#include <memory>
#include <string>

namespace ida_agent::ai
{
class UpdateController final
{
public:
  UpdateController();
  ~UpdateController();
  void Start();
  void Stop() noexcept;
  bool Automatic();
  bool SetAutomatic(bool automatic);
  void CheckNow();
  bool Checking() const;
  std::string Status() const;
  std::string ReleaseUrl() const;
private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
} // namespace ida_agent::ai
