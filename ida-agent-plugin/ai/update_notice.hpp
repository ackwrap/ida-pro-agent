#pragma once

#include "ai/update_check.hpp"
#include <QtWidgets>
#include <functional>

namespace ida_agent::ai
{
// Main-thread update prompt. Automatic notices are shown once per release;
// an explicit manual check can reopen a dismissed notice for that release.
class UpdateNotice final
{
public:
  using OpenReleasePage = std::function<bool(const QT::QUrl &)>;
  explicit UpdateNotice(OpenReleasePage open_release = {});
  ~UpdateNotice();
  UpdateNotice(const UpdateNotice &) = delete;
  UpdateNotice &operator=(const UpdateNotice &) = delete;
  bool Show(std::string_view installed, const UpdateCache &cache, bool manual,
      QT::QWidget *parent);
  void Close() noexcept;

private:
  OpenReleasePage open_release_;
  QT::QPointer<QT::QDialog> dialog_;
  std::string notified_tag_;
};
} // namespace ida_agent::ai
