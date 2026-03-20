#include <iostream>
#include <gk/email/email.hpp>

struct DummyDns : gk::email::DnsValidationHook
{
  bool has_mx_record(std::string_view domain) const override
  {
    return domain == "example.com";
  }
};

struct DisposableCheck : gk::email::DisposableEmailHook
{
  bool is_disposable(std::string_view domain) const override
  {
    return domain == "tempmail.com";
  }
};

int main()
{
  DummyDns dns;
  DisposableCheck disposable;

  gk::email::Address addr{"user", "tempmail.com"};

  auto result = gk::email::validate(addr, {}, &dns, &disposable);

  for (auto &e : result.errors())
  {
    std::cout << "- " << e.message() << "\n";
  }
}
