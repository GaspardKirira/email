#include <iostream>
#include <email/email.hpp>

struct DummyDns : email::DnsValidationHook
{
  bool has_mx_record(std::string_view domain) const override
  {
    return domain == "example.com";
  }
};

struct DisposableCheck : email::DisposableEmailHook
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

  email::Address addr{"user", "tempmail.com"};

  auto result = email::validate(addr, {}, &dns, &disposable);

  for (auto &e : result.errors())
  {
    std::cout << "- " << e.message() << "\n";
  }
}
