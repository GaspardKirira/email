#include <iostream>
#include <gk/email/email.hpp>

int main()
{
  auto result = gk::email::parse("User@Example.COM");

  if (result)
  {
    auto addr = result.address();
    std::cout << "Local: " << addr.local() << "\n";
    std::cout << "Domain: " << addr.domain() << "\n";
  }
  else
  {
    std::cout << "Parse failed:\n";
    for (auto &e : result.errors())
    {
      std::cout << "- " << e.message() << "\n";
    }
  }
}
