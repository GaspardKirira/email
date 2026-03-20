#include <iostream>
#include <gk/email/email.hpp>

int main()
{
  auto result = gk::email::validate("bad..email@-example..com");

  if (!result)
  {
    std::cout << "Validation errors:\n";
    for (auto &err : result.errors())
    {
      std::cout << "- " << err.message() << "\n";
    }
  }
  else
  {
    std::cout << "Valid email\n";
  }
}
