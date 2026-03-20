#include <iostream>
#include <gk/email/email.hpp>

int main()
{
  auto normalized = gk::email::normalize("  User@Example.COM  ");

  if (normalized)
  {
    std::cout << "Normalized: " << *normalized << "\n";
  }
  else
  {
    std::cout << "Normalization failed\n";
  }
}
