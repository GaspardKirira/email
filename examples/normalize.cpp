#include <iostream>
#include <email/email.hpp>

int main()
{
  auto normalized = email::normalize("  User@Example.COM  ");

  if (normalized)
  {
    std::cout << "Normalized: " << *normalized << "\n";
  }
  else
  {
    std::cout << "Normalization failed\n";
  }
}
