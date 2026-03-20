#include <iostream>
#include <gk/email/email.hpp>

int main()
{
  std::string email_str = "user@example.com";

  if (gk::email::is_valid(email_str))
  {
    std::cout << "Valid email: " << email_str << "\n";
  }
  else
  {
    std::cout << "Invalid email\n";
  }
}
