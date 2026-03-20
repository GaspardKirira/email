/**
 * @file test_basic.cpp
 * @brief Comprehensive test suite for email.hpp.
 *
 * Self-contained — no external test framework required.
 * Compile with:
 *   g++ -std=c++20 -Wall -Wextra -o test_basic test_basic.cpp && ./test_basic
 *
 * Exit code 0 = all tests passed.
 * Exit code 1 = at least one failure.
 */

#include <gk/email/email.hpp>

#include <iostream>
#include <string>

using namespace gk;

namespace test
{
  static int total = 0;
  static int passed = 0;
  static int failed = 0;

  void suite(std::string_view name)
  {
    std::cout << "\n── " << name << " ──\n";
  }

  void pass(std::string_view name)
  {
    ++total;
    ++passed;
    std::cout << "  \033[32m[PASS]\033[0m " << name << "\n";
  }

  void fail(std::string_view name, std::string_view reason = "")
  {
    ++total;
    ++failed;
    std::cout << "  \033[31m[FAIL]\033[0m " << name;
    if (!reason.empty())
      std::cout << "  →  " << reason;
    std::cout << "\n";
  }

// Evaluate expr; no exception expected.
#define CHECK(name, expr)                                                  \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      if (expr)                                                            \
      {                                                                    \
        test::pass(name);                                                  \
      }                                                                    \
      else                                                                 \
      {                                                                    \
        test::fail(name, "expression was false");                          \
      }                                                                    \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("unexpected exception: ") + _e.what()); \
    }                                                                      \
  } while (0)

// Assert that no exception is thrown.
#define NO_THROW(name, expr)                                               \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      expr;                                                                \
      test::pass(name);                                                    \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("unexpected exception: ") + _e.what()); \
    }                                                                      \
  } while (0)

// Assert that a specific exception type is thrown.
#define THROWS(name, ExType, expr)                                    \
  do                                                                  \
  {                                                                   \
    bool _caught = false;                                             \
    try                                                               \
    {                                                                 \
      expr;                                                           \
    }                                                                 \
    catch (const ExType &)                                            \
    {                                                                 \
      _caught = true;                                                 \
    }                                                                 \
    catch (const std::exception &_e)                                  \
    {                                                                 \
      test::fail(name, std::string("wrong exception: ") + _e.what()); \
      break;                                                          \
    }                                                                 \
    if (_caught)                                                      \
      test::pass(name);                                               \
    else                                                              \
      test::fail(name, "no exception thrown");                        \
  } while (0)

// Assert that a specific ErrorCode appears among fatal errors.
#define HAS_CODE(name, vr_expr, expected_code)                             \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      auto _vr = (vr_expr);                                                \
      bool _found = false;                                                 \
      for (const auto &_e : _vr.errors())                                  \
        if (_e.code() == (expected_code))                                  \
        {                                                                  \
          _found = true;                                                   \
          break;                                                           \
        }                                                                  \
      if (_found)                                                          \
        test::pass(name);                                                  \
      else                                                                 \
        test::fail(name, "error code not found in result");                \
    }                                                                      \
    catch (const std::exception &_e)                                       \
    {                                                                      \
      test::fail(name, std::string("unexpected exception: ") + _e.what()); \
    }                                                                      \
  } while (0)

  void summary()
  {
    std::cout << "\n════════════════════════════════════\n";
    std::cout << "  Total  : " << total << "\n";
    std::cout << "  Passed : \033[32m" << passed << "\033[0m\n";
    if (failed > 0)
      std::cout << "  Failed : \033[31m" << failed << "\033[0m\n";
    else
      std::cout << "  Failed : 0\n";
    std::cout << "════════════════════════════════════\n";
  }

} // namespace test

struct NoMxHook : email::DnsValidationHook
{
  bool has_mx_record(std::string_view) const override { return false; }
};

struct HasMxHook : email::DnsValidationHook
{
  bool has_mx_record(std::string_view) const override { return true; }
};

struct DisposableHook : email::DisposableEmailHook
{
  bool is_disposable(std::string_view) const override { return true; }
};

struct NotDisposableHook : email::DisposableEmailHook
{
  bool is_disposable(std::string_view) const override { return false; }
};

// IDN encoder that prepends "xn--" to each non-ASCII label (fake, just for API testing)
struct FakeIdnEncoder : email::IdnEncoderHook
{
  std::optional<std::string> encode(std::string_view label) const override
  {
    return "xn--" + std::string(label.substr(0, label.find('\xc3')));
  }
};

static void test_error_class()
{
  test::suite("Error class and ErrorCode");

  // error_code_to_string covers all codes
  CHECK("None string", email::error_code_to_string(email::ErrorCode::None) == "No error");
  CHECK("EmptyInput string", email::error_code_to_string(email::ErrorCode::EmptyInput) == "Input is empty");
  CHECK("MissingAtSign string", email::error_code_to_string(email::ErrorCode::MissingAtSign) == "Missing '@' sign");
  CHECK("MultipleAtSigns string", email::error_code_to_string(email::ErrorCode::MultipleAtSigns) == "Multiple '@' signs found");
  CHECK("EmptyLocalPart string", email::error_code_to_string(email::ErrorCode::EmptyLocalPart) == "Local part is empty");
  CHECK("EmptyDomain string", email::error_code_to_string(email::ErrorCode::EmptyDomain) == "Domain is empty");
  CHECK("ExceedsMaxLength string", email::error_code_to_string(email::ErrorCode::ExceedsMaxLength).find("320") != std::string_view::npos);
  CHECK("LocalPartTooLong string", email::error_code_to_string(email::ErrorCode::LocalPartTooLong).find("64") != std::string_view::npos);
  CHECK("DomainTooLong string", email::error_code_to_string(email::ErrorCode::DomainTooLong).find("255") != std::string_view::npos);
  CHECK("DomainTldTooShort string", email::error_code_to_string(email::ErrorCode::DomainTldTooShort).find("2") != std::string_view::npos);
  CHECK("DnsValidationFailed string", email::error_code_to_string(email::ErrorCode::DnsValidationFailed).find("MX") != std::string_view::npos);
  CHECK("DisposableEmailDetected", email::error_code_to_string(email::ErrorCode::DisposableEmailDetected).find("Disposable") != std::string_view::npos);
  CHECK("Unknown code string", email::error_code_to_string(static_cast<email::ErrorCode>(9999)) == "Unknown error");

  // Error construction and accessors
  {
    email::Error e{email::ErrorCode::EmptyInput, email::Severity::Error};
    CHECK("error code accessor", e.code() == email::ErrorCode::EmptyInput);
    CHECK("error severity", e.severity() == email::Severity::Error);
    CHECK("error is_error", e.is_error());
    CHECK("error not is_warning", !e.is_warning());
    CHECK("error message non-empty", !e.message().empty());
    CHECK("error no position", !e.position().has_value());
  }
  {
    email::Error e{email::ErrorCode::DomainLabelTooLong, email::Severity::Warning, std::size_t{5}};
    CHECK("warning is_warning", e.is_warning());
    CHECK("warning not is_error", !e.is_error());
    CHECK("warning position", e.position() == std::size_t{5});
  }
  {
    email::Error e{email::ErrorCode::LocalPartConsecutiveDots, email::Severity::Error,
                   std::string("test message"), std::optional<std::size_t>{7}};
    CHECK("custom message", e.message() == "test message");
    CHECK("custom position", e.position() == std::size_t{7});
  }
  {
    // Constructor taking (code, severity, size_t)
    email::Error e{email::ErrorCode::DomainLeadingDot, email::Severity::Error, std::size_t{0}};
    CHECK("pos ctor position", e.position() == std::size_t{0});
    CHECK("pos ctor default msg", !e.message().empty());
  }
}

// =============================================================================
//  2 – Address class
// =============================================================================

static void test_address_class()
{
  test::suite("Address class");

  // Default construction
  {
    email::Address a;
    CHECK("default empty", a.empty());
    CHECK("default local empty", a.local().empty());
    CHECK("default domain empty", a.domain().empty());
    CHECK("default to_string", a.to_string().empty());
    CHECK("default no display_name", !a.display_name().has_value());
  }

  // Two-argument construction
  {
    email::Address a{"user", "example.com"};
    CHECK("local", a.local() == "user");
    CHECK("domain", a.domain() == "example.com");
    CHECK("to_string", a.to_string() == "user@example.com");
    CHECK("not empty", !a.empty());
    CHECK("no display_name", !a.display_name().has_value());
  }

  // Three-argument construction (with display name)
  {
    email::Address a{"user", "example.com", "John Doe"};
    CHECK("display_name set", a.display_name().has_value());
    CHECK("display_name value", *a.display_name() == "John Doe");
    CHECK("to_string no name", a.to_string() == "user@example.com");
  }

  // Equality operators
  {
    email::Address a1{"user", "example.com"};
    email::Address a2{"user", "example.com"};
    email::Address a3{"User", "example.com"};
    email::Address a4{"user", "EXAMPLE.COM"};
    CHECK("== same", a1 == a2);
    CHECK("!= different local", a1 != a3);
    CHECK("!= different domain", a1 != a4);
  }

  // equivalent_to — case-insensitive domain comparison
  {
    email::Address a1{"user", "example.com"};
    email::Address a2{"user", "EXAMPLE.COM"};
    email::Address a3{"user", "Example.Com"};
    email::Address a4{"User", "example.com"}; // local differs
    CHECK("equivalent_to same case", a1.equivalent_to(a2));
    CHECK("equivalent_to mixed case", a1.equivalent_to(a3));
    CHECK("not equivalent diff local", !a1.equivalent_to(a4));
  }
}

// =============================================================================
//  3 – ValidationResult
// =============================================================================

static void test_validation_result()
{
  test::suite("ValidationResult");

  // Empty result = valid
  {
    email::ValidationResult vr;
    CHECK("empty is valid", vr.is_valid());
    CHECK("empty bool op", static_cast<bool>(vr));
    CHECK("empty error_count", vr.error_count() == 0);
    CHECK("empty is empty", vr.empty());
    CHECK("empty errors vec", vr.errors().empty());
    CHECK("empty fatal_errors", vr.fatal_errors().empty());
    CHECK("empty warnings", vr.warnings().empty());
  }

  // Adding a fatal error makes it invalid
  {
    email::ValidationResult vr;
    vr.add_error(email::Error{email::ErrorCode::EmptyInput, email::Severity::Error});
    CHECK("with error not valid", !vr.is_valid());
    CHECK("with error bool op", !static_cast<bool>(vr));
    CHECK("with error count", vr.error_count() == 1);
    CHECK("fatal_errors size", vr.fatal_errors().size() == 1);
    CHECK("warnings empty", vr.warnings().empty());
  }

  // Adding a warning keeps it valid
  {
    email::ValidationResult vr;
    vr.add_error(email::Error{email::ErrorCode::DomainTrailingDot, email::Severity::Warning});
    CHECK("warning still valid", vr.is_valid());
    CHECK("warning count", vr.error_count() == 1);
    CHECK("fatal empty", vr.fatal_errors().empty());
    CHECK("warnings size", vr.warnings().size() == 1);
  }

  // Merge
  {
    email::ValidationResult vr1, vr2;
    vr1.add_error(email::Error{email::ErrorCode::EmptyInput, email::Severity::Error});
    vr2.add_error(email::Error{email::ErrorCode::EmptyDomain, email::Severity::Warning});
    vr1.merge(vr2);
    CHECK("merge total", vr1.error_count() == 2);
    CHECK("merge still invalid", !vr1.is_valid());
    CHECK("merge warnings present", vr1.warnings().size() == 1);
  }

  // Mixed errors and warnings
  {
    email::ValidationResult vr;
    vr.add_error(email::Error{email::ErrorCode::EmptyInput, email::Severity::Error});
    vr.add_error(email::Error{email::ErrorCode::DomainTrailingDot, email::Severity::Warning});
    vr.add_error(email::Error{email::ErrorCode::DomainNumericTld, email::Severity::Error});
    CHECK("mixed total", vr.error_count() == 3);
    CHECK("mixed fatal", vr.fatal_errors().size() == 2);
    CHECK("mixed warnings", vr.warnings().size() == 1);
    CHECK("mixed not valid", !vr.is_valid());
  }
}

// =============================================================================
//  4 – ParseResult
// =============================================================================

static void test_parse_result()
{
  test::suite("ParseResult");

  // Successful parse
  {
    auto r = email::parse("user@example.com");
    CHECK("success() true", r.success());
    CHECK("bool op true", static_cast<bool>(r));
    CHECK("errors empty", r.errors().empty());
    CHECK("first_error none", !r.first_error().has_value());
    CHECK("address local", r.address().local() == "user");
    CHECK("address domain", r.address().domain() == "example.com");
    CHECK("address_or returns addr", r.address_or().to_string() == "user@example.com");
  }

  // Failed parse
  {
    auto r = email::parse("bad-email");
    CHECK("failed success() false", !r.success());
    CHECK("failed bool op false", !static_cast<bool>(r));
    CHECK("failed errors not empty", !r.errors().empty());
    CHECK("failed first_error set", r.first_error().has_value());
  }

  // address() throws on failure
  {
    auto r = email::parse("bad");
    THROWS("address() throws on fail", std::logic_error, (void)r.address());
  }

  // address_or fallback
  {
    auto r = email::parse("bad");
    email::Address fallback{"fb", "fallback.com"};
    auto a = r.address_or(fallback);
    CHECK("address_or fallback local", a.local() == "fb");
    CHECK("address_or fallback domain", a.domain() == "fallback.com");
  }

  // first_error carries the right code
  {
    auto r = email::parse("missingatexample.com");
    auto fe = r.first_error();
    CHECK("first_error code MissingAt",
          fe.has_value() && fe->code() == email::ErrorCode::MissingAtSign);
  }
}

// =============================================================================
//  5 – is_valid() — quick boolean validation
// =============================================================================

static void test_is_valid()
{
  test::suite("is_valid()");

  // Valid addresses
  CHECK("plain", email::is_valid("user@example.com"));
  CHECK("subdomain", email::is_valid("a.b@sub.example.co.uk"));
  CHECK("plus tag", email::is_valid("user+tag@example.com"));
  CHECK("underscore local", email::is_valid("first_last@example.com"));
  CHECK("hyphen local", email::is_valid("user-name@example.com"));
  CHECK("digits local", email::is_valid("user123@example.com"));
  CHECK("uppercase domain", email::is_valid("user@EXAMPLE.COM"));
  CHECK("numeric local", email::is_valid("123@example.com"));
  CHECK("single char local", email::is_valid("a@example.com"));

  // Invalid addresses — structural
  CHECK("empty string", !email::is_valid(""));
  CHECK("only spaces", !email::is_valid("   "));
  CHECK("no at sign", !email::is_valid("userexample.com"));
  CHECK("two at signs", !email::is_valid("user@@example.com"));
  CHECK("three at signs", !email::is_valid("a@@b@example.com"));
  CHECK("empty local", !email::is_valid("@example.com"));
  CHECK("empty domain", !email::is_valid("user@"));

  // Invalid addresses — local part
  CHECK("leading dot local", !email::is_valid(".user@example.com"));
  CHECK("trailing dot local", !email::is_valid("user.@example.com"));
  CHECK("consec dots local", !email::is_valid("us..er@example.com"));
  CHECK("space in local", !email::is_valid("us er@example.com"));
  CHECK("at in local", !email::is_valid("us@er@example.com"));
  {
    std::string long_local(65, 'a');
    CHECK("local too long", !email::is_valid(long_local + "@example.com"));
  }

  // Invalid addresses — domain
  CHECK("no dot in domain", !email::is_valid("user@localhost"));
  CHECK("leading dot domain", !email::is_valid("user@.example.com"));
  CHECK("hyphen start label", !email::is_valid("user@-bad.com"));
  CHECK("hyphen end label", !email::is_valid("user@bad-.com"));
  CHECK("numeric tld", !email::is_valid("user@example.123"));
  CHECK("consecutive dots domain", !email::is_valid("user@exam..ple.com"));
  CHECK("ip literal no flag", !email::is_valid("user@[192.168.1.1]"));

  // Trailing dot domain = warning only → still valid
  CHECK("trailing dot domain ok", email::is_valid("user@example.com."));

  // Null byte in input
  {
    std::string s = "user";
    s += '\0';
    s += "@example.com";
    CHECK("null byte invalid", !email::is_valid(s));
  }
}

// =============================================================================
//  6 – parse()
// =============================================================================

static void test_parse()
{
  test::suite("parse()");

  // Basic parse
  {
    auto r = email::parse("user@example.com");
    CHECK("parse ok", r.success());
    CHECK("local", r.address().local() == "user");
    CHECK("domain", r.address().domain() == "example.com");
  }

  // Whitespace trimming (default ParseOptions trims)
  {
    auto r = email::parse("  user@example.com  ");
    CHECK("trimmed parse ok", r.success());
    CHECK("trimmed local", r.address().local() == "user");
  }

  // Display name angle-addr form
  {
    auto r = email::parse("John Doe <user@example.com>");
    CHECK("angle-addr ok", r.success());
    CHECK("angle local", r.address().local() == "user");
    CHECK("angle domain", r.address().domain() == "example.com");
    CHECK("display name", r.address().display_name().has_value() &&
                              *r.address().display_name() == "John Doe");
  }

  // Angle-addr without display name
  {
    auto r = email::parse("<user@example.com>");
    CHECK("bare angle ok", r.success());
    CHECK("bare angle local", r.address().local() == "user");
  }

  // Structural failures
  {
    auto r = email::parse("");
    CHECK("empty fails", !r.success());
    HAS_CODE("empty code", email::validate(""), email::ErrorCode::EmptyInput);
  }
  {
    auto r = email::parse("no-at-sign");
    CHECK("no @ fails", !r.success());
    CHECK("no @ first_error", r.first_error().has_value() &&
                                  r.first_error()->code() == email::ErrorCode::MissingAtSign);
  }
  {
    auto r = email::parse("a@@b.com");
    CHECK("two @ fails", !r.success());
    CHECK("two @ code", r.first_error().has_value() &&
                            r.first_error()->code() == email::ErrorCode::MultipleAtSigns);
  }
  {
    auto r = email::parse("@example.com");
    CHECK("empty local fails", !r.success());
  }
  {
    auto r = email::parse("user@");
    CHECK("empty domain fails", !r.success());
  }

  // Null byte
  {
    std::string s = "user";
    s += '\0';
    s += "@x.com";
    auto r = email::parse(s);
    CHECK("null byte fails", !r.success());
  }

  // Max length via ParseOptions
  {
    email::ParseOptions po;
    po.validation.max_email_length = 10;
    auto r = email::parse("user@example.com", po); // 16 chars > 10
    CHECK("max_email_length parse fails", !r.success());
    CHECK("max_length code", r.first_error().has_value() &&
                                 r.first_error()->code() == email::ErrorCode::ExceedsMaxLength);
  }
}

// =============================================================================
//  7 – validate() — detailed error reporting
// =============================================================================

static void test_validate()
{
  test::suite("validate()");

  // --- Local part errors ---
  HAS_CODE("leading dot local",
           email::validate(".user@example.com"),
           email::ErrorCode::LocalPartLeadingDot);

  HAS_CODE("trailing dot local",
           email::validate("user.@example.com"),
           email::ErrorCode::LocalPartTrailingDot);

  HAS_CODE("consecutive dots local",
           email::validate("us..er@example.com"),
           email::ErrorCode::LocalPartConsecutiveDots);

  HAS_CODE("invalid char space",
           email::validate("us er@example.com"),
           email::ErrorCode::LocalPartInvalidChar);

  {
    std::string long_local(65, 'a');
    HAS_CODE("local too long",
             email::validate(long_local + "@example.com"),
             email::ErrorCode::LocalPartTooLong);
  }

  // --- Domain errors ---
  HAS_CODE("no dot in domain",
           email::validate("user@localhost"),
           email::ErrorCode::DomainMissingDot);

  HAS_CODE("leading dot domain",
           email::validate("user@.example.com"),
           email::ErrorCode::DomainLeadingDot);

  HAS_CODE("hyphen start label",
           email::validate("user@-bad.com"),
           email::ErrorCode::DomainLabelStartsWithHyphen);

  HAS_CODE("hyphen end label",
           email::validate("user@bad-.com"),
           email::ErrorCode::DomainLabelEndsWithHyphen);

  HAS_CODE("numeric tld",
           email::validate("user@example.123"),
           email::ErrorCode::DomainNumericTld);

  HAS_CODE("consecutive dots domain",
           email::validate("user@exam..ple.com"),
           email::ErrorCode::DomainConsecutiveDots);

  HAS_CODE("ip literal rejected by default",
           email::validate("user@[192.168.1.1]"),
           email::ErrorCode::DomainInvalidChar);

  {
    std::string long_label(64, 'a');
    HAS_CODE("label too long",
             email::validate("user@" + long_label + ".com"),
             email::ErrorCode::DomainLabelTooLong);
  }

  // Trailing dot domain = warning, not error — still valid
  {
    auto vr = email::validate("user@example.com.");
    CHECK("trailing dot valid", vr.is_valid());
    CHECK("trailing dot warning", !vr.warnings().empty());
    CHECK("trailing dot no fatal", vr.fatal_errors().empty());
    bool has_trailing = false;
    for (auto &w : vr.warnings())
      if (w.code() == email::ErrorCode::DomainTrailingDot)
        has_trailing = true;
    CHECK("trailing dot code", has_trailing);
  }

  // --- validate(Address, options) overload ---
  {
    email::Address addr{"user", "example.com"};
    auto vr = email::validate(addr);
    CHECK("Address overload valid", vr.is_valid());
  }

  // --- IP domain with allow_ip_domain ---
  {
    email::ValidationOptions o;
    o.allow_ip_domain = true;
    auto vr = email::validate(email::Address{"user", "[192.168.1.1]"}, o);
    CHECK("valid ipv4 literal", vr.is_valid());
  }
  {
    email::ValidationOptions o;
    o.allow_ip_domain = true;
    auto vr = email::validate(email::Address{"user", "[256.0.0.1]"}, o);
    CHECK("invalid ipv4 literal", !vr.is_valid());
    HAS_CODE("bad ipv4 code",
             email::validate(email::Address{"user", "[256.0.0.1]"}, o),
             email::ErrorCode::DomainIpLiteralInvalid);
  }
  {
    email::ValidationOptions o;
    o.allow_ip_domain = true;
    auto vr = email::validate(email::Address{"user", "[IPv6:::1]"}, o);
    CHECK("valid ipv6 loopback literal", vr.is_valid());
  }
  {
    email::ValidationOptions o;
    o.allow_ip_domain = true;
    auto vr = email::validate(email::Address{"user", "[IPv6:2001:db8::1]"}, o);
    CHECK("valid ipv6 doc addr literal", vr.is_valid());
  }

  // --- max_email_length via ValidationOptions ---
  {
    email::ValidationOptions o;
    o.max_email_length = 15;
    auto vr = email::validate("user@example.com", o); // 16 chars
    CHECK("max_email_length fails", !vr.is_valid());
    HAS_CODE("max_email_length code",
             email::validate("user@example.com", o),
             email::ErrorCode::ExceedsMaxLength);
  }

  // --- position reported for consecutive dots ---
  {
    auto vr = email::validate("us..er@example.com");
    bool has_pos = false;
    for (auto &e : vr.errors())
      if (e.code() == email::ErrorCode::LocalPartConsecutiveDots &&
          e.position().has_value())
        has_pos = true;
    CHECK("consec dots position", has_pos);
  }

  // --- null byte ---
  {
    std::string s = "user";
    s += '\0';
    s += "@example.com";
    auto vr = email::validate(s);
    CHECK("null byte invalid", !vr.is_valid());
    HAS_CODE("null byte code",
             email::validate(s),
             email::ErrorCode::NullCharacter);
  }
}

// =============================================================================
//  8 – validate() with ValidationOptions flags
// =============================================================================

static void test_validate_options()
{
  test::suite("validate() with ValidationOptions");

  // require_tld = false: domain still needs a dot (library always requires at
  // least one dot for structural reasons); the flag only disables TLD checks.
  // Use a domain that has a dot but a trivial TLD which would normally warn.
  {
    email::ValidationOptions o;
    o.require_tld = false;
    // "user@example.x" has a dot; with require_tld=false the short TLD warning
    // is suppressed → the result should be valid with no fatal errors.
    auto vr = email::validate("user@example.x", o);
    CHECK("require_tld false ok", vr.is_valid());
  }

  // reject_numeric_tld = false
  {
    email::ValidationOptions o;
    o.reject_numeric_tld = false;
    auto vr = email::validate("user@example.123", o);
    // still needs a dot check — has dot, so DomainMissingDot not triggered
    // numeric tld error suppressed, should be valid (may have TLD short warning)
    bool no_numeric_err = true;
    for (auto &e : vr.fatal_errors())
      if (e.code() == email::ErrorCode::DomainNumericTld)
        no_numeric_err = false;
    CHECK("reject_numeric_tld false no err", no_numeric_err);
  }

  // max_local_length
  {
    email::ValidationOptions o;
    o.max_local_length = 5;
    auto vr = email::validate("toolong@example.com", o);
    CHECK("max_local_length enforced", !vr.is_valid());
    HAS_CODE("max_local_length code",
             email::validate("toolong@example.com", o),
             email::ErrorCode::LocalPartTooLong);
  }

  // max_label_length
  {
    email::ValidationOptions o;
    o.max_label_length = 5;
    auto vr = email::validate("user@toolonglabel.com", o);
    CHECK("max_label_length enforced", !vr.is_valid());
  }

  // max_domain_length
  {
    email::ValidationOptions o;
    o.max_domain_length = 10;
    auto vr = email::validate("user@example.com", o); // domain = 11 chars
    CHECK("max_domain_length enforced", !vr.is_valid());
    HAS_CODE("max_domain_length code",
             email::validate("user@example.com", o),
             email::ErrorCode::DomainTooLong);
  }
}

// =============================================================================
//  9 – normalize()
// =============================================================================

static void test_normalize()
{
  test::suite("normalize()");

  // String overload — default trims whitespace and lowercases domain
  {
    auto n = email::normalize("  User@EXAMPLE.COM  ");
    CHECK("trim + lowercase domain", n.has_value() && *n == "User@example.com");
  }
  {
    auto n = email::normalize("user@example.com");
    CHECK("already normalized", n.has_value() && *n == "user@example.com");
  }

  // Returns nullopt on malformed input
  {
    auto n = email::normalize("bad-email");
    CHECK("malformed returns nullopt", !n.has_value());
  }
  {
    auto n = email::normalize("");
    CHECK("empty returns nullopt", !n.has_value());
  }
  {
    auto n = email::normalize("a@@b.com");
    CHECK("double @ returns nullopt", !n.has_value());
  }

  // NormalizeOptions on string overload
  {
    email::NormalizeOptions o;
    o.lowercase_domain = false;
    auto n = email::normalize("user@EXAMPLE.COM", o);
    CHECK("no lowercase domain", n.has_value() && *n == "user@EXAMPLE.COM");
  }
  {
    email::NormalizeOptions o;
    o.trim_whitespace = false;
    auto n = email::normalize("  user@example.com  ", o);
    // Without trim, spaces remain → two '@' via count_char gives nullopt
    // actually count_char("  user@example.com  ", '@') == 1 so it succeeds
    // but trim_whitespace=false: the spaces stay in the string
    CHECK("no trim preserves spaces", n.has_value()); // still 1 @, parses ok
  }

  // Address overload — all NormalizeOptions flags
  {
    email::Address a{"User+tag", "EXAMPLE.COM"};

    // Default: lowercase domain only
    {
      auto n = email::normalize(a);
      CHECK("addr norm domain lower", n.domain() == "example.com");
      CHECK("addr norm local unchanged", n.local() == "User+tag");
    }

    // remove_plus_tag
    {
      email::NormalizeOptions o;
      o.remove_plus_tag = true;
      auto n = email::normalize(a, o);
      CHECK("remove plus tag", n.local() == "User");
    }

    // lowercase_local
    {
      email::NormalizeOptions o;
      o.lowercase_local = true;
      auto n = email::normalize(a, o);
      CHECK("lowercase local", n.local() == "user+tag");
    }

    // remove_dots_from_local
    {
      email::NormalizeOptions o;
      o.remove_dots_from_local = true;
      email::Address dotted{"j.o.h.n", "example.com"};
      auto n = email::normalize(dotted, o);
      CHECK("remove dots", n.local() == "john");
    }

    // Combined: lowercase_local + remove_plus_tag
    {
      email::NormalizeOptions o;
      o.lowercase_local = true;
      o.remove_plus_tag = true;
      auto n = email::normalize(a, o);
      CHECK("combined local+plus", n.local() == "user");
      CHECK("combined domain", n.domain() == "example.com");
    }
  }

  // Display name is preserved through normalization
  {
    email::Address a{"User", "EXAMPLE.COM", "John Doe"};
    auto n = email::normalize(a);
    CHECK("display name preserved", n.display_name().has_value() &&
                                        *n.display_name() == "John Doe");
  }
}

// =============================================================================
//  10 – try_parse()
// =============================================================================

static void test_try_parse()
{
  test::suite("try_parse()");

  {
    auto a = email::try_parse("user@example.com");
    CHECK("success returns addr", a.has_value());
    CHECK("local ok", a.has_value() && a->local() == "user");
    CHECK("domain ok", a.has_value() && a->domain() == "example.com");
  }
  {
    auto a = email::try_parse("");
    CHECK("empty returns nullopt", !a.has_value());
  }
  {
    auto a = email::try_parse("no-at-sign");
    CHECK("no @ returns nullopt", !a.has_value());
  }
  {
    auto a = email::try_parse("user@@example.com");
    CHECK("double @ nullopt", !a.has_value());
  }
}

// =============================================================================
//  11 – parse_and_validate()
// =============================================================================

static void test_parse_and_validate()
{
  test::suite("parse_and_validate()");

  // Valid input → normalized address + valid result
  {
    auto [addr, vr] = email::parse_and_validate("User@EXAMPLE.COM");
    CHECK("pav valid", vr.is_valid());
    CHECK("pav domain normalized", addr.domain() == "example.com");
    CHECK("pav local unchanged", addr.local() == "User");
  }

  // Invalid input → empty address + invalid result
  {
    auto [addr, vr] = email::parse_and_validate("bad-input");
    CHECK("pav bad empty addr", addr.empty());
    CHECK("pav bad not valid", !vr.is_valid());
    CHECK("pav bad has errors", !vr.errors().empty());
  }

  // ValidationOptions forwarded
  {
    email::ValidationOptions vo;
    vo.reject_numeric_tld = false;
    auto [addr, vr] = email::parse_and_validate("user@example.123", vo);
    bool no_numeric = true;
    for (auto &e : vr.fatal_errors())
      if (e.code() == email::ErrorCode::DomainNumericTld)
        no_numeric = false;
    CHECK("pav vo forwarded", no_numeric);
  }

  // NormalizeOptions forwarded
  {
    email::NormalizeOptions no;
    no.remove_plus_tag = true;
    auto [addr, vr] = email::parse_and_validate("user+tag@example.com", {}, no);
    CHECK("pav no forwarded", vr.is_valid() && addr.local() == "user");
  }
}

// =============================================================================
//  12 – local_part() and domain_part()
// =============================================================================

static void test_extractor_functions()
{
  test::suite("local_part() and domain_part()");

  {
    auto lp = email::local_part("user+tag@example.com");
    CHECK("local_part present", lp.has_value());
    CHECK("local_part value", lp == "user+tag");
  }
  {
    auto dp = email::domain_part("user@Example.COM");
    CHECK("domain_part present", dp.has_value());
    CHECK("domain_part value", dp == "Example.COM"); // raw, not normalized
  }
  {
    auto lp = email::local_part("bad-email");
    CHECK("local_part bad nullopt", !lp.has_value());
  }
  {
    auto dp = email::domain_part("");
    CHECK("domain_part empty nullopt", !dp.has_value());
  }
}

// =============================================================================
//  13 – DNS validation hook
// =============================================================================

static void test_dns_hook()
{
  test::suite("DnsValidationHook");

  email::Address addr{"user", "example.com"};

  // No MX record → warning, still valid
  {
    NoMxHook hook;
    auto vr = email::validate(addr, {}, &hook, nullptr);
    CHECK("no mx still valid", vr.is_valid());
    CHECK("no mx warning", !vr.warnings().empty());
    bool has_dns = false;
    for (auto &w : vr.warnings())
      if (w.code() == email::ErrorCode::DnsValidationFailed)
        has_dns = true;
    CHECK("no mx code", has_dns);
  }

  // Has MX record → clean
  {
    HasMxHook hook;
    auto vr = email::validate(addr, {}, &hook, nullptr);
    CHECK("has mx valid", vr.is_valid());
    CHECK("has mx no warnings", vr.warnings().empty());
    CHECK("has mx empty", vr.empty());
  }

  // nullptr hook → no DNS check
  {
    auto vr = email::validate(addr, {}, nullptr, nullptr);
    CHECK("null hook no dns err", vr.is_valid());
    bool has_dns = false;
    for (auto &e : vr.errors())
      if (e.code() == email::ErrorCode::DnsValidationFailed)
        has_dns = true;
    CHECK("null hook no dns code", !has_dns);
  }
}

// =============================================================================
//  14 – Disposable email hook
// =============================================================================

static void test_disposable_hook()
{
  test::suite("DisposableEmailHook");

  email::Address addr{"user", "mailinator.com"};

  // Always disposable → warning, still valid
  {
    DisposableHook hook;
    auto vr = email::validate(addr, {}, nullptr, &hook);
    CHECK("disposable still valid", vr.is_valid());
    CHECK("disposable warning", !vr.warnings().empty());
    bool has_disp = false;
    for (auto &w : vr.warnings())
      if (w.code() == email::ErrorCode::DisposableEmailDetected)
        has_disp = true;
    CHECK("disposable code", has_disp);
  }

  // Not disposable → clean
  {
    NotDisposableHook hook;
    auto vr = email::validate(addr, {}, nullptr, &hook);
    CHECK("not disposable clean", vr.is_valid());
    bool has_disp = false;
    for (auto &w : vr.warnings())
      if (w.code() == email::ErrorCode::DisposableEmailDetected)
        has_disp = true;
    CHECK("not disposable no code", !has_disp);
  }

  // Both DNS and disposable hooks
  {
    NoMxHook dns;
    DisposableHook disp;
    auto vr = email::validate(addr, {}, &dns, &disp);
    CHECK("both hooks valid", vr.is_valid());
    CHECK("both hooks 2 warnings", vr.warnings().size() == 2);
  }
}

// =============================================================================
//  15 – IDN encoder hook (via normalize_address)
// =============================================================================

static void test_idn_hook()
{
  test::suite("IdnEncoderHook (via normalize)");

  // With encode_idn = false (default), high-byte labels pass through as-is
  {
    email::Address a{"user", "example.com"};
    email::NormalizeOptions o;
    o.encode_idn = false;
    auto n = email::normalize(a, o);
    CHECK("no idn encode unchanged", n.domain() == "example.com");
  }

  // With encode_idn = true but no hook, idn encoding skipped
  {
    email::Address a{"user", "example.com"};
    email::NormalizeOptions o;
    o.encode_idn = true;
    auto n = email::normalize(a, o, nullptr);
    CHECK("idn no hook unchanged", n.domain() == "example.com");
  }

  // With encode_idn = true and a hook, ASCII labels pass through unchanged
  {
    FakeIdnEncoder idn;
    email::Address a{"user", "example.com"};
    email::NormalizeOptions o;
    o.encode_idn = true;
    auto n = email::normalize(a, o, &idn);
    CHECK("idn ascii label unchanged", n.domain() == "example.com");
  }
}

// =============================================================================
//  16 – Edge cases and boundary conditions
// =============================================================================

static void test_edge_cases()
{
  test::suite("Edge cases and boundary conditions");

  // Exactly 64-char local part — boundary (valid)
  {
    std::string local(64, 'a');
    CHECK("64 char local valid", email::is_valid(local + "@example.com"));
  }
  // 65-char local part — over boundary (invalid)
  {
    std::string local(65, 'a');
    CHECK("65 char local invalid", !email::is_valid(local + "@example.com"));
  }

  // Exactly 63-char label — boundary (valid)
  {
    std::string label(63, 'a');
    CHECK("63 char label valid", email::is_valid("user@" + label + ".com"));
  }
  // 64-char label — over boundary (invalid)
  {
    std::string label(64, 'a');
    CHECK("64 char label invalid", !email::is_valid("user@" + label + ".com"));
  }

  // Single-char TLD — short warning, not fatal
  {
    auto vr = email::validate("user@example.c");
    bool has_short = false;
    for (auto &w : vr.warnings())
      if (w.code() == email::ErrorCode::DomainTldTooShort)
        has_short = true;
    CHECK("1-char TLD warning", has_short);
    CHECK("1-char TLD still valid", vr.is_valid());
  }

  // Two-char TLD — fine
  {
    CHECK("2-char TLD valid", email::is_valid("user@example.co"));
  }

  // Multiple subdomains
  {
    CHECK("deep subdomain valid", email::is_valid("user@a.b.c.d.example.com"));
  }

  // All valid local chars
  {
    CHECK("valid chars local", email::is_valid("a.b_c+d-e@example.com"));
  }

  // Hash/exclamation in local part (invalid per is_local_char)
  {
    CHECK("hash invalid", !email::is_valid("user#1@example.com"));
    CHECK("excl invalid", !email::is_valid("user!@example.com"));
  }

  // Address equality with same display names (== ignores display_name)
  {
    email::Address a1{"user", "example.com"};
    email::Address a2{"user", "example.com", "John"};
    CHECK("eq ignores display_name", a1 == a2);
  }

  // equivalent_to: length mismatch
  {
    email::Address a1{"user", "example.com"};
    email::Address a2{"user", "example.net"};
    CHECK("equiv diff domain", !a1.equivalent_to(a2));
  }

  // error_count includes both errors and warnings
  {
    email::ValidationResult vr;
    vr.add_error(email::Error{email::ErrorCode::EmptyInput, email::Severity::Error});
    vr.add_error(email::Error{email::ErrorCode::DomainTrailingDot, email::Severity::Warning});
    CHECK("error_count includes warn", vr.error_count() == 2);
  }

  // validate() on an already-valid address returns empty result
  {
    email::Address a{"user", "example.com"};
    auto vr = email::validate(a);
    CHECK("valid addr empty result", vr.empty());
    CHECK("valid addr is_valid", vr.is_valid());
  }

  // parse_and_validate on valid address gives non-empty address
  {
    auto [addr, vr] = email::parse_and_validate("user@example.com");
    CHECK("pav addr not empty", !addr.empty());
    CHECK("pav to_string", addr.to_string() == "user@example.com");
  }
}

// =============================================================================
//  main
// =============================================================================

int main()
{
  std::cout << "\n╔══════════════════════════════════════╗\n";
  std::cout << "║     email.hpp — test_basic.cpp       ║\n";
  std::cout << "╚══════════════════════════════════════╝\n";

  test_error_class();
  test_address_class();
  test_validation_result();
  test_parse_result();
  test_is_valid();
  test_parse();
  test_validate();
  test_validate_options();
  test_normalize();
  test_try_parse();
  test_parse_and_validate();
  test_extractor_functions();
  test_dns_hook();
  test_disposable_hook();
  test_idn_hook();
  test_edge_cases();

  test::summary();
  return test::failed > 0 ? 1 : 0;
}
