# email

> Email address parsing, validation and normalization for C++.

**email** is a complete, header-only email parsing and validation library written in modern C++20.
It implements RFC 5321 / 5322-inspired rules with practical extensions for real-world usage —
no regex hacks, no external dependencies.

---

## Download

```
https://vixcpp.com/registry/pkg/gk/email
```

---

## Why email?

Validating email addresses correctly is harder than it looks.

Most implementations:

- rely on fragile regexes
- reject valid addresses
- accept invalid ones
- ignore real-world edge cases

**email** solves this by using a state-machine parser + structured validation,
giving you correctness, clarity, and extensibility.

**Common use cases:**

- Authentication systems
- Signup forms and user onboarding
- CRM / contact management
- Email delivery pipelines
- Fraud detection and filtering
- Backend validation APIs
- Embedded systems (no dependencies)

**Example:**

```cpp
auto result = gk::email::parse("User@Example.COM");

if (result) {
    auto addr = result.address();
    std::cout << addr.to_string(); // User@Example.COM
}
```

---

## Features

- RFC 5321 / 5322-inspired parsing (state-machine, not regex)
- Robust validation with structured errors
- Local part + domain validation
- Unicode / IDN ready (punycode hook interface)
- Email normalization (trim, lowercase domain, etc.)
- Display name parsing (`"John Doe <user@example.com>"`)
- IP domain support (`[127.0.0.1]`, IPv6)
- Extensible validation hooks:
  - DNS MX record validation
  - Disposable email detection
- Detailed error reporting with positions
- Header-only implementation
- Zero dependencies
- Requires C++20

---

## Installation

### Using Vix Registry

```sh
vix add @gk/email
vix deps
```

### Manual

```sh
git clone https://github.com/Gaspardkirira/email.git
```

Add the `include/` directory to your project.

### Dependency

- Requires **C++20**
- No external libraries required

---

## Quick examples

### Basic validation

```cpp
#include <gk/email/email.hpp>

int main()
{
    if (gk::email::is_valid("user@example.com"))
        std::cout << "Valid\n";
}
```

### Parse an email

```cpp
#include <gk/email/email.hpp>

int main()
{
    auto result = gk::email::parse("User@Example.COM");

    if (result)
    {
        auto addr = result.address();
        std::cout << addr.local() << "\n";   // User
        std::cout << addr.domain() << "\n";  // Example.COM
    }
}
```

### Normalize

```cpp
#include <gk/email/email.hpp>

int main()
{
    auto norm = gk::email::normalize("  User@Example.COM  ");
    std::cout << *norm << "\n"; // User@example.com
}
```

### Validation with errors

```cpp
#include <gk/email/email.hpp>

int main()
{
    auto result = gk::email::validate("bad..email@-example..com");

    for (auto& err : result.errors())
    {
        std::cout << err.message() << "\n";
    }
}
```

### Parse + validate + normalize

```cpp
#include <gk/email/email.hpp>

int main()
{
    auto [addr, validation] =
        gk::email::parse_and_validate("User@Example.COM");

    if (validation)
        std::cout << addr.to_string() << "\n";
}
```

### Extract parts

```cpp
auto local  = gk::email::local_part("user@example.com");
auto domain = gk::email::domain_part("user@example.com");
```

### Display name support

```cpp
auto result = gk::email::parse("John Doe <user@example.com>");

if (result)
{
    auto addr = result.address();
    std::cout << *addr.display_name(); // John Doe
}
```

### Custom validation hooks

```cpp
struct MyDns : gk::email::DnsValidationHook
{
    bool has_mx_record(std::string_view domain) const override
    {
        return domain == "example.com";
    }
};

MyDns dns;

auto result = gk::email::validate("user@example.com", {}, &dns);
```

---

## API overview

### Free functions

```cpp
using namespace gk;

email::parse(input)                      // → ParseResult
email::try_parse(input)                  // → std::optional<Address>
email::validate(input)                   // → ValidationResult
email::validate(Address)                 // → ValidationResult
email::is_valid(input)                   // → bool
email::normalize(input)                  // → optional<string>
email::normalize(Address)                // → Address
email::parse_and_validate(input)         // → pair<Address, ValidationResult>
email::local_part(input)                 // → optional<string>
email::domain_part(input)                // → optional<string>
```

### Address

```cpp
addr.local()
addr.domain()
addr.display_name()
addr.to_string()
addr.empty()
addr == other
addr.equivalent_to(other)   // case-insensitive domain comparison
```

### ValidationResult

```cpp
result.is_valid()
result.errors()
result.error_count()
result.warnings()
result.fatal_errors()
```

### ParseResult

```cpp
result.success()
result.address()
result.errors()
result.first_error()
```

---

## Options

### NormalizeOptions

```cpp
NormalizeOptions opts;
opts.trim_whitespace        = true;
opts.lowercase_domain       = true;
opts.lowercase_local        = false;
opts.remove_plus_tag        = false;
opts.remove_dots_from_local = false;
opts.encode_idn             = false;
```

### ValidationOptions

```cpp
ValidationOptions opts;
opts.allow_ip_domain            = false;
opts.allow_quoted_local         = false;
opts.allow_international_domain = false;
opts.require_tld                = true;
opts.reject_numeric_tld         = true;
```

---

## Typical workflow

```
input string
    → parse          (state-machine)
    → structural validation
    → normalization
    → domain validation
    → optional hooks (DNS / disposable)
    → final result
```

---

## Design principles

- No regex-based parsing
- Deterministic behavior
- Explicit error reporting
- Extensible architecture (hooks)
- Header-only simplicity
- Modern C++20
- Zero dependencies

---

## Limitations

This library focuses on email **parsing and validation** only.

It does **not** include:

- SMTP verification
- Email sending
- Full RFC edge-case coverage (by design — pragmatic subset)
- Built-in DNS resolver (provided via hooks)

---

## Tests

```sh
vix build
vix test
```

Tests cover:

- Parsing correctness
- Validation rules
- Normalization
- Edge cases
- Error reporting
- Hook integration

---

## License

MIT License — Copyright © Gaspard Kirira
