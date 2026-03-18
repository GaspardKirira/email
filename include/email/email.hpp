/**
 * @file email.hpp
 * @brief Production-grade, header-only C++20 email address parsing and validation library.
 *
 * @version 1.0.1
 * @author Email Library Contributors
 * @copyright MIT License
 *
 * @details
 * This library provides robust email address parsing, validation, and normalization
 * following RFC 5321/5322 standards with pragmatic extensions for real-world use.
 *
 * Features:
 * - State-machine based parser (not naive split)
 * - RFC 5322-inspired validation with practical rules
 * - Unicode/IDN domain support (punycode interface)
 * - Extensible hooks for DNS MX validation and disposable email detection
 * - Zero external dependencies
 * - Header-only C++20 implementation
 *
 * @example Basic Usage:
 * @code
 *
 * // Simple validation
 * bool valid = email::is_valid("user@example.com");
 *
 * // Parse with full result
 * auto result = email::parse("User@Example.COM");
 * if (result) {
 *     auto addr = result.address();
 *     // addr.local() == "User", addr.domain() == "Example.COM"
 * }
 *
 * // Normalize
 * auto norm = email::normalize("  User@Example.COM  ");
 * // norm == "User@example.com"
 *
 * // Validate with detailed errors
 * auto validation = email::validate(addr);
 * if (!validation.is_valid()) {
 *     for (auto& err : validation.errors()) {
 *         std::cerr << err.message() << "\n";
 *     }
 * }
 * @endcode
 */

#pragma once

#include <algorithm>
#include <cctype>
#include <concepts>
#include <cstdint>
#include <functional>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

namespace email
{
  class Address;
  class ParseResult;
  class ValidationResult;
  class Error;
  struct ParseOptions;
  struct NormalizeOptions;
  struct ValidationOptions;

  namespace detail
  {
    class Parser;
    class Validator;
    class Normalizer;
  } // namespace detail

  /**
   * @brief Error codes for email parsing and validation failures.
   *
   * Organized by category:
   * - General (1xx): structural issues
   * - Local part (2xx): issues with the part before '@'
   * - Domain (3xx): issues with the part after '@'
   * - Normalization (4xx): issues during normalization
   */
  enum class ErrorCode : uint32_t
  {
    // General structural errors
    None = 0,
    EmptyInput = 100,
    MissingAtSign = 101,
    MultipleAtSigns = 102,
    EmptyLocalPart = 103,
    EmptyDomain = 104,
    ExceedsMaxLength = 105,
    InvalidEncoding = 106,
    NullCharacter = 107,

    // Local part errors
    LocalPartTooLong = 200,
    LocalPartInvalidChar = 201,
    LocalPartLeadingDot = 202,
    LocalPartTrailingDot = 203,
    LocalPartConsecutiveDots = 204,
    LocalPartInvalidQuotedString = 205,
    LocalPartUnmatchedQuote = 206,

    // Domain errors
    DomainTooLong = 300,
    DomainLabelTooLong = 301,
    DomainInvalidChar = 302,
    DomainLeadingDot = 303,
    DomainTrailingDot = 304,
    DomainConsecutiveDots = 305,
    DomainMissingDot = 306,
    DomainLabelStartsWithHyphen = 307,
    DomainLabelEndsWithHyphen = 308,
    DomainNumericTld = 309,
    DomainIpLiteralInvalid = 310,
    DomainIpv6Invalid = 311,
    DomainTldTooShort = 312,

    // Normalization errors
    NormalizationFailed = 400,
    PunycodeEncodingFailed = 401,

    // Hook errors
    DnsValidationFailed = 500,
    DisposableEmailDetected = 501,
  };

  /**
   * @brief Returns a human-readable string for a given ErrorCode.
   * @param code The error code to describe.
   * @return A string_view with the error description.
   */
  [[nodiscard]] constexpr std::string_view error_code_to_string(ErrorCode code) noexcept
  {
    switch (code)
    {
    case ErrorCode::None:
      return "No error";
    case ErrorCode::EmptyInput:
      return "Input is empty";
    case ErrorCode::MissingAtSign:
      return "Missing '@' sign";
    case ErrorCode::MultipleAtSigns:
      return "Multiple '@' signs found";
    case ErrorCode::EmptyLocalPart:
      return "Local part is empty";
    case ErrorCode::EmptyDomain:
      return "Domain is empty";
    case ErrorCode::ExceedsMaxLength:
      return "Email address exceeds maximum length (320 chars)";
    case ErrorCode::InvalidEncoding:
      return "Invalid character encoding";
    case ErrorCode::NullCharacter:
      return "Null character found in input";
    case ErrorCode::LocalPartTooLong:
      return "Local part exceeds 64 characters";
    case ErrorCode::LocalPartInvalidChar:
      return "Local part contains invalid character";
    case ErrorCode::LocalPartLeadingDot:
      return "Local part begins with a dot";
    case ErrorCode::LocalPartTrailingDot:
      return "Local part ends with a dot";
    case ErrorCode::LocalPartConsecutiveDots:
      return "Local part contains consecutive dots";
    case ErrorCode::LocalPartInvalidQuotedString:
      return "Local part quoted string is malformed";
    case ErrorCode::LocalPartUnmatchedQuote:
      return "Local part has unmatched quote";
    case ErrorCode::DomainTooLong:
      return "Domain exceeds 255 characters";
    case ErrorCode::DomainLabelTooLong:
      return "Domain label exceeds 63 characters";
    case ErrorCode::DomainInvalidChar:
      return "Domain contains invalid character";
    case ErrorCode::DomainLeadingDot:
      return "Domain begins with a dot";
    case ErrorCode::DomainTrailingDot:
      return "Domain ends with a dot";
    case ErrorCode::DomainConsecutiveDots:
      return "Domain contains consecutive dots";
    case ErrorCode::DomainMissingDot:
      return "Domain must contain at least one dot";
    case ErrorCode::DomainLabelStartsWithHyphen:
      return "Domain label starts with a hyphen";
    case ErrorCode::DomainLabelEndsWithHyphen:
      return "Domain label ends with a hyphen";
    case ErrorCode::DomainNumericTld:
      return "Domain TLD is fully numeric";
    case ErrorCode::DomainIpLiteralInvalid:
      return "IP address literal is invalid";
    case ErrorCode::DomainIpv6Invalid:
      return "IPv6 address is invalid";
    case ErrorCode::DomainTldTooShort:
      return "TLD is too short (< 2 characters)";
    case ErrorCode::NormalizationFailed:
      return "Normalization failed";
    case ErrorCode::PunycodeEncodingFailed:
      return "Punycode encoding failed";
    case ErrorCode::DnsValidationFailed:
      return "DNS validation failed (no MX record found)";
    case ErrorCode::DisposableEmailDetected:
      return "Disposable email domain detected";
    default:
      return "Unknown error";
    }
  }

  /**
   * @brief Severity levels for errors and warnings.
   */
  enum class Severity
  {
    Info,    ///< Informational, not a blocking issue
    Warning, ///< Non-fatal issue, email may still be usable
    Error,   ///< Fatal issue, email is invalid
  };

  /**
   * @brief Structured error with code, severity, message, and optional position.
   */
  class Error
  {
  public:
    constexpr Error(ErrorCode code, Severity sev, std::string message,
                    std::optional<std::size_t> pos = std::nullopt)
        : code_(code), severity_(sev), message_(std::move(message)), position_(pos) {}

    constexpr Error(ErrorCode code, Severity sev, std::size_t pos)
        : code_(code),
          severity_(sev),
          message_(error_code_to_string(code)),
          position_(pos) {}

    constexpr explicit Error(ErrorCode code, Severity sev = Severity::Error,
                             std::optional<std::size_t> pos = std::nullopt)
        : code_(code),
          severity_(sev),
          message_(error_code_to_string(code)),
          position_(pos) {}

    [[nodiscard]] constexpr ErrorCode code() const noexcept { return code_; }
    [[nodiscard]] constexpr Severity severity() const noexcept { return severity_; }
    [[nodiscard]] const std::string &message() const noexcept { return message_; }
    [[nodiscard]] constexpr std::optional<std::size_t> position() const noexcept { return position_; }
    [[nodiscard]] constexpr bool is_error() const noexcept { return severity_ == Severity::Error; }
    [[nodiscard]] constexpr bool is_warning() const noexcept { return severity_ == Severity::Warning; }

  private:
    ErrorCode code_;
    Severity severity_;
    std::string message_;
    std::optional<std::size_t> position_;
  };

  /**
   * @brief Represents a parsed and validated email address.
   */
  class Address
  {
  public:
    Address() = default;

    Address(std::string local, std::string domain)
        : local_(std::move(local)), domain_(std::move(domain)) {}

    Address(std::string local, std::string domain, std::string display_name)
        : local_(std::move(local)),
          domain_(std::move(domain)),
          display_name_(std::move(display_name)) {}

    [[nodiscard]] const std::string &local() const noexcept { return local_; }
    [[nodiscard]] const std::string &domain() const noexcept { return domain_; }
    [[nodiscard]] const std::optional<std::string> &display_name() const noexcept { return display_name_; }

    [[nodiscard]] std::string to_string() const
    {
      if (local_.empty() && domain_.empty())
        return {};
      return local_ + "@" + domain_;
    }

    [[nodiscard]] bool empty() const noexcept { return local_.empty() && domain_.empty(); }

    [[nodiscard]] bool operator==(const Address &other) const noexcept
    {
      return local_ == other.local_ && domain_ == other.domain_;
    }

    [[nodiscard]] bool operator!=(const Address &other) const noexcept
    {
      return !(*this == other);
    }

    [[nodiscard]] bool equivalent_to(const Address &other) const noexcept
    {
      if (local_ != other.local_)
        return false;
      if (domain_.size() != other.domain_.size())
        return false;
      for (std::size_t i = 0; i < domain_.size(); ++i)
      {
        if (std::tolower(static_cast<unsigned char>(domain_[i])) !=
            std::tolower(static_cast<unsigned char>(other.domain_[i])))
          return false;
      }
      return true;
    }

  private:
    std::string local_;
    std::string domain_;
    std::optional<std::string> display_name_;
  };

  /**
   * @brief Options for controlling the normalization process.
   */
  struct NormalizeOptions
  {
    bool trim_whitespace = true;
    bool lowercase_domain = true;
    bool lowercase_local = false;
    bool encode_idn = false;
    bool remove_plus_tag = false;
    bool remove_dots_from_local = false;
  };

  /**
   * @brief Options for controlling the validation process.
   */
  struct ValidationOptions
  {
    bool allow_ip_domain = false;
    bool allow_quoted_local = false;
    bool allow_international_domain = false;
    bool allow_international_local = false;
    bool require_tld = true;
    bool reject_numeric_tld = true;
    std::size_t max_email_length = 320;
    std::size_t max_local_length = 64;
    std::size_t max_domain_length = 255;
    std::size_t max_label_length = 63;
  };

  /**
   * @brief Combined options for parsing.
   */
  struct ParseOptions
  {
    NormalizeOptions normalize;
    ValidationOptions validation;
    bool collect_all_errors = true;
  };

  /**
   * @brief Interface for DNS MX record validation hook.
   */
  struct DnsValidationHook
  {
    virtual ~DnsValidationHook() = default;
    [[nodiscard]] virtual bool has_mx_record(std::string_view domain) const = 0;
  };

  /**
   * @brief Interface for disposable email detection hook.
   */
  struct DisposableEmailHook
  {
    virtual ~DisposableEmailHook() = default;
    [[nodiscard]] virtual bool is_disposable(std::string_view domain) const = 0;
  };

  /**
   * @brief Interface for IDN (Internationalized Domain Name) punycode encoding.
   */
  struct IdnEncoderHook
  {
    virtual ~IdnEncoderHook() = default;
    [[nodiscard]] virtual std::optional<std::string> encode(std::string_view label) const = 0;
  };

  /**
   * @brief Result of a validation operation.
   */
  class ValidationResult
  {
  public:
    ValidationResult() = default;

    void add_error(Error error) { errors_.push_back(std::move(error)); }

    [[nodiscard]] bool is_valid() const noexcept
    {
      return std::ranges::none_of(errors_, [](const Error &e)
                                  { return e.is_error(); });
    }

    [[nodiscard]] explicit operator bool() const noexcept { return is_valid(); }

    [[nodiscard]] const std::vector<Error> &errors() const noexcept { return errors_; }

    [[nodiscard]] std::vector<Error> fatal_errors() const
    {
      std::vector<Error> result;
      std::ranges::copy_if(errors_, std::back_inserter(result),
                           [](const Error &e)
                           { return e.is_error(); });
      return result;
    }

    [[nodiscard]] std::vector<Error> warnings() const
    {
      std::vector<Error> result;
      std::ranges::copy_if(errors_, std::back_inserter(result),
                           [](const Error &e)
                           { return e.is_warning(); });
      return result;
    }

    [[nodiscard]] std::size_t error_count() const noexcept { return errors_.size(); }
    [[nodiscard]] bool empty() const noexcept { return errors_.empty(); }

    void merge(const ValidationResult &other)
    {
      errors_.insert(errors_.end(), other.errors_.begin(), other.errors_.end());
    }

  private:
    std::vector<Error> errors_;
  };

  /**
   * @brief Result of a parse operation.
   */
  class ParseResult
  {
  public:
    explicit ParseResult(Address address)
        : address_(std::move(address)), success_(true) {}

    explicit ParseResult(std::vector<Error> errors)
        : errors_(std::move(errors)), success_(false) {}

    explicit ParseResult(Error error) : success_(false)
    {
      errors_.push_back(std::move(error));
    }

    [[nodiscard]] bool success() const noexcept { return success_; }
    [[nodiscard]] explicit operator bool() const noexcept { return success_; }

    [[nodiscard]] const Address &address() const
    {
      if (!success_)
        throw std::logic_error("ParseResult: no address (parse failed)");
      return *address_;
    }

    [[nodiscard]] Address address_or(Address fallback = {}) const noexcept
    {
      if (!success_)
        return fallback;
      return *address_;
    }

    [[nodiscard]] const std::vector<Error> &errors() const noexcept { return errors_; }

    [[nodiscard]] std::optional<Error> first_error() const noexcept
    {
      if (errors_.empty())
        return std::nullopt;
      return errors_.front();
    }

  private:
    std::optional<Address> address_;
    std::vector<Error> errors_;
    bool success_;
  };

  namespace detail
  {
    struct Chars
    {
      [[nodiscard]] static constexpr bool is_local_char(char c) noexcept
      {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') ||
               c == '.' || c == '_' || c == '+' || c == '-';
      }

      [[nodiscard]] static constexpr bool is_domain_char(char c) noexcept
      {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '-';
      }

      [[nodiscard]] static constexpr bool is_alnum(char c) noexcept
      {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
      }

      [[nodiscard]] static constexpr bool is_digit(char c) noexcept
      {
        return c >= '0' && c <= '9';
      }

      [[nodiscard]] static constexpr bool is_ascii(char c) noexcept
      {
        return static_cast<unsigned char>(c) < 128;
      }

      [[nodiscard]] static constexpr bool is_high_byte(char c) noexcept
      {
        return static_cast<unsigned char>(c) >= 128;
      }

      [[nodiscard]] static constexpr bool is_quoted_char(char c) noexcept
      {
        auto uc = static_cast<unsigned char>(c);
        return uc >= 32 && uc <= 126 && c != '"' && c != '\\';
      }

      [[nodiscard]] static bool is_ascii_string(std::string_view sv) noexcept
      {
        return std::ranges::all_of(sv, [](char c)
                                   { return is_ascii(c); });
      }

      [[nodiscard]] static constexpr bool is_whitespace(char c) noexcept
      {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
      }

      [[nodiscard]] static constexpr char to_lower(char c) noexcept
      {
        if (c >= 'A' && c <= 'Z')
          return static_cast<char>(c + ('a' - 'A'));
        return c;
      }
    };

    struct StringUtil
    {
      [[nodiscard]] static std::string_view trim(std::string_view sv) noexcept
      {
        while (!sv.empty() && Chars::is_whitespace(sv.front()))
          sv.remove_prefix(1);
        while (!sv.empty() && Chars::is_whitespace(sv.back()))
          sv.remove_suffix(1);
        return sv;
      }

      [[nodiscard]] static std::string to_lower(std::string_view sv)
      {
        std::string result;
        result.reserve(sv.size());
        std::ranges::transform(sv, std::back_inserter(result),
                               [](char c)
                               { return Chars::to_lower(c); });
        return result;
      }

      [[nodiscard]] static bool is_all_digits(std::string_view sv) noexcept
      {
        return !sv.empty() && std::ranges::all_of(sv, Chars::is_digit);
      }

      [[nodiscard]] static std::size_t count_char(std::string_view sv, char c) noexcept
      {
        return static_cast<std::size_t>(std::ranges::count(sv, c));
      }

      [[nodiscard]] static std::vector<std::string_view> split(std::string_view sv, char delim)
      {
        std::vector<std::string_view> parts;
        std::size_t start = 0;
        for (std::size_t i = 0; i <= sv.size(); ++i)
        {
          if (i == sv.size() || sv[i] == delim)
          {
            parts.push_back(sv.substr(start, i - start));
            start = i + 1;
          }
        }
        return parts;
      }
    };

    struct IpUtil
    {
      [[nodiscard]] static bool is_valid_ipv4(std::string_view sv) noexcept
      {
        int parts = 0;
        int value = 0;
        int digit_count = 0;

        for (std::size_t i = 0; i <= sv.size(); ++i)
        {
          char c = (i < sv.size()) ? sv[i] : '.';
          if (c == '.')
          {
            if (digit_count == 0 || digit_count > 3)
              return false;
            if (value > 255)
              return false;
            ++parts;
            value = 0;
            digit_count = 0;
          }
          else if (Chars::is_digit(c))
          {
            if (digit_count == 1 && value == 0)
              return false; // leading zero
            value = value * 10 + (c - '0');
            ++digit_count;
          }
          else
          {
            return false;
          }
        }
        return parts == 4;
      }

      [[nodiscard]] static bool is_valid_ipv6(std::string_view sv) noexcept
      {
        if (sv.empty())
          return false;

        // Strip optional "IPv6:" prefix
        if (sv.size() > 5 &&
            (sv.substr(0, 6) == "IPv6: " || sv.substr(0, 5) == "IPv6:"))
        {
          sv.remove_prefix(sv.find(':') + 1);
        }

        int groups = 0;
        int compressed = -1;
        std::size_t i = 0;

        while (i <= sv.size())
        {
          if (i == sv.size())
          {
            ++groups;
            break;
          }

          if (sv[i] == ':')
          {
            if (i + 1 < sv.size() && sv[i + 1] == ':')
            {
              if (compressed != -1)
                return false;
              compressed = groups;
              ++groups;
              i += 2;
            }
            else
            {
              ++groups;
              ++i;
            }
          }
          else
          {
            int hex_count = 0;
            while (i < sv.size() && sv[i] != ':')
            {
              char c = sv[i];
              if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F')))
                return false;
              ++hex_count;
              ++i;
            }
            if (hex_count == 0 || hex_count > 4)
              return false;
          }
        }

        return (compressed != -1) ? (groups <= 8) : (groups == 8);
      }

      [[nodiscard]] static bool is_valid_ip_literal(std::string_view sv) noexcept
      {
        if (sv.size() < 3)
          return false;
        if (sv.front() != '[' ||
            sv.back() != ']')
          return false;

        auto inner = sv.substr(1, sv.size() - 2);
        if (inner.empty())
          return false;

        // IPv6 literal: [IPv6:...]
        if (inner.size() >= 5)
        {
          std::string lower_prefix{inner.substr(0, 5)};
          std::ranges::transform(lower_prefix, lower_prefix.begin(),
                                 [](unsigned char c)
                                 { return std::tolower(c); });
          if (lower_prefix == "ipv6:")
            return is_valid_ipv6(inner.substr(5));
        }

        return is_valid_ipv4(inner);
      }
    };

    class Parser
    {
    public:
      [[nodiscard]] static ParseResult parse(std::string_view input,
                                             const ParseOptions &options = {})
      {
        std::vector<Error> errors;

        // Null-byte check
        if (input.find('\0') != std::string_view::npos)
        {
          errors.emplace_back(ErrorCode::NullCharacter, Severity::Error);
          return ParseResult{std::move(errors)};
        }

        // Trim
        std::string_view trimmed =
            options.normalize.trim_whitespace ? StringUtil::trim(input) : input;

        if (trimmed.empty())
        {
          errors.emplace_back(ErrorCode::EmptyInput, Severity::Error);
          return ParseResult{std::move(errors)};
        }

        // Total length guard
        if (trimmed.size() > options.validation.max_email_length)
        {
          errors.emplace_back(ErrorCode::ExceedsMaxLength, Severity::Error);
          return ParseResult{std::move(errors)};
        }

        // Angle-addr / display-name extraction
        std::string_view work = trimmed;
        std::string display_name;

        if (trimmed.back() == '>' && trimmed.find('<') != std::string_view::npos)
        {
          auto open = trimmed.rfind('<');
          if (open != std::string_view::npos)
          {
            display_name = std::string(StringUtil::trim(trimmed.substr(0, open)));
            work = trimmed.substr(open + 1, trimmed.size() - open - 2);
          }
          else
          {
            errors.emplace_back(ErrorCode::MissingAtSign, Severity::Error, std::size_t{0});
            return ParseResult{std::move(errors)};
          }
        }

        // Find the '@' sign
        auto at_pos = find_at_sign(work);
        if (!at_pos.has_value())
        {
          auto at_count = StringUtil::count_char(work, '@');
          errors.emplace_back(at_count == 0 ? ErrorCode::MissingAtSign
                                            : ErrorCode::MultipleAtSigns,
                              Severity::Error);
          return ParseResult{std::move(errors)};
        }

        std::string_view local_sv = work.substr(0, *at_pos);
        std::string_view domain_sv = work.substr(*at_pos + 1);

        if (local_sv.empty())
          errors.emplace_back(ErrorCode::EmptyLocalPart, Severity::Error);
        if (domain_sv.empty())
          errors.emplace_back(ErrorCode::EmptyDomain, Severity::Error);

        if (!errors.empty())
          return ParseResult{std::move(errors)};

        std::string local{local_sv};
        std::string domain{domain_sv};

        Address addr = display_name.empty()
                           ? Address{std::move(local), std::move(domain)}
                           : Address{std::move(local), std::move(domain),
                                     std::move(display_name)};
        return ParseResult{std::move(addr)};
      }

    private:
      // Returns the position of the single unquoted '@', or nullopt if 0 or 2+.
      [[nodiscard]] static std::optional<std::size_t> find_at_sign(
          std::string_view sv) noexcept
      {
        bool in_quotes = false;
        std::size_t at_pos = std::string_view::npos;
        std::size_t at_count = 0;

        for (std::size_t i = 0; i < sv.size(); ++i)
        {
          char c = sv[i];
          if (c == '\\' && in_quotes && i + 1 < sv.size())
          {
            ++i;
            continue;
          }
          if (c == '"')
          {
            in_quotes = !in_quotes;
            continue;
          }
          if (!in_quotes && c == '@')
          {
            ++at_count;
            at_pos = i;
          }
        }

        return (at_count == 1) ? std::make_optional(at_pos) : std::nullopt;
      }
    };

    class Validator
    {
    public:
      /**
       * @brief Validates an Address.
       *
       * @param addr        The address to validate.
       * @param options     Validation options (max lengths, flags, etc.).   ← FIX: added
       * @param dns         Optional DNS hook for MX record checking.
       * @param disposable  Optional hook for disposable email detection.
       * @return ValidationResult with all found errors.
       */
      [[nodiscard]] static ValidationResult validate(
          const Address &addr,
          const ValidationOptions &options = {}, // ← FIX: was missing
          const DnsValidationHook *dns = nullptr,
          const DisposableEmailHook *disposable = nullptr)
      {
        ValidationResult result;

        validate_local(addr.local(), options, result);
        if (!result.is_valid())
          return result;

        validate_domain(addr.domain(), options, result); // ← FIX: options threaded

        if (result.is_valid())
        {
          if (dns && !dns->has_mx_record(addr.domain()))
          {
            result.add_error(Error{ErrorCode::DnsValidationFailed, Severity::Warning});
          }
          if (disposable && disposable->is_disposable(addr.domain()))
          {
            result.add_error(Error{ErrorCode::DisposableEmailDetected, Severity::Warning});
          }
        }

        return result;
      }

    private:
      static void validate_local(std::string_view local,
                                 const ValidationOptions &options,
                                 ValidationResult &result)
      {
        if (local.empty())
        {
          result.add_error(Error{ErrorCode::EmptyLocalPart, Severity::Error});
          return;
        }

        if (local.size() > options.max_local_length)
          result.add_error(Error{ErrorCode::LocalPartTooLong, Severity::Error});

        if (local.front() == '.')
          result.add_error(Error{ErrorCode::LocalPartLeadingDot, Severity::Error, std::size_t{0}});

        if (local.back() == '.')
          result.add_error(Error{ErrorCode::LocalPartTrailingDot, Severity::Error, local.size() - 1});

        char prev = '\0';
        for (std::size_t i = 0; i < local.size(); ++i)
        {
          char c = local[i];

          if (!Chars::is_ascii(c))
          {
            if (!options.allow_international_local)
              result.add_error(Error{ErrorCode::LocalPartInvalidChar, Severity::Error,
                                     "Non-ASCII not allowed", i});
            prev = c;
            continue;
          }

          if (!Chars::is_local_char(c))
            result.add_error(Error{ErrorCode::LocalPartInvalidChar, Severity::Error,
                                   "Invalid character", i});

          if (c == '.' && prev == '.')
            result.add_error(Error{ErrorCode::LocalPartConsecutiveDots, Severity::Error, i});

          prev = c;
        }
      }

      static void validate_quoted_local(const std::string &local,
                                        ValidationResult &result)
      {
        if (local.size() < 2 || local.back() != '"')
        {
          result.add_error(Error{ErrorCode::LocalPartUnmatchedQuote, Severity::Error});
          return;
        }

        for (std::size_t i = 1; i < local.size() - 1; ++i)
        {
          char c = local[i];
          if (c == '\\')
          {
            if (i + 1 >= local.size() - 1)
            {
              result.add_error(Error{ErrorCode::LocalPartInvalidQuotedString,
                                     Severity::Error,
                                     "Trailing backslash in quoted string", i});
              return;
            }
            ++i;
          }
          else if (!Chars::is_quoted_char(c) && !Chars::is_high_byte(c))
          {
            result.add_error(Error{ErrorCode::LocalPartInvalidQuotedString,
                                   Severity::Error,
                                   std::string("Invalid character in quoted string: '") +
                                       c + "'",
                                   i});
          }
        }
      }

      static void validate_domain(const std::string &domain,
                                  const ValidationOptions &options,
                                  ValidationResult &result)
      {
        if (domain.empty())
        {
          result.add_error(Error{ErrorCode::EmptyDomain, Severity::Error});
          return;
        }

        // IP address literal domain
        if (domain.front() == '[')
        {
          if (!options.allow_ip_domain)
          {
            result.add_error(Error{ErrorCode::DomainInvalidChar, Severity::Error,
                                   "IP address literals not allowed in domain"});
            return;
          }
          if (!IpUtil::is_valid_ip_literal(domain))
            result.add_error(Error{ErrorCode::DomainIpLiteralInvalid, Severity::Error});
          return;
        }

        // Total length
        if (domain.size() > options.max_domain_length)
          result.add_error(Error{ErrorCode::DomainTooLong, Severity::Error});

        // Leading dot
        if (domain.front() == '.')
          result.add_error(Error{ErrorCode::DomainLeadingDot, Severity::Error, std::size_t{0}});

        // Trailing dot — valid as FQDN, treated as warning
        if (domain.back() == '.')
          result.add_error(Error{ErrorCode::DomainTrailingDot, Severity::Warning,
                                 domain.size() - 1});

        // At least one dot required
        auto dot_count = StringUtil::count_char(domain, '.');
        if (dot_count == 0)
          result.add_error(Error{ErrorCode::DomainMissingDot, Severity::Error});

        // Validate labels
        std::size_t label_start = 0;
        for (std::size_t i = 0; i <= domain.size(); ++i)
        {
          if (i == domain.size() || domain[i] == '.')
          {
            if (i > 0 && i < domain.size() &&
                domain[i - 1] == '.' && domain[i] == '.')
            {
              result.add_error(
                  Error{ErrorCode::DomainConsecutiveDots, Severity::Error, i});
            }

            std::string_view label =
                std::string_view(domain).substr(label_start, i - label_start);
            if (!label.empty())
              validate_domain_label(label, options, result, label_start);

            label_start = i + 1;
          }
        }

        // Validate TLD
        if (dot_count > 0 && options.require_tld)
        {
          auto last_dot = domain.rfind('.');
          std::string_view tld = std::string_view(domain).substr(last_dot + 1);
          while (!tld.empty() && tld.back() == '.')
            tld.remove_suffix(1);

          if (tld.size() < 2)
            result.add_error(Error{ErrorCode::DomainTldTooShort, Severity::Warning,
                                   "TLD too short (< 2 characters)"});

          if (options.reject_numeric_tld && StringUtil::is_all_digits(tld))
            result.add_error(Error{ErrorCode::DomainNumericTld, Severity::Error});
        }
      }

      static void validate_domain_label(
          std::string_view label,
          const ValidationOptions &options,
          ValidationResult &result,
          std::size_t label_start)
      {
        if (label.empty())
          return;

        if (label.size() > options.max_label_length)
          result.add_error(
              Error{ErrorCode::DomainLabelTooLong, Severity::Error, label_start});

        if (label.front() == '-')
          result.add_error(Error{ErrorCode::DomainLabelStartsWithHyphen,
                                 Severity::Error, label_start});

        if (label.back() == '-')
          result.add_error(Error{ErrorCode::DomainLabelEndsWithHyphen,
                                 Severity::Error, label_start + label.size() - 1});

        for (std::size_t i = 0; i < label.size(); ++i)
        {
          char c = label[i];
          if (Chars::is_high_byte(c))
          {
            if (!options.allow_international_domain)
              result.add_error(Error{ErrorCode::DomainInvalidChar, Severity::Error,
                                     "Non-ASCII character in domain label",
                                     label_start + i});
            continue;
          }
          if (!Chars::is_domain_char(c))
            result.add_error(Error{ErrorCode::DomainInvalidChar, Severity::Error,
                                   std::string("Invalid character '") + c +
                                       "' in domain label",
                                   label_start + i});
        }
      }
    };

    class Normalizer
    {
    public:
      [[nodiscard]] static std::optional<std::string> normalize(
          std::string_view input,
          const NormalizeOptions &options = {},
          const IdnEncoderHook *idn = nullptr)
      {
        (void)idn; // hook reserved for future punycode use
        input = StringUtil::trim(input);
        if (input.empty())
          return std::nullopt;
        if (StringUtil::count_char(input, '@') != 1)
          return std::nullopt;

        auto at_pos = input.find('@');
        std::string local{input.substr(0, at_pos)};
        std::string domain{input.substr(at_pos + 1)};

        if (options.lowercase_domain)
        {
          std::ranges::transform(domain, domain.begin(),
                                 [](unsigned char c)
                                 { return std::tolower(c); });
        }

        return local + "@" + domain;
      }

      [[nodiscard]] static Address normalize_address(
          const Address &addr,
          const NormalizeOptions &options = {},
          const IdnEncoderHook *idn = nullptr)
      {
        std::string local = addr.local();
        std::string domain = addr.domain();

        if (options.lowercase_local)
        {
          std::ranges::transform(local, local.begin(),
                                 [](unsigned char c)
                                 { return std::tolower(c); });
        }

        if (options.remove_plus_tag)
        {
          auto plus = local.find('+');
          if (plus != std::string::npos)
            local = local.substr(0, plus);
        }

        if (options.remove_dots_from_local)
          local.erase(std::remove(local.begin(), local.end(), '.'), local.end());

        if (options.lowercase_domain)
        {
          std::ranges::transform(domain, domain.begin(),
                                 [](unsigned char c)
                                 { return std::tolower(c); });
        }

        if (options.encode_idn && idn)
        {
          auto encoded = encode_idn_domain(domain, *idn);
          if (encoded)
            domain = std::move(*encoded);
        }

        if (addr.display_name())
          return Address{std::move(local), std::move(domain), *addr.display_name()};
        return Address{std::move(local), std::move(domain)};
      }

    private:
      [[nodiscard]] static std::optional<std::string> encode_idn_domain(
          const std::string &domain,
          const IdnEncoderHook &idn)
      {
        auto labels = StringUtil::split(domain, '.');
        std::string result;
        result.reserve(domain.size());

        for (std::size_t i = 0; i < labels.size(); ++i)
        {
          if (i > 0)
            result += '.';
          auto label = labels[i];

          bool needs_encoding =
              std::ranges::any_of(label, Chars::is_high_byte);
          if (needs_encoding)
          {
            auto encoded = idn.encode(label);
            if (!encoded)
              return std::nullopt;
            result += *encoded;
          }
          else
          {
            result += std::string(label);
          }
        }
        return result;
      }
    };

  } // namespace detail

  /**
   * @brief Parses an email address string into a ParseResult.
   */
  [[nodiscard]] inline ParseResult parse(std::string_view input,
                                         const ParseOptions &options = {})
  {
    return detail::Parser::parse(input, options);
  }

  /**
   * @brief Validates an Address object against RFC 5322 rules.
   */
  [[nodiscard]] inline ValidationResult validate(
      const Address &addr,
      const ValidationOptions &options = {},
      const DnsValidationHook *dns = nullptr,
      const DisposableEmailHook *disposable = nullptr)
  {
    // FIX: threads options through to Validator::validate()
    return detail::Validator::validate(addr, options, dns, disposable);
  }

  /**
   * @brief Validates a raw email string.
   */
  [[nodiscard]] inline ValidationResult validate(std::string_view input,
                                                 const ValidationOptions &options = {})
  {
    ParseOptions po;
    po.validation = options;
    auto parse_result = detail::Parser::parse(input, po);
    if (!parse_result)
    {
      ValidationResult vr;
      for (auto &e : parse_result.errors())
        vr.add_error(e);
      return vr;
    }
    // FIX: passes options as second arg (was passing it where DnsValidationHook* expected)
    return detail::Validator::validate(parse_result.address(), options);
  }

  /**
   * @brief Quickly checks if an email address string is valid.
   */
  [[nodiscard]] inline bool is_valid(std::string_view input,
                                     const ValidationOptions &options = {})
  {
    return static_cast<bool>(validate(input, options));
  }

  /**
   * @brief Normalizes an email address string.
   */
  [[nodiscard]] inline std::optional<std::string> normalize(
      std::string_view input,
      const NormalizeOptions &options = {},
      const IdnEncoderHook *idn = nullptr)
  {
    return detail::Normalizer::normalize(input, options, idn);
  }

  /**
   * @brief Normalizes an Address object.
   */
  [[nodiscard]] inline Address normalize(const Address &addr,
                                         const NormalizeOptions &options = {},
                                         const IdnEncoderHook *idn = nullptr)
  {
    return detail::Normalizer::normalize_address(addr, options, idn);
  }

  /**
   * @brief Attempts to parse an email address, returning std::nullopt on failure.
   */
  [[nodiscard]] inline std::optional<Address> try_parse(std::string_view input,
                                                        const ParseOptions &options = {})
  {
    auto result = detail::Parser::parse(input, options);
    if (!result)
      return std::nullopt;
    return result.address();
  }

  /**
   * @brief Parses, validates, and normalizes an email address in one step.
   */
  [[nodiscard]] inline std::pair<Address, ValidationResult> parse_and_validate(
      std::string_view input,
      const ValidationOptions &vo = {},
      const NormalizeOptions &no = {},
      const DnsValidationHook *dns = nullptr,
      const DisposableEmailHook *disposable = nullptr)
  {
    ParseOptions po;
    po.validation = vo;
    po.normalize = no;

    auto parse_result = detail::Parser::parse(input, po);
    if (!parse_result)
    {
      ValidationResult vr;
      for (auto &e : parse_result.errors())
        vr.add_error(e);
      return {Address{}, vr};
    }

    auto normalized = detail::Normalizer::normalize_address(parse_result.address(), no);
    // FIX: vo is threaded correctly as second arg
    auto validation = detail::Validator::validate(normalized, vo, dns, disposable);

    return {std::move(normalized), std::move(validation)};
  }

  /**
   * @brief Extracts the local part from a raw email string.
   */
  [[nodiscard]] inline std::optional<std::string> local_part(std::string_view input)
  {
    auto addr = try_parse(input);
    if (!addr)
      return std::nullopt;
    return addr->local();
  }

  /**
   * @brief Extracts the domain part from a raw email string.
   */
  [[nodiscard]] inline std::optional<std::string> domain_part(std::string_view input)
  {
    auto addr = try_parse(input);
    if (!addr)
      return std::nullopt;
    return addr->domain();
  }

} // namespace email
