# Changelog

## vNext

- Migrate to .net8 [#4](https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/4)
- Upgrade nunit tests to the latest version
- [SPF] Check if the domain has just one spf record.
- [SPF] Change the include check to validate if it can be a domain

## v1.0.7

- Fix number of lookups being counted wrong

## v1.0.6

- Add null checks to all public methods.
- Add checks to ensure hostname does not exceed 253 characters.

## v1.0.5

- Add Microsoft Source Link and symbols.
- Add support for BIMI.
- Add A, AAAA and MX lookup methods to IResolver.
- Fix max lookups.
- Add implementation for MX and A directives.

## v1.0.4

- Fix `SpfLookupException` not being thrown directly.
- Remove unimplemented `CheckSpfRecord`.
- Fix SPF address `Contains` method.

## v1.0.3

- Fix parsing error with whitespaces.
- Fix case insensitive parsing for SPF.
- Add `DkimException`, `DmarcException`, `SpfException`.
- Add *Invalid* and *NotFound* exceptions.
- Add `SpfLookupException`.
- Change exception for include lookup fails.

## v1.0.2

- Fix policy tag validation for DKIM.
- Fix CIDR parsing for SPF.
- Fix max lookups for SPF.
- Add SPF modifier parsing.
- Add more test coverage.

## v1.0.1

- Add DMARC parsing and lookup.
- Fix for empty tags during parsing.

## v1.0.0

- Initial release with SPF and DKIM.
