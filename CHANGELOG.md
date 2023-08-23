# Changelog

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