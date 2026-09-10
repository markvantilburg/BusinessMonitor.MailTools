# Changelog

## v1.2.0
- [DKIM] **Breaking:** a record whose `h=` tag does not include `sha256` is now rejected as invalid, `rsa-sha1` signatures must not be accepted by verifiers (RFC 8301) so such a key can never verify a signature. `h=sha1:sha256` and an absent `h=` tag remain valid.
- [BIMI] Reject `l=` and `a=` locations that contain credentials, or point to localhost or a non-routable IP address (loopback, private, link-local, cloud metadata ranges), so a consumer fetching them cannot be pointed at itself or its internal network.
- [MX] Limit the number of MX records resolved per domain to 10, an `MxException` is thrown when exceeded (in line with RFC 7208 section 4.6.4 and the existing SPF `mx` limit).
- [MX] Detect non-routable addresses hidden in IPv6 transition addresses, 6to4 (`2002::/16`), Teredo (`2001::/32`) and NAT64 (`64:ff9b::/96`) are checked on the IPv4 address they embed, IPv4-compatible addresses (`::/96`) are treated as non-routable.
- Exception messages that quote DNS record content now replace control and non-ASCII characters and truncate long values, see the README note on exception messages.
- [SPF] [DMARC] [MX] `GetSpfRecord`, `GetDmarcRecord` and `ValidateMxRecords` now validate the domain as a DNS name and throw `ArgumentException` for anything else, in line with the DKIM and BIMI checks, so malformed input can no longer reach the resolver. A single trailing dot (the absolute form, `example.com.`) is accepted by all checks and removed before the lookup, this was previously rejected by the DKIM and BIMI checks.
- [SPF] [MX] MX hosts returned by DNS are validated before they are resolved again, a single trailing dot is removed and a null MX (RFC 7505) is skipped. An invalid host throws `SpfException` for the SPF `mx` mechanism and is reported in `InvalidMxRecords` by the MX validator.
- A resolver returning `null` instead of an empty array is now treated as an empty result by all checks.
- [DMARC] **Breaking:** the parser now follows RFC 9989 (DMARCbis, obsoletes RFC 7489). Multiple records on a domain are invalid, the version tag is matched exactly (`v=DMARC1`, case sensitive, whitespace around `=` allowed), `p` may appear anywhere and is optional (treated as `p=none`, see `PolicySpecified`), `sp` inherits `p` and the new `np` inherits `sp`, `fo` is ignored without `ruf` and validated, `rua`/`ruf` entries are trimmed and validated as URIs with the obsolete `!size` suffix removed, duplicate tags and malformed segments are invalid, tag values are case insensitive. New tags `np`, `t` and `psd` are exposed as `NonExistentSubdomainPolicy`, `TestMode` and `PublicSuffixDomain`. `PercentageTag`, `ReportFormat` and `ReportInterval` are marked obsolete as the tags were removed from the specification.
- [SPF] The lookup limit is now counted per evaluation instead of per `SpfCheck` instance, a shared instance can be used from multiple threads without one evaluation resetting the limit of another. The count is exposed as `SpfRecord.Lookups`.

## v1.1.0
- [SPF] Detect duplicate IP4/IP6 mechanisms in SPF records [Issue:#13](https://github.com/markvantilburg/BusinessMonitor.MailTools/issues/13)
- [MX] Improve the localhost/non routable IP addresses detection [Issue:#7](https://github.com/markvantilburg/BusinessMonitor.MailTools/issues/7)
- [DKIM] Validate all fields
- [DKIM] Validate Service [Issue:#14](https://github.com/markvantilburg/BusinessMonitor.MailTools/issues/14)
- [DKIM] Validate Hash [Issue:#16](https://github.com/markvantilburg/BusinessMonitor.MailTools/issues/16)
- Overall, apply additional hardening to the methods to protect against a potentially malicious DNS server.

## v1.0.10
- [BIMI] Add the new local-part selector tag (https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/11)
- [BIMI] Update the new preference tag (https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/10)
- Build, add a .net10 build

## v1.0.9
- If the SPF record contains A but that does not resolve throw an error
- [MX]  Add a new method to validate MX records, if one of the domains resolves to "localhost" we mark it as invalid [Issue:#7](https://github.com/markvantilburg/BusinessMonitor.MailTools/issues/7)
- [BIMI] Add the new preference tag (https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/8)

## v1.0.8
- Migrate to .net8 [#4](https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/4)
- Upgrade nunit tests to the latest version
- [SPF] Check if the domain has just one spf record.
- [SPF] Change the include check to validate if it can be a domain
- [DNS] Example DNS over HTTPS (DoH) resolver
- [BIMI] Add support for the avatar preference tag [#5](https://github.com/markvantilburg/BusinessMonitor.MailTools/pull/5)

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
