using NUnit.Framework;
using System;
using System.Net;
using BusinessMonitor.MailTools.Mx;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;

namespace BusinessMonitor.MailTools.Test
{
    [TestFixture]
    public class MxValidatorTests
    {
        private static MxValidator.MxValidationResult Validate(params string[] addresses)
        {
            var resolver = new DummyResolver();
            resolver.AddMail("example.com", "mail.example.com");

            foreach (var address in addresses)
            {
                resolver.AddAddress("mail.example.com", IPAddress.Parse(address));
            }

            var validator = new MxValidator(resolver);

            return validator.ValidateMxRecords("example.com");
        }

        [Test]
        public void ValidateMxRecords_WithValidMxRecords_ReturnsValidResult()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("businessmonitor.nl", "mail1.businessmonitor.nl");
            resolver.AddMail("businessmonitor.nl", "mail2.businessmonitor.nl");
            resolver.AddAddress("mail1.businessmonitor.nl", IPAddress.Parse("222.222.1.1"));
            resolver.AddAddress("mail2.businessmonitor.nl", IPAddress.Parse("222.222.1.2"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("businessmonitor.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.HasNullMx, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(result.CanReceiveMail, Is.True);
        }

        [Test]
        public void ValidateMxRecords_WithInvalidMxRecords_ReturnsInvalidResult()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("geen.nl", "bogus.dmrmail.nl");
            resolver.AddAddress("bogus.dmrmail.nl", IPAddress.Parse("127.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("geen.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords.Count, Is.EqualTo(1));
            Assert.That(result.InvalidMxRecords, Does.Contain("bogus.dmrmail.nl"));
            Assert.That(result.CanReceiveMail, Is.False);
        }

        [Test]
        public void ValidateMxRecords_WithNoMxRecords_ReturnsNoRecords()
        {
            // Arrange
            var resolver = new DummyResolver();
            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("nonexistentdomain.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.HasImplicitMx, Is.False);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);

            // The implicit MX is looked up on the domain itself
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "nonexistentdomain.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithImplicitMx_ReturnsImplicitMx()
        {
            // Arrange, no MX records but an address record, RFC 5321 section 5.1 treats the domain
            // as an MX with preference 0 pointing to itself
            var resolver = new DummyResolver();
            resolver.AddAddress("implicit.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("implicit.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.HasNullMx, Is.False);
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "implicit.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithImplicitMxMultipleAddresses_ReturnsImplicitMx()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddAddress("implicit.nl", IPAddress.Parse("222.222.1.1"));
            resolver.AddAddress("implicit.nl", IPAddress.Parse("2606:4700:4700::1111"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("implicit.nl");

            // Assert
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [TestCase("127.0.0.1")]
        [TestCase("10.0.0.1")]
        [TestCase("192.168.1.1")]
        [TestCase("::1")]
        [TestCase("::ffff:10.0.0.1")]
        [TestCase("2002:a00:1::1")]  // 6to4 embedding 10.0.0.1
        public void ValidateMxRecords_WithNonRoutableImplicitMx_MarksDomainInvalid(string address)
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddAddress("implicit.nl", IPAddress.Parse(address));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("implicit.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "implicit.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithMixedImplicitMxAddresses_MarksDomainInvalid()
        {
            // Arrange, a single non-routable address among routable ones invalidates the implicit MX
            var resolver = new DummyResolver();
            resolver.AddAddress("implicit.nl", IPAddress.Parse("1.1.1.1"));
            resolver.AddAddress("implicit.nl", IPAddress.Parse("10.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("implicit.nl");

            // Assert
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "implicit.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithImplicitMxAndTrailingDotDomain_ResolvesWithoutDot()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddAddress("implicit.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("implicit.nl.");

            // Assert
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.MailLookups, Is.EqualTo(new[] { "implicit.nl" }));
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "implicit.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithImplicitMxAndNullAddressEntries_IgnoresThem()
        {
            // Arrange
            var resolver = new DummyResolver { ReturnNullEntry = true };
            resolver.AddAddress("implicit.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act, the null entry prepended to the MX result is removed so the list is empty and
            // the implicit MX applies, the null entry in the address result is removed as well
            var result = validator.ValidateMxRecords("implicit.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithMxRecords_DoesNotResolveImplicitMx()
        {
            // Arrange, the domain has both MX and address records, only the MX hosts are resolved
            var resolver = new DummyResolver();
            resolver.AddMail("both.nl", "mail.both.nl");
            resolver.AddAddress("mail.both.nl", IPAddress.Parse("222.222.1.1"));
            resolver.AddAddress("both.nl", IPAddress.Parse("10.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("both.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.HasImplicitMx, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.both.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithTooManyMxRecords_ValidatesFirstTenAndReportsRest()
        {
            // Arrange
            var resolver = new DummyResolver();

            for (var i = 1; i <= 12; i++)
            {
                resolver.AddMail("many.nl", $"mx{i}.many.nl");
                resolver.AddAddress($"mx{i}.many.nl", IPAddress.Parse("222.222.1.1"));
            }

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("many.nl");

            // Assert, the first ten hosts are resolved, the rest are reported without a lookup
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(result.MxRecordLimitExceeded, Is.True);
            Assert.That(result.UnvalidatedMxRecords, Is.EqualTo(new[] { "mx11.many.nl", "mx12.many.nl" }));
            Assert.That(resolver.AddressLookups, Has.Count.EqualTo(10));
            Assert.That(resolver.AddressLookups, Does.Not.Contain("mx11.many.nl"));
        }

        [Test]
        public void ValidateMxRecords_WithTooManyMxRecords_AllFirstTenInvalid_CannotReceiveMail()
        {
            // Arrange, the hosts beyond the limit are of unknown validity and do not count toward CanReceiveMail
            var resolver = new DummyResolver();

            for (var i = 1; i <= 11; i++)
            {
                resolver.AddMail("many.nl", $"mx{i}.many.nl");
            }

            resolver.AddAddress("mx11.many.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("many.nl");

            // Assert
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Has.Count.EqualTo(10));
            Assert.That(result.UnvalidatedMxRecords, Is.EqualTo(new[] { "mx11.many.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithTooManyMxRecords_NullMxAndInvalidNamesStillReported()
        {
            // Arrange, a null MX and an invalid host name need no lookup and are reported beyond the limit
            var resolver = new DummyResolver();

            for (var i = 1; i <= 10; i++)
            {
                resolver.AddMail("many.nl", $"mx{i}.many.nl");
                resolver.AddAddress($"mx{i}.many.nl", IPAddress.Parse("222.222.1.1"));
            }

            resolver.AddMail("many.nl", "mx11.many.nl");
            resolver.AddMail("many.nl", "bad_host.many.nl");
            resolver.AddMail("many.nl", ".");

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("many.nl");

            // Assert
            Assert.That(result.HasNullMx, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "bad_host.many.nl", "." }));
            Assert.That(result.UnvalidatedMxRecords, Is.EqualTo(new[] { "mx11.many.nl" }));
            Assert.That(resolver.AddressLookups, Has.Count.EqualTo(10));
        }

        [Test]
        public void ValidateMxRecords_WithMaxMxRecords_ResolvesAll()
        {
            // Arrange
            var resolver = new DummyResolver();

            for (var i = 1; i <= 10; i++)
            {
                resolver.AddMail("ten.nl", $"mx{i}.ten.nl");
                resolver.AddAddress($"mx{i}.ten.nl", IPAddress.Parse("222.222.1.1"));
            }

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("ten.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Has.Count.EqualTo(10));
        }

        // Domains that could alter the DNS query
        [TestCase("busi ness.nl")]
        [TestCase("business..nl")]
        [TestCase(".business.nl")]
        [TestCase("business.nl..")]
        [TestCase("busi\u0000ness.nl")]
        [TestCase("business.nl&type=A")]
        [TestCase("")]
        public void ValidateMxRecords_WithInvalidDomain_ThrowsArgumentException(string domain)
        {
            var resolver = new DummyResolver();
            var validator = new MxValidator(resolver);

            Assert.Throws<ArgumentException>(() => validator.ValidateMxRecords(domain));

            Assert.That(resolver.MailLookups, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithTrailingDotDomain_ResolvesWithoutDot()
        {
            var resolver = new DummyResolver();
            resolver.AddMail("example.com", "mail.example.com");
            resolver.AddAddress("mail.example.com", IPAddress.Parse("1.1.1.1"));

            var validator = new MxValidator(resolver);

            var result = validator.ValidateMxRecords("example.com.");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.MailLookups, Is.EqualTo(new[] { "example.com" }));
        }

        [Test]
        public void ValidateMxRecords_WithIdnDomain_ResolvesAsciiForm()
        {
            // An internationalized domain name is looked up in its A-label form
            var resolver = new DummyResolver();
            resolver.AddMail("xn--bcher-kva.de", "mail.xn--bcher-kva.de");
            resolver.AddAddress("mail.xn--bcher-kva.de", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            var result = validator.ValidateMxRecords("bücher.de");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(resolver.MailLookups, Is.EqualTo(new[] { "xn--bcher-kva.de" }));
        }

        [Test]
        public void ValidateMxRecords_WithIdnImplicitMx_ReportsAsciiForm()
        {
            var resolver = new DummyResolver();
            resolver.AddAddress("xn--bcher-kva.de", IPAddress.Parse("127.0.0.1"));

            var validator = new MxValidator(resolver);

            var result = validator.ValidateMxRecords("bücher.de");

            Assert.That(result.HasImplicitMx, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "xn--bcher-kva.de" }));
        }

        [Test]
        public void ValidateMxRecords_WithNullDomain_ThrowsArgumentNullException()
        {
            var validator = new MxValidator(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() => validator.ValidateMxRecords(null));
        }

        [TestCase("mail.example.com&type=TXT")]
        [TestCase("mail example.com")]
        [TestCase("mail..example.com")]
        [TestCase("-mail.example.com")]
        [TestCase("mail.example.com..")]
        [TestCase("mail\u0000.example.com")]
        // An MX exchange must be a host name (RFC 1123 section 2.1), not any DNS name
        [TestCase("_mx.hostile.nl")]
        [TestCase("mail._tcp.hostile.nl")]
        [TestCase("192.0.2.1")]          // IP address literal
        [TestCase("10.0.0.1")]
        [TestCase("2001:db8::1")]
        [TestCase("mail.hostile.123")]   // Numeric top-level domain
        // Special-use names (RFC 6761 and others) never receive internet mail
        [TestCase("localhost")]
        [TestCase("mail.localhost")]
        [TestCase("mail.local")]
        [TestCase("mail.internal")]
        [TestCase("mail.home.arpa")]
        [TestCase("mail.onion")]
        [TestCase("mail.test")]
        [TestCase("mail.invalid")]
        public void ValidateMxRecords_WithInvalidMxHost_MarksRecordInvalidWithoutResolving(string mxHost)
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("hostile.nl", mxHost);

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("hostile.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { mxHost }));
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(resolver.AddressLookups, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithTrailingDotMxHost_ResolvesWithoutDot()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("dot.nl", "mail.dot.nl.");
            resolver.AddAddress("mail.dot.nl", IPAddress.Parse("127.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("dot.nl");

            // Assert
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mail.dot.nl." }));
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.dot.nl" }));
        }

        [TestCase(".")]
        [TestCase("")]
        public void ValidateMxRecords_WithNullMx_SkipsRecord(string mxHost)
        {
            // A null MX (RFC 7505) states the domain accepts no mail, there is nothing to resolve and
            // it is an MX record so the implicit MX fallback does not apply even when the domain has
            // address records
            var resolver = new DummyResolver();
            resolver.AddMail("nomail.nl", mxHost);
            resolver.AddAddress("nomail.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            var result = validator.ValidateMxRecords("nomail.nl");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.HasImplicitMx, Is.False);
            Assert.That(result.HasNullMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithTwoNullMx_ReportsNullMxOnce()
        {
            // A null MX must be the only MX record (RFC 7505 section 3), two of them is a misconfiguration
            var resolver = new DummyResolver();
            resolver.AddMail("doublenull.nl", ".");
            resolver.AddMail("doublenull.nl", ".");

            var validator = new MxValidator(resolver);

            var result = validator.ValidateMxRecords("doublenull.nl");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.HasNullMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "." }));
            Assert.That(resolver.AddressLookups, Is.Empty);
        }

        [Test]
        public void Constructor_WithNullResolver_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new MxValidator(null);
            });
        }

        [Test]
        public void ValidateMxRecords_WithNullMailRecords_ReturnsNoRecords()
        {
            // Arrange
            var resolver = new DummyResolver { ReturnNullWhenEmpty = true };
            var validator = new MxValidator(resolver);

            // Act, the address lookup for the implicit MX returns null as well
            var result = validator.ValidateMxRecords("nullmail.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.False);
            Assert.That(result.HasImplicitMx, Is.False);
            Assert.That(result.InvalidMxRecords, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithNullEntries_IgnoresThem()
        {
            // Arrange
            var resolver = new DummyResolver { ReturnNullEntry = true };
            resolver.AddMail("nullentry.nl", "mail.nullentry.nl");
            resolver.AddAddress("mail.nullentry.nl", IPAddress.Parse("10.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("nullentry.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mail.nullentry.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithNullAddressRecords_MarksRecordInvalid()
        {
            // Arrange, a null result is an empty result, the host has no address records
            var resolver = new DummyResolver { ReturnNullWhenEmpty = true };
            resolver.AddMail("nulladdress.nl", "mail.nulladdress.nl");

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("nulladdress.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mail.nulladdress.nl" }));
            Assert.That(result.CanReceiveMail, Is.False);
        }

        [Test]
        public void ValidateMxRecords_WithDuplicateMxHosts_ResolvesAndReportsOnce()
        {
            // Arrange, DNS names are case insensitive and the absolute form is the same host
            var resolver = new DummyResolver();
            resolver.AddMail("dup.nl", "mail.dup.nl");
            resolver.AddMail("dup.nl", "MAIL.dup.nl");
            resolver.AddMail("dup.nl", "mail.dup.nl.");
            resolver.AddMail("dup.nl", "Mail.Dup.NL.");
            resolver.AddAddress("mail.dup.nl", IPAddress.Parse("127.0.0.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("dup.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mail.dup.nl" }));
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.dup.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithDuplicateValidMxHosts_ResolvesOnce()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("dup.nl", "mail.dup.nl");
            resolver.AddMail("dup.nl", "mail.dup.nl");
            resolver.AddMail("dup.nl", "mail2.dup.nl");
            resolver.AddAddress("mail.dup.nl", IPAddress.Parse("222.222.1.1"));
            resolver.AddAddress("mail2.dup.nl", IPAddress.Parse("222.222.1.2"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("dup.nl");

            // Assert
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.dup.nl", "mail2.dup.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithDuplicateInvalidMxHosts_ReportsEach()
        {
            // Arrange, records that are not a host name cannot be normalized and are reported as returned
            var resolver = new DummyResolver();
            resolver.AddMail("dup.nl", "bad host");
            resolver.AddMail("dup.nl", "bad host");

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("dup.nl");

            // Assert
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "bad host", "bad host" }));
            Assert.That(resolver.AddressLookups, Is.Empty);
        }

        [Test]
        public void ValidateMxRecords_WithManyDuplicateMxRecords_ResolvesOnceWithinLimit()
        {
            // Arrange, the limit applies to distinct hosts, duplicates are resolved once and do not count
            var resolver = new DummyResolver();

            for (var i = 1; i <= 11; i++)
            {
                resolver.AddMail("many.nl", "mail.many.nl");
            }

            resolver.AddAddress("mail.many.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("many.nl");

            // Assert
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.MxRecordLimitExceeded, Is.False);
            Assert.That(result.UnvalidatedMxRecords, Is.Empty);
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.many.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithMxHostWithoutAddressRecords_MarksRecordInvalid()
        {
            // Arrange, a dangling MX, the host has no address records so mail cannot be delivered to it
            var resolver = new DummyResolver();
            resolver.AddMail("noaddress.nl", "mail.noaddress.nl");

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("noaddress.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mail.noaddress.nl" }));
            Assert.That(result.CanReceiveMail, Is.False);
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.noaddress.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithOneValidAmongInvalidMxRecords_CanReceiveMail()
        {
            // Arrange, a single usable host is enough to receive mail
            var resolver = new DummyResolver();
            resolver.AddMail("partial.nl", "mx1.partial.nl");
            resolver.AddMail("partial.nl", "mx2.partial.nl");
            resolver.AddMail("partial.nl", "mx3.partial.nl");
            resolver.AddMail("partial.nl", "bad host");
            resolver.AddAddress("mx1.partial.nl", IPAddress.Parse("127.0.0.1"));
            resolver.AddAddress("mx2.partial.nl", IPAddress.Parse("222.222.1.1"));
            // mx3 has no address records

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("partial.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mx1.partial.nl", "mx3.partial.nl", "bad host" }));
            Assert.That(result.CanReceiveMail, Is.True);
        }

        [Test]
        public void ValidateMxRecords_WithOnlyInvalidMxRecords_CannotReceiveMail()
        {
            // Arrange
            var resolver = new DummyResolver();
            resolver.AddMail("allbad.nl", "mx1.allbad.nl");
            resolver.AddMail("allbad.nl", "mx2.allbad.nl");
            resolver.AddMail("allbad.nl", "mx3.allbad.nl");
            resolver.AddMail("allbad.nl", "bad host");
            resolver.AddAddress("mx1.allbad.nl", IPAddress.Parse("127.0.0.1"));
            resolver.AddAddress("mx2.allbad.nl", IPAddress.Parse("10.0.0.1"));
            // mx3 has no address records

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("allbad.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "mx1.allbad.nl", "mx2.allbad.nl", "mx3.allbad.nl", "bad host" }));
            Assert.That(result.CanReceiveMail, Is.False);
        }

        [Test]
        public void ValidateMxRecords_WithNullMxAndValidMx_ReportsNullMxInvalid()
        {
            // Arrange, a null MX must be the only MX record (RFC 7505 section 3), next to a real MX it is
            // reported as invalid while the real host still receives mail
            var resolver = new DummyResolver();
            resolver.AddMail("mixednull.nl", ".");
            resolver.AddMail("mixednull.nl", "mail.mixednull.nl");
            resolver.AddAddress("mail.mixednull.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("mixednull.nl");

            // Assert
            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.HasNullMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "." }));
            Assert.That(resolver.AddressLookups, Is.EqualTo(new[] { "mail.mixednull.nl" }));
        }

        [Test]
        public void ValidateMxRecords_WithValidMxAndNullMx_ReportsNullMxInvalid()
        {
            // Arrange, the order of the records does not matter
            var resolver = new DummyResolver();
            resolver.AddMail("mixednull.nl", "mail.mixednull.nl");
            resolver.AddMail("mixednull.nl", "");
            resolver.AddAddress("mail.mixednull.nl", IPAddress.Parse("222.222.1.1"));

            var validator = new MxValidator(resolver);

            // Act
            var result = validator.ValidateMxRecords("mixednull.nl");

            // Assert
            Assert.That(result.HasNullMx, Is.True);
            Assert.That(result.CanReceiveMail, Is.True);
            Assert.That(result.InvalidMxRecords, Is.EqualTo(new[] { "" }));
        }

        // IPv4 non-routable ranges
        [TestCase("0.1.2.3")]         // 0.0.0.0/8
        [TestCase("10.0.0.1")]        // 10.0.0.0/8
        [TestCase("10.255.255.255")]  // 10.0.0.0/8 upper bound
        [TestCase("127.0.0.1")]       // loopback 127.0.0.0/8
        [TestCase("127.255.255.255")] // loopback upper bound
        [TestCase("169.254.1.1")]     // link-local 169.254.0.0/16
        [TestCase("172.16.0.1")]      // 172.16.0.0/12 lower bound
        [TestCase("172.31.255.255")]  // 172.16.0.0/12 upper bound
        [TestCase("192.168.0.1")]     // 192.168.0.0/16
        [TestCase("192.168.255.255")] // 192.168.0.0/16 upper bound
        [TestCase("100.64.0.1")]      // CGNAT 100.64.0.0/10 lower bound
        [TestCase("100.127.255.255")] // CGNAT upper bound
        [TestCase("224.0.0.1")]       // multicast lower bound
        [TestCase("239.255.255.255")] // multicast upper bound
        [TestCase("240.0.0.1")]       // reserved
        [TestCase("255.255.255.255")] // broadcast
        // IPv4-mapped IPv6 must not bypass the IPv4 checks
        [TestCase("::ffff:10.0.0.1")]
        [TestCase("::ffff:192.168.1.1")]
        [TestCase("::ffff:127.0.0.1")]
        [TestCase("::ffff:172.16.0.1")]
        [TestCase("::ffff:169.254.1.1")]
        // Documentation / test / benchmarking ranges
        [TestCase("192.0.0.1")]       // 192.0.0.0/24
        [TestCase("192.0.2.1")]       // TEST-NET-1
        [TestCase("198.51.100.1")]    // TEST-NET-2
        [TestCase("203.0.113.1")]     // TEST-NET-3
        [TestCase("198.18.0.1")]      // 198.18.0.0/15 lower bound
        [TestCase("198.19.255.255")]  // 198.18.0.0/15 upper bound
        [TestCase("2001:db8::1")]     // IPv6 documentation 2001:db8::/32
        // IPv6 non-routable ranges
        [TestCase("::")]              // unspecified
        [TestCase("::1")]             // loopback
        [TestCase("fe80::1")]         // link-local fe80::/10
        [TestCase("fec0::1")]         // site-local fec0::/10 (deprecated)
        [TestCase("ff02::1")]         // multicast ff00::/8
        [TestCase("fc00::1")]         // unique local fc00::/7 lower half
        [TestCase("fd12:3456:789a::1")] // unique local fc00::/7 upper half
        // IPv4-compatible IPv6 ::/96 (deprecated, never routed)
        [TestCase("::10.0.0.1")]
        [TestCase("::1.1.1.1")]
        [TestCase("::2")]
        // IPv6 transition addresses embedding a non-routable IPv4 address
        [TestCase("2002:a00:1::1")]              // 6to4 embedding 10.0.0.1
        [TestCase("2002:c0a8:101::1")]           // 6to4 embedding 192.168.1.1
        [TestCase("2002:7f00:1::1")]             // 6to4 embedding 127.0.0.1
        [TestCase("2002:ac10:1::1")]             // 6to4 embedding 172.16.0.1
        [TestCase("2001:0:4136:e378::f5ff:fffe")] // Teredo, client ~(f5ff:fffe) = 10.0.0.1
        [TestCase("2001:0:4136:e378::3f57:fefe")] // Teredo, client ~(3f57:fefe) = 192.168.1.1
        [TestCase("2001:0:4136:e378::80ff:fffe")] // Teredo, client ~(80ff:fffe) = 127.0.0.1
        [TestCase("64:ff9b::10.0.0.1")]          // NAT64 embedding 10.0.0.1
        [TestCase("64:ff9b::192.168.1.1")]       // NAT64 embedding 192.168.1.1
        [TestCase("64:ff9b::169.254.1.1")]       // NAT64 embedding 169.254.1.1
        public void ValidateMxRecords_WithNonRoutableAddress_MarksRecordInvalid(string address)
        {
            var result = Validate(address);

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Does.Contain("mail.example.com"));
            Assert.That(result.CanReceiveMail, Is.False);
        }

        // IPv4 routable addresses, including boundaries just outside the non-routable ranges
        [TestCase("1.1.1.1")]
        [TestCase("9.255.255.255")]   // just below 10.0.0.0/8
        [TestCase("11.0.0.1")]        // just above 10.0.0.0/8
        [TestCase("126.255.255.255")] // just below loopback
        [TestCase("128.0.0.1")]       // just above loopback
        [TestCase("169.253.255.255")] // just below link-local
        [TestCase("169.255.0.1")]     // just above link-local
        [TestCase("172.15.255.255")]  // just below 172.16.0.0/12
        [TestCase("172.32.0.1")]      // just above 172.16.0.0/12
        [TestCase("192.167.255.255")] // just below 192.168.0.0/16
        [TestCase("192.169.0.1")]     // just above 192.168.0.0/16
        [TestCase("100.63.255.255")]  // just below CGNAT
        [TestCase("100.128.0.1")]     // just above CGNAT
        [TestCase("223.255.255.255")] // just below multicast
        // IPv6 routable addresses
        [TestCase("2606:4700:4700::1111")]
        [TestCase("fbff::1")]         // just below fc00::/7
        [TestCase("fe00::1")]         // just above fc00::/7, below fe80::/10
        [TestCase("::ffff:1.1.1.1")]  // IPv4-mapped but routable
        [TestCase("192.0.1.1")]       // just below TEST-NET-1
        [TestCase("192.0.3.1")]       // just above TEST-NET-1
        [TestCase("198.51.99.255")]   // just below TEST-NET-2
        [TestCase("198.51.101.0")]    // just above TEST-NET-2
        [TestCase("203.0.112.255")]   // just below TEST-NET-3
        [TestCase("203.0.114.0")]     // just above TEST-NET-3
        [TestCase("198.17.255.255")]  // just below benchmarking range
        [TestCase("198.20.0.1")]      // just above benchmarking range
        [TestCase("2001:db7:ffff::1")] // just below documentation range
        [TestCase("2001:db9::1")]     // just above documentation range
        // IPv6 transition addresses embedding a routable IPv4 address
        [TestCase("2002:101:101::1")]            // 6to4 embedding 1.1.1.1
        [TestCase("2002:d8ef:2301::1")]          // 6to4 embedding 216.239.35.1
        [TestCase("2001:0:4136:e378::fefe:fefe")] // Teredo, client ~(fefe:fefe) = 1.1.1.1
        [TestCase("64:ff9b::1.1.1.1")]           // NAT64 embedding 1.1.1.1
        [TestCase("64:ff9c::10.0.0.1")]          // not the NAT64 well-known prefix
        [TestCase("2003:a00:1::1")]              // not the 6to4 prefix
        public void ValidateMxRecords_WithRoutableAddress_MarksRecordValid(string address)
        {
            var result = Validate(address);

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Is.Empty);
            Assert.That(result.CanReceiveMail, Is.True);
        }

        [Test]
        public void ValidateMxRecords_WithMixedAddresses_MarksRecordInvalid()
        {
            // A single non-routable address among routable ones invalidates the MX record
            var result = Validate("1.1.1.1", "10.0.0.1");

            Assert.That(result.HasMxRecords, Is.True);
            Assert.That(result.InvalidMxRecords, Does.Contain("mail.example.com"));
            Assert.That(result.CanReceiveMail, Is.False);
        }
    }
}
