using BusinessMonitor.MailTools.Dkim;
using BusinessMonitor.MailTools.Exceptions;
using BusinessMonitor.MailTools.Test.Dns;
using NUnit.Framework;
using System.Linq;
using System;

namespace BusinessMonitor.MailTools.Test
{
    internal class DkimTests
    {
        [Test]
        public void TestParse()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo("7JWI64WVIQ=="));
            Assert.That(record.Notes, Is.EqualTo("Hello, World!"));
            Assert.That(record.KeyType, Is.EqualTo("rsa"));
            Assert.That(record.Algorithms.Length, Is.EqualTo(0));

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; h=sha1:sha256; k=ed25519; s=email");

            Assert.That(record2.Algorithms, Does.Contain("sha1"));
            Assert.That(record2.KeyType, Is.EqualTo("ed25519"));
            Assert.That(record2.ServiceType, Does.Contain("email"));
        }

        [Test]
        public void TestFlags()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==; t=y:s");

            Assert.That(record, Is.Not.Null);
            Assert.That((record.Flags & DkimFlags.Testing) != 0, Is.True);
            Assert.That((record.Flags & DkimFlags.SameDomain) != 0, Is.True);

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=7JWI64WVIQ==");

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.Flags, Is.EqualTo(DkimFlags.None));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("test._domainkey.businessmonitor.nl", "v=DKIM1; p=7JWI64WVIQ==; n=Hello, World!");

            var check = new DkimCheck(resolver);
            var record = check.GetDkimRecord("businessmonitor.nl", "test");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo("7JWI64WVIQ=="));
            Assert.That(record.Notes, Is.EqualTo("Hello, World!"));
        }

        [Test]
        [TestCase("")]
        [TestCase("v=DKIM1; n=Notes")]
        [TestCase("v=DKIM1; p=?NotAValidBase64String?")]
        public void TestInvalid(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        public void TestInvalidArguments()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                new DkimCheck(null);
            });

            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetDkimRecord(null, "test");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                check.GetDkimRecord("test", null);
            });

            Assert.Throws<ArgumentException>(() =>
            {
                var domain = new string('a', 300);

                check.GetDkimRecord(domain, "test");
            });

            Assert.Throws<ArgumentNullException>(() =>
            {
                DkimCheck.ParseDkimRecord(null);
            });
        }

        [Test]
        public void TestNotFound()
        {
            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<DkimNotFoundException>(() =>
            {
                check.GetDkimRecord("example.com", "test");
            });
        }

        [Test]
        public void TestRevoked()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.Empty);
        }

        // Selectors and domains that could alter the DNS query
        [TestCase("business.nl", "sel ector")]
        [TestCase("business.nl", "sel..ector")]
        [TestCase("business.nl", ".selector")]
        [TestCase("business.nl", "selector.")]
        [TestCase("business.nl", "sel\u0000ector")]
        [TestCase("business.nl", "sel/ector")]
        [TestCase("business.nl", "-selector")]
        [TestCase("business.nl", "")]
        [TestCase("busi ness.nl", "default")]
        [TestCase("business..nl", "default")]
        [TestCase(".business.nl", "default")]
        [TestCase("business.nl.", "default")]
        public void TestInvalidQueryInput(string domain, string selector)
        {
            var check = new DkimCheck(new DummyResolver());

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetDkimRecord(domain, selector);
            });
        }

        [Test]
        public void TestMultiLabelSelector()
        {
            // Selectors are sub-domains and may contain multiple labels
            var resolver = new DummyResolver("s1.s2._domainkey.business.nl", "v=DKIM1; p=");
            var check = new DkimCheck(resolver);

            Assert.DoesNotThrow(() =>
            {
                check.GetDkimRecord("business.nl", "s1.s2");
            });
        }

        [Test]
        public void TestCombinedNameTooLong()
        {
            var check = new DkimCheck(new DummyResolver());
            var domain = string.Join(".", Enumerable.Repeat(new string('a', 60), 4)); // 243 chars, valid on its own

            Assert.Throws<ArgumentException>(() =>
            {
                check.GetDkimRecord(domain, "selector");
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=")]           // Revoked key - empty (should pass)
        [TestCase("v=DKIM1; p=aaa")]        // Invalid - incomplete base64
        [TestCase("v=DKIM1; p=!!!")]        // Invalid - non-base64 characters
        [TestCase("v=DKIM1; p=AA")]         // Invalid - too short (% 4 != 0)
        public void TestBase64Validation(string value)
        {
            if (value.EndsWith("p="))
            {
                // Revoked key - should parse successfully
                var record = DkimCheck.ParseDkimRecord(value);
                Assert.That(record, Is.Not.Null);
                Assert.That(record.IsRevoked, Is.True);
            }
            else
            {
                // Invalid keys should throw
                Assert.Throws<DkimInvalidException>(() =>
                {
                    DkimCheck.ParseDkimRecord(value);
                });
            }
        }

        [Test]
        public void TestValidBase64Keys()
        {
            // Valid public key
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuSDS3a/QcWYbKrc/zM8KguDIeb4FQtRQFUTGLbx8FeYfFQ3+tsgU3p0FQCtrR8VfzlHkqU7381A4SMNwXzBW4vB1U0GhimPM6HxcHDdZCjXXqmCHqXoIchHs07lncb1JU83V5HG9g2n8ocWqq+9Hr0KfeG6vgLUSGm5uSXQeDCwIDAQAB");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.IsRevoked, Is.False);
            Assert.That(record.PublicKey, Is.EqualTo("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuSDS3a/QcWYbKrc/zM8KguDIeb4FQtRQFUTGLbx8FeYfFQ3+tsgU3p0FQCtrR8VfzlHkqU7381A4SMNwXzBW4vB1U0GhimPM6HxcHDdZCjXXqmCHqXoIchHs07lncb1JU83V5HG9g2n8ocWqq+9Hr0KfeG6vgLUSGm5uSXQeDCwIDAQAB"));
        }

        [Test]
        public void TestMultipleDkimRecords()
        {
            // Multiple DKIM records for the same selector is invalid
            var resolver = new DummyResolver("test._domainkey.example.com", new string[] { "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuSDS3a/QcWYbKrc/zM8KguDIeb4FQtRQFUTGLbx8FeYfFQ3+tsgU3p0FQCtrR8VfzlHkqU7381A4SMNwXzBW4vB1U0GhimPM6HxcHDdZCjXXqmCHqXoIchHs07lncb1JU83V5HG9g2n8ocWqq+9Hr0KfeG6vgLUSGm5uSXQeDCwIDAQAB"
                , "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuSDS3a/QcWYbKrc/zM8KguDIeb4FQtRQFUTGLbx8FeYfFQ3+tsgU3p0FQCtrR8VfzlHkqU7381A4SMNwXzBW4vB1U0GhimPM6HxcHDdZCjXXqmCHqXoIchHs07lncb1JU83V5HG9g2n8ocWqq+9Hr0KfeG6vgLUSGm5uSXQeDCwIDAQAB"
                , "v=DKIM1; p="
            });

            var check = new DkimCheck(resolver);

            Assert.Throws<DkimInvalidException>(() =>
            {
                check.GetDkimRecord("example.com", "test");
            }, "Should reject multiple DKIM records for the same selector");
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==", "rsa")]                    // Absent, defaults to rsa
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=", "rsa")]                // Empty, defaults to rsa
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=rsa", "rsa")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=ed25519", "ed25519")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k= rsa ", "rsa")]           // Surrounding whitespace
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=ed25519;K=rsa", "ed25519")] // k is case sensitive
        public void TestKeyType(string value, string expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.KeyType, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=email", new[] { "email" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=*", new[] { "*" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=email:*", new[] { "email", "*" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s= email : * ", new[] { "email", "*" })] // Whitespace around colons is allowed
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=tlsrpt:email", new[] { "tlsrpt", "email" })] // Unrecognized types are ignored
        [TestCase("v=DKIM1; p=7JWI64WVIQ==", new[] { "*" })] // Absent, defaults to all service types
        public void TestServiceType(string value, string[] expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.ServiceType, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=")]           // Empty list does not include email
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=web")]        // Record does not apply to email
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=tlsrpt")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=EMAIL")]      // Case sensitive
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=Email")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; s=e mail")]
        public void TestInvalidServiceType(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha1", new[] { "sha1" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha256", new[] { "sha256" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha1:sha256", new[] { "sha1", "sha256" })]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==", new string[0])] // Absent, all algorithms allowed
        public void TestHashAlgorithms(string value, string[] expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Algorithms, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=")]              // Empty list is invalid
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=SHA256")]        // Case sensitive
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=Sha1")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha512")]        // Not a registered algorithm
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=md5")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha1:")]         // Empty list entry
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha1::sha256")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; h=sha 256")]
        public void TestInvalidHashAlgorithm(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=RSA")] // Case sensitive
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=Ed25519")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=r sa")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=dsa")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=ed448")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=rsa2048")]
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=ED25519;K=rsa")] // k is case sensitive
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; K=ed25519;k=aap")] // k is case sensitive
        [TestCase("v=DKIM1; p=7JWI64WVIQ==; k=ed25519;k=rsa")] // k is case sensitive
        public void TestInvalidKeyType(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }
    }
}
