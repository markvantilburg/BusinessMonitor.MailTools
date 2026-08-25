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
        // A valid 1024 bit RSA public key
        private const string RsaKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCuSDS3a/QcWYbKrc/zM8KguDIeb4FQtRQFUTGLbx8FeYfFQ3+tsgU3p0FQCtrR8VfzlHkqU7381A4SMNwXzBW4vB1U0GhimPM6HxcHDdZCjXXqmCHqXoIchHs07lncb1JU83V5HG9g2n8ocWqq+9Hr0KfeG6vgLUSGm5uSXQeDCwIDAQAB";

        // A valid 2048 bit RSA public key
        private const string Rsa2048Key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxEXr/hvIkxRP5uKoXYFiRPBSRsLwHOMq5imQY7+qX4WzfC14VoKpdN6SwK1nO9QqqFHhEhBgFpZqhK2QJFaJGp9ALgJRAczAGlFjEOSu82q7doG4no24Or4Jj4SeN2d5vvxI4ec8RveoRmZBzOKj4Lf8NhuJzJjf2ECf9WiOAagRzitvNYlNCuSy4IlGenYRkn9bOYCcU3rWEu/lYNpFI706iKHVc3ls+ARGnq6jAVbfztuBi9eosR06mzRZhUwXD4pzuSf5gkNYM4jrh/T5H4RP7ECSfn280oji9TLXNvCUgBju4gjt3lBvF2pHSc4zOUe4vTgN6+4DpwLX8vdv3wIDAQAB";

        // A 512 bit RSA public key, below the RFC 8301 minimum of 1024 bits
        private const string Rsa512Key = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN8c5XSiQHW0yhAM1Ri5p/AqskZ4/6Vq4YN+48G8PFmZm7zUylOnWuaGtYOCLm02qXusGWhtJPbmaJGwTpx0JOkCAwEAAQ==";

        // A valid ed25519 public key, the RFC 8463 example key
        private const string Ed25519Key = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        [Test]
        public void TestParse()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=" + RsaKey + "; n=Hello, World!");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
            Assert.That(record.Notes, Is.EqualTo("Hello, World!"));
            Assert.That(record.KeyType, Is.EqualTo("rsa"));
            Assert.That(record.Algorithms.Length, Is.EqualTo(0));

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=" + Ed25519Key + "; h=sha1:sha256; k=ed25519; s=email");

            Assert.That(record2.Algorithms, Does.Contain("sha1"));
            Assert.That(record2.KeyType, Is.EqualTo("ed25519"));
            Assert.That(record2.ServiceType, Does.Contain("email"));
        }

        [Test]
        public void TestFlags()
        {
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; p=" + RsaKey + "; t=y:s");

            Assert.That(record, Is.Not.Null);
            Assert.That((record.Flags & DkimFlags.Testing) != 0, Is.True);
            Assert.That((record.Flags & DkimFlags.SameDomain) != 0, Is.True);

            var record2 = DkimCheck.ParseDkimRecord("v=DKIM1; p=" + RsaKey);

            Assert.That(record2, Is.Not.Null);
            Assert.That(record2.Flags, Is.EqualTo(DkimFlags.None));
        }

        [Test]
        public void TestLookup()
        {
            var resolver = new DummyResolver("test._domainkey.businessmonitor.nl", "v=DKIM1; p=" + RsaKey + "; n=Hello, World!");

            var check = new DkimCheck(resolver);
            var record = check.GetDkimRecord("businessmonitor.nl", "test");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
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
        [TestCase("v=DKIM1; p=" + RsaKey, 1024)]
        [TestCase("v=DKIM1; p=" + Rsa2048Key, 2048)]
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519", 256)]
        public void TestKeySize(string value, int expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.KeySize, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=" + Rsa512Key)]               // Below the RFC 8301 minimum of 1024 bits
        [TestCase("v=DKIM1; p=7JWI64WVIQ==")]               // Valid base64 but not a DER encoded RSA key
        [TestCase("v=DKIM1; p=" + Ed25519Key)]              // An ed25519 key is not a valid RSA key
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=ed25519")]  // An RSA key is not a raw 32 byte ed25519 key
        [TestCase("v=DKIM1; p=AAAA; k=ed25519")]            // 3 bytes, not a 32 byte ed25519 key
        public void TestInvalidKeyData(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
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
        [TestCase("v=DKIM1; p=" + RsaKey, "rsa")]                    // Absent, defaults to rsa
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=", "rsa")]                // Empty, defaults to rsa
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=rsa", "rsa")]
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519", "ed25519")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k= rsa ", "rsa")]           // Surrounding whitespace
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519;K=rsa", "ed25519")] // k is case sensitive
        public void TestKeyType(string value, string expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.KeyType, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey)]
        [TestCase("v = DKIM1 ; p=" + RsaKey)]        // Whitespace around = is allowed
        [TestCase("k=rsa; p=" + RsaKey)]             // Version tag is optional
        [TestCase("p=" + RsaKey)]
        public void TestVersionTag(string value)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
        }

        [Test]
        [TestCase("v=DKIM2; p=" + RsaKey)]           // Version must be exactly DKIM1
        [TestCase("v=DKIM1extra; p=" + RsaKey)]
        [TestCase("v=dkim1; p=" + RsaKey)]           // Case sensitive
        [TestCase("v=; p=" + RsaKey)]
        [TestCase("p=" + RsaKey + "; v=DKIM1")]           // Version must be the first tag
        public void TestInvalidVersionTag(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        public void TestLookupWithoutVersionTag()
        {
            var resolver = new DummyResolver("test._domainkey.business.nl", "k=rsa; p=" + RsaKey);
            var check = new DkimCheck(resolver);

            var record = check.GetDkimRecord("business.nl", "test");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
        }

        [Test]
        public void TestLookupIgnoresUnrelatedRecords()
        {
            // Unrelated TXT records on the same name should not count as DKIM records
            var resolver = new DummyResolver("test._domainkey.business.nl", new string[]
            {
                "google-site-verification=abc123",
                "v=DKIM1; p=" + RsaKey
            });
            var check = new DkimCheck(resolver);

            var record = check.GetDkimRecord("business.nl", "test");

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + ";")]          // A trailing semicolon is allowed
        [TestCase("v=DKIM1; p=" + RsaKey + "; ")]
        public void TestTrailingSemicolon(string value)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.PublicKey, Is.EqualTo(RsaKey));
        }

        [Test]
        public void TestWhitespaceAroundColons()
        {
            // Folding whitespace around colons is allowed in tag lists (RFC 6376 section 3.6.1)
            var record = DkimCheck.ParseDkimRecord("v=DKIM1; h=sha1 : sha256; t=y : s; s= email : * ; p=" + RsaKey);

            Assert.That(record.Algorithms, Is.EqualTo(new[] { "sha1", "sha256" }));
            Assert.That((record.Flags & DkimFlags.Testing) != 0, Is.True);
            Assert.That((record.Flags & DkimFlags.SameDomain) != 0, Is.True);
            Assert.That(record.ServiceType, Is.EqualTo(new[] { "email", "*" }));
        }

        [Test]
        [TestCase("v=DKIM1; 3=x; p=" + RsaKey)]      // A tag name must start with a letter (RFC 6376 section 3.2)
        [TestCase("v=DKIM1; a-b=x; p=" + RsaKey)]    // Only letters, digits and underscores
        [TestCase("v=DKIM1; a b=x; p=" + RsaKey)]
        public void TestInvalidTagName(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; garbage; p=" + RsaKey)]  // Segments must be tag=value pairs
        [TestCase("v=DKIM1; p=" + RsaKey + "; garbage")]
        [TestCase("v=DKIM1;; p=" + RsaKey)]          // Empty segment in the middle of the record
        [TestCase("v=DKIM1; p=" + RsaKey + "; =value")]   // Tag without a name
        public void TestMalformedTag(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=email", new[] { "email" })]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=*", new[] { "*" })]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=email:*", new[] { "email", "*" })]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s= email : * ", new[] { "email", "*" })] // Whitespace around colons is allowed
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=tlsrpt:email", new[] { "tlsrpt", "email" })] // Unrecognized types are ignored
        [TestCase("v=DKIM1; p=" + RsaKey, new[] { "*" })] // Absent, defaults to all service types
        public void TestServiceType(string value, string[] expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.ServiceType, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=")]           // Empty list does not include email
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=web")]        // Record does not apply to email
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=tlsrpt")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=EMAIL")]      // Case sensitive
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=Email")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; s=e mail")]
        public void TestInvalidServiceType(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha1", new[] { "sha1" })]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha256", new[] { "sha256" })]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha1:sha256", new[] { "sha1", "sha256" })]
        [TestCase("v=DKIM1; p=" + RsaKey, new string[0])] // Absent, all algorithms allowed
        public void TestHashAlgorithms(string value, string[] expected)
        {
            var record = DkimCheck.ParseDkimRecord(value);

            Assert.That(record, Is.Not.Null);
            Assert.That(record.Algorithms, Is.EqualTo(expected));
        }

        [Test]
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519; h=sha256")]
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519; h=sha1:sha256")] // sha256 is allowed, sha1 is just ignored
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519")]                // Absent, all algorithms allowed
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=rsa; h=sha1")]            // Only invalid for ed25519 keys
        public void TestKeyTypeHashConsistency(string value)
        {
            Assert.DoesNotThrow(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; k=ed25519; h=sha1")] // An ed25519 key can only be used with sha256 (RFC 8463)
        [TestCase("v=DKIM1; p=" + Ed25519Key + "; h=sha1; k=ed25519")] // Tag order does not matter
        public void TestInvalidKeyTypeHashCombination(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=")]              // Empty list is invalid
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=SHA256")]        // Case sensitive
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=Sha1")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha512")]        // Not a registered algorithm
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=md5")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha1:")]         // Empty list entry
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha1::sha256")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; h=sha 256")]
        public void TestInvalidHashAlgorithm(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }

        [Test]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=RSA")] // Case sensitive
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=Ed25519")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=r sa")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=dsa")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=ed448")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=rsa2048")]
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=ED25519;K=rsa")] // k is case sensitive
        [TestCase("v=DKIM1; p=" + RsaKey + "; K=ed25519;k=aap")] // k is case sensitive
        [TestCase("v=DKIM1; p=" + RsaKey + "; k=ed25519;k=rsa")] // k is case sensitive
        public void TestInvalidKeyType(string value)
        {
            Assert.Throws<DkimInvalidException>(() =>
            {
                DkimCheck.ParseDkimRecord(value);
            });
        }
    }
}
