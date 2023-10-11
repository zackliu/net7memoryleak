using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Net.Http;
using System.Text;
using System.Collections.Concurrent;

namespace ClientSide
{
    internal class Program
    {
        static long i = 0;
        static volatile bool running = true;

        static void Main(string[] args)
        {
            Task.Run(() =>
            {
                while (true)
                {
                    var result = Console.ReadLine();
                    running = false;
                    GC.Collect(2, GCCollectionMode.Aggressive);
                }
            });
            RunAsync().GetAwaiter().GetResult();
        }

        static async Task RunAsync()
        {
            var cert = CertificateHelper.GetCertificate(Convert.FromBase64String(""));

            var count = 0;
            while (running)
            {
                _ = Task.Run(() => DoRequest(cert));
                if (count++ % 1 == 0)
                {
                    await Task.Delay(1);
                }
            }
        }

        static async Task DoRequest(X509Certificate2 cert)
        {
            var handler = new HttpClientHandler();
            try
            {
                var count = Interlocked.Increment(ref i);
                if (count % 100 == 0)
                {
                    Console.WriteLine($"Done {count}");
                }
                handler.ClientCertificates.Add(cert);
                var httpclient = new HttpClient(handler, disposeHandler: false);
                await httpclient.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("https://localhost:7251/test")));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                handler.Dispose();
            }
        }

        private static X509Certificate2 buildSelfSignedServerCertificate()
        {
            const string CertificateName = "localhost";
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddDnsName(Environment.MachineName);

            X500DistinguishedName distinguishedName = new X500DistinguishedName($"CN={CertificateName}");

            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));


                request.CertificateExtensions.Add(
                   new X509EnhancedKeyUsageExtension(
                       new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
                certificate.FriendlyName = CertificateName;

                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "WeNeedASaf3rPassword"), "WeNeedASaf3rPassword", X509KeyStorageFlags.MachineKeySet);
            }
        }
    }

    public static class CertificateHelper
    {
        private static readonly ConcurrentDictionary<string, object?> _cache = new();

        public static X509Certificate2 GetCertificate(string certPath)
        {
            if (string.IsNullOrEmpty(certPath))
            {
                throw new ArgumentNullException(nameof(certPath));
            }

            var certBytes = File.ReadAllBytes(certPath);
            return GetCertificate(certBytes);
        }

        public static X509Certificate2 GetCertificate(byte[] certBytes)
        {
            // Check if the cert chain is already cached
            var hash = string.Create(256 / 8 * 2, certBytes, (c, b) => HashUtils.Sha256(b, c));
            if (_cache.TryGetValue(hash, out _))
            {
                return new X509Certificate2(certBytes);
            }

            // Cache the cert chain into dotnet cert store
            // To workaround https://github.com/dotnet/aspnetcore/issues/21183#issuecomment-628712171
            var cert2Collection = new X509Certificate2Collection();
            cert2Collection.Import(certBytes);

            using (X509Store store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser, OpenFlags.ReadWrite))
            {
                foreach (X509Certificate2 cert in cert2Collection)
                {
                    if (!cert.HasPrivateKey)
                    {
                        store.Add(cert);
                    }
                }
            }

            _cache.TryAdd(hash, null);

            return new X509Certificate2(certBytes);
        }
    }

    public static class HashUtils
    {
        private const string Hex = "0123456789abcdef";
        private const int Sha256BinaryLength = 256 / 8;
        private const int Sha256HexLength = Sha256BinaryLength * 2;

        public static void Sha256(Span<byte> content, Span<byte> hash)
        {
            if (hash.Length < Sha256BinaryLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256BinaryLength}.", nameof(hash));
            }
            SHA256.TryHashData(content, hash, out _);
        }

        public static void Sha256(Span<byte> content, Span<char> hashHex)
        {
            if (hashHex.Length < Sha256HexLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256HexLength}.", nameof(hashHex));
            }
            Span<byte> binary = stackalloc byte[Sha256BinaryLength];
            Sha256(content, binary);
            ToHex(binary, hashHex);
        }

        public static void Sha256(string utf8Text, Span<char> hashHex)
        {
            ArgumentNullException.ThrowIfNull(utf8Text);
            if (hashHex.Length < Sha256BinaryLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256BinaryLength}.", nameof(hashHex));
            }
            var length = Encoding.UTF8.GetByteCount(utf8Text);
            Span<byte> content = length <= 128 ? stackalloc byte[length] : new byte[length];
            Encoding.UTF8.GetBytes(utf8Text, content);
            Sha256(content, hashHex);
        }

        public static string Sha256(string utf8Text)
        {
            ArgumentNullException.ThrowIfNull(utf8Text);
            Span<char> hash = stackalloc char[Sha256HexLength];
            Sha256(utf8Text, hash);
            return new string(hash);
        }

        public static bool VerifySha256(string utf8Text, string hashHex)
        {
            ArgumentNullException.ThrowIfNull(utf8Text);
            ArgumentNullException.ThrowIfNull(hashHex);
            Span<char> expected = stackalloc char[Sha256HexLength];
            Sha256(utf8Text, expected);
            for (int i = 0; i < Sha256HexLength; i++)
            {
                if (expected[i] != hashHex[i] &&
                    expected[i] != char.ToLowerInvariant(hashHex[i]))
                {
                    return false;
                }
            }
            return true;
        }

        public static void HMACSha256(byte[] key, Span<byte> content, Span<byte> hash)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (hash.Length < Sha256BinaryLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256BinaryLength}.", nameof(hash));
            }
            using var hmac = new HMACSHA256(key);
            hmac.TryComputeHash(content, hash, out _);
        }

        public static void HMACSha256(byte[] key, Span<byte> content, Span<char> hashHex)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (hashHex.Length < Sha256HexLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256HexLength}.", nameof(hashHex));
            }
            Span<byte> binary = stackalloc byte[Sha256BinaryLength];
            HMACSha256(key, content, binary);
            ToHex(binary, hashHex);
        }

        public static void HMACSha256(byte[] key, string utf8Text, Span<char> hashHex)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (utf8Text == null)
            {
                throw new ArgumentNullException(nameof(utf8Text));
            }
            if (hashHex.Length < Sha256BinaryLength)
            {
                throw new ArgumentException($"Too small, expected {Sha256BinaryLength}.", nameof(hashHex));
            }
            var length = Encoding.UTF8.GetByteCount(utf8Text);
            Span<byte> content = length <= 128 ? stackalloc byte[length] : new byte[length];
            Encoding.UTF8.GetBytes(utf8Text, content);
            HMACSha256(key, content, hashHex);
        }

        public static string HMACSha256(byte[] key, string utf8Text)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(utf8Text);
            Span<char> hash = stackalloc char[Sha256HexLength];
            HMACSha256(key, utf8Text, hash);
            return new string(hash);
        }

        public static bool VerifyHMACSha256(byte[] key, string utf8Text, string hashHex)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(utf8Text);
            if (hashHex?.Length != Sha256HexLength)
            {
                return false;
            }
            Span<char> expected = stackalloc char[Sha256HexLength];
            HMACSha256(key, utf8Text, expected);
            for (int i = 0; i < Sha256HexLength; i++)
            {
                if (expected[i] != hashHex[i] &&
                    expected[i] != char.ToLowerInvariant(hashHex[i]))
                {
                    return false;
                }
            }
            return true;
        }

        private static void ToHex(Span<byte> binary, Span<char> hex)
        {
            for (int i = 0; i < binary.Length; i++)
            {
                hex[i * 2] = Hex[binary[i] >> 4];
                hex[i * 2 + 1] = Hex[binary[i] & 0x0f];
            }
        }
    }

}