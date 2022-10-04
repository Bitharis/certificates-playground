using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificateService.Private
{
    /// <summary>
    /// A service that creates a CA root
    /// </summary>
    public class CertificateAuthorityService : ICertificateAuthorityService
    {
        private const bool IsCertificateAuthority = true;

        public X509Certificate2 GenerateCertificateAuthority(string subjectName, int keySizeInBits)
        {
            using (RSA parent = RSA.Create(keySizeInBits))
            {
                CertificateRequest parentReq = new CertificateRequest(subjectName, parent, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(IsCertificateAuthority, true, 0, true));

                // Set the subjeck key identifier
                parentReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));

                // In a CA root cert, "Authority Key Identifier" should be the same as "Subject Key Identifier".
                var skiExtension = (X509SubjectKeyIdentifierExtension)parentReq.CertificateExtensions.Where(e => e.Oid.FriendlyName == "Subject Key Identifier").SingleOrDefault();
                parentReq.CertificateExtensions.Add(new AuthorityKeyIdentifierExtension(skiExtension, false)); ;

                // Limit the usage of this certificate.
                parentReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

                X509Certificate2 rootCA = parentReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-45), DateTimeOffset.UtcNow.AddDays(365));

                return rootCA;
            }
        }

        public X509Certificate2 GenerateLeafCertificate(X509Certificate2 certificateAuthorityRoot, int keyBitSize, string subjectName, ExtendedUsage extendedUsage)
        {
            using (RSA rsa = RSA.Create(keyBitSize))
            {
                CertificateRequest req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

                req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, false));

                req.CertificateExtensions.Add(SetExtendedKeyUsage(extendedUsage));

                req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                //todo move this outside?
                SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddIpAddress(IPAddress.Loopback);
                sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
                sanBuilder.AddDnsName("localhost");
                sanBuilder.AddDnsName(Environment.MachineName);
                AddExternalIpAddress(sanBuilder);

                req.CertificateExtensions.Add(sanBuilder.Build());

                byte[] serialNumber = GenerateSerialNumber();

                X509Certificate2 cert = req.Create(
                    certificateAuthorityRoot,
                    DateTimeOffset.UtcNow.AddDays(-1),
                    DateTimeOffset.UtcNow.AddDays(90),
                    serialNumber);

                // the req.Create() above creates a certificate that doesnt include the private key. The following line fixes that.
                cert = RSACertificateExtensions.CopyWithPrivateKey(cert, rsa);

                return cert;
            }
        }

        private X509EnhancedKeyUsageExtension SetExtendedKeyUsage(ExtendedUsage extendedUsage)
        {
            switch (extendedUsage)
            {
                case ExtendedUsage.ClientAuth:
                    return new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false);
                case ExtendedUsage.ServerAuth:
                    return new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false);
                default:
                    throw new ArgumentOutOfRangeException("Unexpecte ExtendedUsage value"); 

            }
        }

        public void InstallCertificateToTrustStore(X509Certificate2 rootCertificate)
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(rootCertificate);
            store.Close();
        }

        public void ExportCertificateAuthority(X509Certificate2 certificate, string destinationFolder, string filename)
        {
            var certificateBytes = this.ExportCertificateAsBytes(certificate);
            this.ExportCertificateAsCrt(certificateBytes, destinationFolder, filename, null);
        }

        public void ExportCertificateAuthorityKey(X509Certificate2 certificate, string passphrase, string destinationFolder, string filename)
        {
            var certificateBytes = this.ExportCertificateKeyAsBytes(certificate, passphrase);
            this.ExportCertificateAsCrt(certificateBytes, destinationFolder, filename, passphrase);
        }

        public void ExportLeafCertificate(X509Certificate2 certificate, string destinationFolder, string filename)
        {
            var certificateBytes = this.ExportCertificateAsBytes(certificate);
            this.ExportCertificateAsPfx(certificateBytes, destinationFolder, filename, null);
        }

        public void ExportLeafCertificateKey(X509Certificate2 certificate, string passphrase, string destinationFolder, string filename)
        {
            var certificateBytes = this.ExportCertificateKeyAsBytes(certificate, passphrase);
            this.ExportCertificateAsPfx(certificateBytes, destinationFolder, filename, passphrase);
        }

        public void ExportCertificatePem(byte[] certificate, string destinationFolder, string filename)
        {
            using (var cert = new X509Certificate2(certificate))
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");

                if (Directory.Exists(destinationFolder) == false)
                {
                    Directory.CreateDirectory(destinationFolder);
                }

                var fullPath = Path.Combine(destinationFolder, filename + ".pem");

                if (File.Exists(fullPath) == false)
                {
                    using (var streamWriter = File.CreateText(fullPath))
                    {
                        streamWriter.Write(builder.ToString());
                    }
                }
            }
        }

        public void ExportCertificateKeyPem(byte[] certificate, string passphrase, string destinationFolder, string filename)
        {
            using (var cert = new X509Certificate2(certificate, passphrase))
            {
                StringBuilder builder = new StringBuilder();
                builder.AppendLine("-----BEGIN CERTIFICATE-----");
                builder.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
                builder.AppendLine("-----END CERTIFICATE-----");

                if (Directory.Exists(destinationFolder) == false)
                {
                    Directory.CreateDirectory(destinationFolder);
                }

                var fullPath = Path.Combine(destinationFolder, filename + ".key.pem");

                if (File.Exists(fullPath) == false)
                {
                    using (var streamWriter = File.CreateText(fullPath))
                    {
                        streamWriter.Write(builder.ToString());
                    }
                }
            }
        }

        public byte[] ExportCertificateKeyAsBytes(X509Certificate2 certificate, string passphrase)
        {
            return certificate.Export(X509ContentType.Pkcs12, passphrase);
        }

        public byte[] ExportCertificateAsBytes(X509Certificate2 certificate)
        {
            return certificate.Export(X509ContentType.Pkcs12);
        }


        private void ExportCertificateInternal(X509ContentType type, byte[] certificate, string passphrase, string destinationFolder, string filename, bool includePrivateKey)
        {
            using (var cert = includePrivateKey ? new X509Certificate2(certificate, passphrase, X509KeyStorageFlags.Exportable) : new X509Certificate2(certificate))
            {
                if(cert.HasPrivateKey == false)
                {
                    throw new Exception("private key is missing from the certificate.");
                }

                byte[] certData = includePrivateKey ? cert.Export(type, passphrase) : cert.Export(type);

                if (Directory.Exists(destinationFolder) == false)
                {
                    Directory.CreateDirectory(destinationFolder);
                }

                var fullPath = Path.Combine(destinationFolder, filename);

                File.WriteAllBytes(fullPath, certData);
            }
        }

        private void ExportCertificateAsPfx(byte[] certificate, string destinationFolder, string filename, string passphrase)
        {
            bool includePrivateKey = string.IsNullOrEmpty(passphrase) == false;
            ExportCertificateInternal(X509ContentType.Pfx, certificate, passphrase, destinationFolder, filename + ".pfx", includePrivateKey: includePrivateKey);
        }

        private void ExportCertificateAsCrt(byte[] certificate, string destinationFolder, string filename, string passphrase)
        {
            bool includePrivateKey = string.IsNullOrEmpty(passphrase) == false;
            ExportCertificateInternal(X509ContentType.Cert, certificate, passphrase, destinationFolder, filename + ".crt", includePrivateKey: includePrivateKey);
        }

        /// <summary>
        /// Gets a certificate from a byte array.
        /// </summary>
        private X509Certificate2 GetCertificateFromByteArray(byte[] certificateBytes, string passphrase)
        {
            X509Certificate2 certificate = new X509Certificate2(certificateBytes, passphrase, X509KeyStorageFlags.Exportable);
            return certificate;
        }

        private byte[] GenerateSerialNumber()
        {
            byte[] serialNumber = new Byte[20];

            //RNGCryptoServiceProvider is an implementation of a random number generator.
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(serialNumber); // The array is now filled with cryptographically strong random bytes.
            return serialNumber;
        }

        private static void AddExternalIpAddress(SubjectAlternativeNameBuilder sanBuilder)
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    Console.WriteLine(ni.Name);
                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            Console.WriteLine("Adding IP: " + ip.Address.ToString() + " to SAN.");
                            sanBuilder.AddIpAddress(ip.Address);
                        }
                    }
                }
            }
        }
    }
}
