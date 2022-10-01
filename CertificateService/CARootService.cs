using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CertificateService
{
    /// <summary>
    /// A service that creates a CA root
    /// </summary>
    public class CARootService
    {
        private const bool IsCertificateAuthority = true;
        private const bool HasPathConstaint = true;
        private const int KeySizeInBits = 4096;
        private const string SubjectName = @"CN=Experimental Issuing Authority
OU=www.Evil-Corp.com
O=Evil corp
C=SE";
        

        /// <summary>
        /// Generates a CA Root with the properties defined here 
        /// https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/
        /// </summary>
        /// <param name="passphrase">The passphrase to protext the private key.</param>
        /// <returns>The CA Root bytes.</returns>
        public X509Certificate2 GenerateCAroot()
        {
            using (RSA parent = RSA.Create(KeySizeInBits))
            {
                CertificateRequest parentReq = new CertificateRequest(SubjectName, parent, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                parentReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(IsCertificateAuthority, HasPathConstaint, 0, true));

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

        public byte[] ConvertCARootToByteArray(X509Certificate2 rootCA, string passphrase)
        {
            return rootCA.Export(X509ContentType.Pkcs12, passphrase);
        }

        public X509Certificate2 GetCARootFromByteArray(byte[] certificateBytes, string passphrase)
        {
            X509Certificate2 rootCA = new X509Certificate2(certificateBytes, passphrase, X509KeyStorageFlags.Exportable);
            return rootCA;
        }
    }
}
