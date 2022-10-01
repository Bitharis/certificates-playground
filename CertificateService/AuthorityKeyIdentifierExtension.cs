using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateService
{
    public class AuthorityKeyIdentifierExtension : X509Extension
    {
        private static Oid IdceAuthorityKeyIdentifier = new Oid("2.5.29.35");

        public AuthorityKeyIdentifierExtension(X509SubjectKeyIdentifierExtension subjectKeyIdentifierExtension, bool critical)
            : base(IdceAuthorityKeyIdentifier, GetRawData(subjectKeyIdentifierExtension), critical)
        {                        
        }

        private static byte[] GetRawData(X509SubjectKeyIdentifierExtension subjectKeyIdentifierExtension)
        {
            var segment = new ArraySegment<byte>(subjectKeyIdentifierExtension.RawData, 2, subjectKeyIdentifierExtension.RawData.Length - 2);

            var authorityKeyIdentifierRawData = new byte[segment.Count + 4];

            // KeyID of the AuthorityKeyIdentifier
            authorityKeyIdentifierRawData[0] = 0x30;
            authorityKeyIdentifierRawData[1] = 0x16;
            authorityKeyIdentifierRawData[2] = 0x80;
            authorityKeyIdentifierRawData[3] = 0x14;

            Array.Copy(segment.ToArray(), 0, authorityKeyIdentifierRawData, 4, segment.ToArray().Length);

            return authorityKeyIdentifierRawData;
        }
    }
}
