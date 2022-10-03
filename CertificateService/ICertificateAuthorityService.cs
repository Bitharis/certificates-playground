using System.Security.Cryptography.X509Certificates;

namespace CertificateService
{
    public interface ICertificateAuthorityService
    {
        /// Generates a CA root with the properties defined here 
        /// https://www.golinuxcloud.com/add-x509-extensions-to-certificate-openssl/
        /// </summary>
        /// <param name="subjectName">subject name.</param>
        /// /// <param name="keySizeInBits">the keys size</param>
        /// <returns>The CA Root bytes.</returns>
        X509Certificate2 GenerateCertificateAuthority(string subjectName, int keySizeInBits);

        /// <summary>
        /// Generate a leaf certificate and sign it with a custom root CA.
        /// </summary>
        /// <param name="certificateAuthorityRoot">The root certificate to be used for signing it.</param>
        /// <param name="keyBitSize">the keys size</param>
        /// <param name="subjectName">subject name.</param>
        X509Certificate2 GenerateLeafCertificate(X509Certificate2 certificateAuthorityRoot, int keyBitSize, string subjectName);

        /// <summary>
        /// Installs a root certificate to machine's Trusted Certificates store.
        /// </summary>
        void InstallCertificateToTrustStore(X509Certificate2 certificate);


        /// <summary>
        /// Exports the public part of the root certificate as a *.crt file .
        /// .cert .cer .crt - Is a .pem (or rarely .der) formatted file with a different extension,
        /// one that is recognized by Windows Explorer as a certificate, which .pem is not.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportCertificateAuthority(X509Certificate2 certificate, string destinationFolder, string filename);

        /// <summary>
        /// Exports the public and private part of the root certificate as a *.crt file.
        /// .cert .cer .crt - Is a .pem (or rarely .der) formatted file with a different extension,
        /// one that is recognized by Windows Explorer as a certificate, which .pem is not.
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="passphrase">The certificate's  passphrase.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportCertificateAuthorityKey(X509Certificate2 certificate,string passphrase, string destinationFolde, string filename);

        /// <summary>
        /// Exports the public part of the certificate on a pfx container.
        /// This is a password-protected container format that contains both public and private certificate pairs.
        /// This container is fully encrypted. 
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="passphrase">The certificate's  passphrase.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportLeafCertificate(X509Certificate2 certificate, string destinationFolder, string filename);

        /// <summary>
        /// Exports the public and private part of the certificate on a pfx container.
        /// This is a password-protected container format that contains both public and private certificate pairs.
        /// This container is fully encrypted. 
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="passphrase">The certificate's  passphrase.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportLeafCertificateKey(X509Certificate2 certificate, string passphrase, string destinationFolder, string filename);

        /// <summary>
        /// Exports a certificate on a *.pem container.
        /// pem - Defined in RFC 1422 (part of a series from 1421 through 1424) 
        /// this is a container format that may include just the public certificate (such as with Apache installs, and CA certificate files /etc/ssl/certs),
        /// or may include an entire certificate chain including public key, private key, and root certificates. 
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="passphrase">The certificate's  passphrase.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportCertificatePem(byte[] certificate, string destinationFolder, string filename);

        /// <summary>
        /// Exports a certificate on a *.pem container including the private key.
        /// pem - Defined in RFC 1422 (part of a series from 1421 through 1424) 
        /// this is a container format that may include just the public certificate (such as with Apache installs, and CA certificate files /etc/ssl/certs),
        /// or may include an entire certificate chain including public key, private key, and root certificates. 
        /// </summary>
        /// <param name="certificate">The certificate.</param>
        /// <param name="passphrase">The certificate's  passphrase.</param>
        /// <param name="destinationFolder">The folder to save the file.</param>
        /// <param name="filename">The name of the file wihtout the extension.</param>
        void ExportCertificateKeyPem(byte[] certificate, string passphrase, string destinationFolder, string filename);

        /// <summary>
        /// Export the certificate as byte array, include private key.
        /// </summary>
        /// <param name="certificate"></param>
        /// <param name="passphrase"></param>
        /// <returns></returns>
        byte[] ExportCertificateKeyAsBytes(X509Certificate2 certificate, string passphrase);

        /// <summary>
        /// Export the certificate as byte array.
        /// </summary>
        /// <param name="certificate"></param>
        /// <returns></returns>
        byte[] ExportCertificateAsBytes(X509Certificate2 certificate);

    }
}