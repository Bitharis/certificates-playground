// See https://aka.ms/new-console-template for more information
using CertificateService;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

Console.WriteLine("Create a Root CA");

var caService = new CARootService();

string passphrase = "some-random-passphrase-for-protection";

var rootCA = caService.GenerateCAroot();

var certificateBytes = caService.ConvertCARootToByteArray(rootCA, passphrase);

var result = caService.GetCARootFromByteArray(certificateBytes,passphrase);

//Console.WriteLine(result);

foreach (X509Extension extension in result.Extensions)
{
    Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");

    if (extension.Oid.FriendlyName == "Key Usage")
    {
        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
        Console.WriteLine(ext.KeyUsages);
    }

    if (extension.Oid.FriendlyName == "Basic Constraints")
    {
        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
        Console.WriteLine(ext.CertificateAuthority);
        Console.WriteLine(ext.HasPathLengthConstraint);
        Console.WriteLine(ext.PathLengthConstraint);
    }

    if (extension.Oid.FriendlyName == "Subject Key Identifier")
    {
        X509SubjectKeyIdentifierExtension ext = (X509SubjectKeyIdentifierExtension)extension;
        Console.WriteLine(ext.SubjectKeyIdentifier);
    }

    if (extension.Oid.FriendlyName == "Authority Key Identifier")
    {
        Console.WriteLine(extension.Format(true));
    }


    if (extension.Oid.FriendlyName == "Enhanced Key Usage")
    {
        X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
        OidCollection oids = ext.EnhancedKeyUsages;
        foreach (Oid oid in oids)
        {
            Console.WriteLine(oid.FriendlyName + "(" + oid.Value + ")");
        }
    }

    Console.WriteLine("---------------------------------------------");


}
