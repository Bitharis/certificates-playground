// See https://aka.ms/new-console-template for more information
using CertificateService;
using CertificateService.Private;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Security.Cryptography.X509Certificates;

using IHost host = 
    Host.CreateDefaultBuilder(args)
    .ConfigureServices((_, services) => services.AddSingleton<ICertificateAuthorityService, CertificateAuthorityService>())
    .Build();

Run(host.Services);

await host.StartAsync();

void Run(IServiceProvider services)
{
    ICertificateAuthorityService caService = ResolveCaService(services);

    string passphrase = "some-random-passphrase-for-protection";
    int RootCAkeySizeInBits = 4096;
    int CertKeyBitSize = 2048;
    string CaSubjectName = @"CN=Experimental Issuing Authority";
    string DestinationFolder = @"C:\Certs\";

    Console.WriteLine("Creating root certificate for Experimental Issuing Authority...");
    X509Certificate2 rootCertificate = caService.GenerateCertificateAuthority(CaSubjectName, RootCAkeySizeInBits);
    Console.WriteLine("Finished creating the root certificate.");

    Console.WriteLine("Creating leaf certificate for WebApplication-X...");
    X509Certificate2 webApplicationXleafCertificate = caService.GenerateLeafCertificate(rootCertificate, CertKeyBitSize, "CN=WebApplication-X-Leaf-Certificate");
    Console.WriteLine("Finished creating the leaf certificate for WebApplication-X.");

    Console.WriteLine("Export root certificate as experimental-issuing-authority.crt - public key only.");
    caService.ExportCertificateAuthority(rootCertificate, DestinationFolder, "experimental-issuing-authority");

    Console.WriteLine("Export leaf certificate as web-application-x.pfx");
    caService.ExportLeafCertificateKey(webApplicationXleafCertificate, passphrase, DestinationFolder, "web-application-x");

    Console.WriteLine("Install root certificate experimental-issuing-authority.crt to trust store.");
    caService.InstallCertificateToTrustStore(rootCertificate);


    Console.WriteLine("Export ca-certificate.pem and ca-certificate.key.pem");

    var root = caService.ExportCertificateKeyAsBytes(rootCertificate, passphrase);
    caService.ExportCertificateKeyPem(root, passphrase, DestinationFolder, "ca-certificate");

    root = caService.ExportCertificateAsBytes(rootCertificate);
    caService.ExportCertificatePem(root, DestinationFolder, "ca-certificate");

    Console.WriteLine("Create and export server-certificate.pem and server-certificate.key.pem");
    var serverCertificate = caService.GenerateLeafCertificate(rootCertificate, CertKeyBitSize, "CN=WebApplication-X-Leaf-Certificate");
    var cert = caService.ExportCertificateKeyAsBytes(serverCertificate, passphrase);
    caService.ExportCertificateKeyPem(cert, passphrase, DestinationFolder, "server-certificate");
    cert = caService.ExportCertificateAsBytes(serverCertificate);
    caService.ExportCertificatePem(root, DestinationFolder, "server-certificate");

    Console.WriteLine("Create and export client-certificate.pem and client-certificate.key.pem");
    var clientCertificate = caService.GenerateLeafCertificate(rootCertificate, CertKeyBitSize, "CN=WebApplication-X-Leaf-Certificate");
    var cert2 = caService.ExportCertificateKeyAsBytes(clientCertificate, passphrase);
    caService.ExportCertificateKeyPem(cert2, passphrase, DestinationFolder, "client-certificate");
    cert = caService.ExportCertificateAsBytes(clientCertificate);
    caService.ExportCertificatePem(root, DestinationFolder, "client-certificate");






}

ICertificateAuthorityService ResolveCaService(IServiceProvider services)
{
    var serviceScope = services.CreateScope();
    IServiceProvider provider = serviceScope.ServiceProvider;
    var caService = provider.GetRequiredService<ICertificateAuthorityService>();
    return caService;
}