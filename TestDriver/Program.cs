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
    X509Certificate2 rootCertificate = caService.GenerateRootCertificate(CaSubjectName, RootCAkeySizeInBits);
    Console.WriteLine("Finished creating the root certificate.");

    Console.WriteLine("Creating leaf certificate for WebApplication-X...");
    X509Certificate2 WebApplicationXleafCertificate = caService.GenerateLeafCertificate(rootCertificate, CertKeyBitSize, "CN=WebApplication-X-Leaf-Certificate");
    Console.WriteLine("Finished creating the leaf certificate for WebApplication-X.");

    Console.WriteLine("Export root certificate as experimental-issuing-authority.crt - public key only.");
    caService.ExportCertificateAuthorityPublic(rootCertificate, DestinationFolder, "experimental-issuing-authority");

    Console.WriteLine("Export leaf certificate as web-application-x.pfx");
    caService.ExportLeafCertificatePrivate(WebApplicationXleafCertificate, passphrase, DestinationFolder, "web-application-x");

    Console.WriteLine("Install root certificate experimental-issuing-authority.crt to trust store.");
    caService.InstallCertificateToTrustStore(rootCertificate);
}

ICertificateAuthorityService ResolveCaService(IServiceProvider services)
{
    var serviceScope = services.CreateScope();
    IServiceProvider provider = serviceScope.ServiceProvider;
    var caService = provider.GetRequiredService<ICertificateAuthorityService>();
    return caService;
}