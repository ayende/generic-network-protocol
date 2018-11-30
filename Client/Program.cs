using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Client
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, 4433);
            using (var stream = tcpClient.GetStream())
            using (var ssl = new SslStream(stream, leaveInnerStreamOpen: false,
                userCertificateValidationCallback: 
                    (object sender, X509Certificate certificate, 
                     X509Chain chain, SslPolicyErrors sslPolicyErrors) => true
                     ))
            {
                var cert = new X509CertificateCollection();
                cert.Add(new X509Certificate2(@"C:\Users\ayende\source\repos\ConsoleApplication4\Client\example.p12"));
                await ssl.AuthenticateAsClientAsync("example.com", cert, checkCertificateRevocation: false);

                var writer = new StreamWriter(ssl);
                var reader = new StreamReader(ssl);

                while (true)
                {
                    Console.WriteLine(reader.ReadLine());
                    var str = Console.ReadLine();
                    writer.WriteLine(str);
                    writer.Flush();
                }
            }
        }
    }
}
