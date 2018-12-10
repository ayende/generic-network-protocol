using System;
using System.Collections.Generic;
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

                var status = reader.ReadLine();
                if (status != "OK")
                {
                    Console.WriteLine("Connection error: " + status);
                }


                writer.Write("GET employees/1-A\r\nSequence: 32\r\n\r\n");
                writer.Flush();

                var  headers = new Dictionary<string, string>();
                status = reader.ReadLine();

                string line;

                while ((line = reader.ReadLine()) != null && line.Length > 0)
                {
                    var parts = line.Split(":");
                    headers[parts[0]] = parts[1].Trim();
                }

                string val = null;
                if (headers.TryGetValue("Size", out var sizeStr) && int.TryParse(sizeStr, out var size))
                {
                    val = string.Create(size, reader, (span, state) =>
                    {
                        state.ReadBlock(span);
                    });
                }

                if (status != "OK")
                {
                    Console.WriteLine("ERROR! " + status);
                }

                Console.WriteLine(val);

            }
        }
    }
}
