using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Helpers;
using Titanium.Web.Proxy.Http;
using Titanium.Web.Proxy.Models;

namespace Titanium.Web.Proxy.Examples.Basic
{
    public class ProxyTestController
    {
        readonly ProxyServer proxyServer;
        readonly Regex wuProxyRegex = new Regex(@"pxywuden0(3|4).hqintl1.com", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        //keep track of request headers
        readonly IDictionary<Guid, HeaderCollection> requestHeaderHistory = new ConcurrentDictionary<Guid, HeaderCollection>();

        //keep track of response headers
        readonly IDictionary<Guid, HeaderCollection> responseHeaderHistory = new ConcurrentDictionary<Guid, HeaderCollection>();

        //share requestBody outside handlers
        //Using a dictionary is not a good idea since it can cause memory overflow
        //ideally the data should be moved out of memory
        //private readonly IDictionary<Guid, string> requestBodyHistory = new ConcurrentDictionary<Guid, string>();

        public ProxyTestController()
        {
            proxyServer = new ProxyServer();

            //generate root certificate without storing it in file system
            proxyServer.CertificateEngine = Network.CertificateEngine.BouncyCastle;
            proxyServer.CertificateManager.CreateTrustedRootCertificate(false);
            proxyServer.CertificateManager.TrustRootCertificate();

            proxyServer.ExceptionFunc = exception => LogMessage(exception.Message);
            proxyServer.TrustRootCertificate = true;
            proxyServer.ForwardToUpstreamGateway = true;

            //optionally set the Certificate Engine
            //Under Mono or Non-Windows runtimes only BouncyCastle will be supported
            //proxyServer.CertificateEngine = Network.CertificateEngine.DefaultWindows;

            //optionally set the Root Certificate
            //proxyServer.RootCertificate = new X509Certificate2("myCert.pfx", string.Empty, X509KeyStorageFlags.Exportable);
        }

        public void StartProxy()
        {
            proxyServer.BeforeRequest += OnRequest;
            proxyServer.BeforeResponse += OnResponse;
            proxyServer.TunnelConnectRequest += OnTunnelConnectRequest;
            proxyServer.TunnelConnectResponse += OnTunnelConnectResponse;
            proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

            //proxyServer.EnableWinAuth = true;

            var explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Any, 8000, true)
            {
                //Exclude Https addresses you don't want to proxy
                //Useful for clients that use certificate pinning
                //for example google.com and dropbox.com
                ExcludedHttpsHostNameRegex = new List<string>
                {
                    "dropbox.com"
                },

                //Include Https addresses you want to proxy (others will be excluded)
                //for example github.com
                //IncludedHttpsHostNameRegex = new List<string>
                //{
                //    "github.com"
                //},

                //You can set only one of the ExcludedHttpsHostNameRegex and IncludedHttpsHostNameRegex properties, otherwise ArgumentException will be thrown
            };

            //Use self-issued generic certificate on all https requests
            //Optimizes performance by not creating a certificate for each https-enabled domain
            //Useful when certificate trust is not required by proxy clients
            //string certFilename = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "genericcert.cer");
            //if (!string.IsNullOrWhiteSpace(certFilename) && File.Exists(certFilename))
            //{
            //    explicitEndPoint.GenericCertificate = new X509Certificate2(certFilename, "PEM pass phrase");
            //};

            //An explicit endpoint is where the client knows about the existence of a proxy
            //So client sends request in a proxy friendly manner
            proxyServer.AddEndPoint(explicitEndPoint);
            proxyServer.Start();


            //Transparent endpoint is useful for reverse proxy (client is not aware of the existence of proxy)
            //A transparent endpoint usually requires a network router port forwarding HTTP(S) packets or DNS
            //to send data to this endPoint
            //var transparentEndPoint = new TransparentProxyEndPoint(IPAddress.Any, 443, true)
            //{
            //    //Generic Certificate hostname to use
            //    //When SNI is disabled by client
            //    GenericCertificateName = "google.com"
            //};

            //proxyServer.AddEndPoint(transparentEndPoint);

            //proxyServer.UpStreamHttpProxy = new ExternalProxy() { HostName = "localhost", Port = 8888 };
            //proxyServer.UpStreamHttpsProxy = new ExternalProxy() { HostName = "localhost", Port = 8888 };

            foreach (var endPoint in proxyServer.ProxyEndPoints)
                LogMessage("Listening on '{0}' endpoint at Ip {1} and port: {2} ", endPoint.GetType().Name, endPoint.IpAddress, endPoint.Port);

#if NET45
            //Only explicit proxies can be set as system proxy!
            //proxyServer.SetAsSystemHttpProxy(explicitEndPoint);
            //proxyServer.SetAsSystemHttpsProxy(explicitEndPoint);
            proxyServer.SetAsSystemProxy(explicitEndPoint, ProxyProtocolType.AllHttp);
#endif
        }

        public void Stop()
        {
            proxyServer.TunnelConnectRequest -= OnTunnelConnectRequest;
            proxyServer.TunnelConnectResponse -= OnTunnelConnectResponse;
            proxyServer.BeforeRequest -= OnRequest;
            proxyServer.BeforeResponse -= OnResponse;
            proxyServer.ServerCertificateValidationCallback -= OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback -= OnCertificateSelection;

            proxyServer.Stop();

            //remove the generated certificates
            //proxyServer.CertificateManager.RemoveTrustedRootCertificates();
        }

        async Task OnTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs e)
        {
            LogMessage("Tunnel to: " + e.WebSession.Request.Host);
        }

        async Task OnTunnelConnectResponse(object sender, TunnelConnectSessionEventArgs e)
        {
        }

        //intecept & cancel redirect or update requests
        public async Task OnRequest(object sender, SessionEventArgs e)
        {
            LogMessage("Active Client Connections:" + ((ProxyServer)sender).ClientConnectionCount);
            LogMessage(e.WebSession.Request.Url);

            if (wuProxyRegex.IsMatch(e.WebSession.Request.Host))
            {
                var builder = new UriBuilder(e.WebSession.Request.RequestUri) { Host = "pxywuden01.hqintl1.com" };
                e.WebSession.Request.RequestUri = builder.Uri;
                e.WebSession.Request.Host = builder.Uri.Host;
                LogMessage("Redirected pxywuden03.hqintl1.com to pxywuden01.hqintl1.com");
            }

            //read request headers
            requestHeaderHistory[e.Id] = e.WebSession.Request.RequestHeaders;

            if (e.WebSession.Request.HasBody)
            {
                //Get/Set request body bytes
                var bodyBytes = await e.GetRequestBody();
                await e.SetRequestBody(bodyBytes);

                //Get/Set request body as string
                string bodyString = await e.GetRequestBodyAsString();
                await e.SetRequestBodyString(bodyString);

                //requestBodyHistory[e.Id] = bodyString;
            }

            ////To cancel a request with a custom HTML content
            ////Filter URL
            //if (e.WebSession.Request.RequestUri.AbsoluteUri.Contains("google.com"))
            //{
            //    await e.Ok("<!DOCTYPE html>" +
            //          "<html><body><h1>" +
            //          "Website Blocked" +
            //          "</h1>" +
            //          "<p>Blocked by titanium web proxy.</p>" +
            //          "</body>" +
            //          "</html>");
            //}

            ////Redirect example
            //if (e.WebSession.Request.RequestUri.AbsoluteUri.Contains("wikipedia.org"))
            //{
            //    await e.Redirect("https://www.paypal.com");
            //}
        }

        static void LogMessage(string v, params object[] args)
        {
            #if _DEBUG
            Console.WriteLine(v, args);
            #endif
        }

        //Modify response
        public async Task OnResponse(object sender, SessionEventArgs e)
        {
            LogMessage("Active Server Connections:" + ((ProxyServer)sender).ServerConnectionCount);

            //if (requestBodyHistory.ContainsKey(e.Id))
            //{
            //    //access request body by looking up the shared dictionary using requestId
            //    var requestBody = requestBodyHistory[e.Id];
            //}

            //read response headers
            responseHeaderHistory[e.Id] = e.WebSession.Response.ResponseHeaders;

            // print out process id of current session
            //LogMessage($"PID: {e.WebSession.ProcessId.Value}");

            //if (!e.ProxySession.Request.Host.Equals("medeczane.sgk.gov.tr")) return;
            if (e.WebSession.Request.Method == "GET" || e.WebSession.Request.Method == "POST")
            {
                if (e.WebSession.Response.ResponseStatusCode == (int)HttpStatusCode.OK)
                {
                    if (e.WebSession.Response.ContentType != null && e.WebSession.Response.ContentType.Trim().ToLower().Contains("text/html"))
                    {
                        var bodyBytes = await e.GetResponseBody();
                        await e.SetResponseBody(bodyBytes);

                        string body = await e.GetResponseBodyAsString();
                        await e.SetResponseBodyString(body);
                    }
                }
            }
        }

        /// <summary>
        /// Allows overriding default certificate validation logic
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            //set IsValid to true/false based on Certificate Errors
            if (e.SslPolicyErrors == SslPolicyErrors.None)
            {
                e.IsValid = true;
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Allows overriding default client certificate selection logic during mutual authentication
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        public Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
        {
            //set e.clientCertificate to override

            return Task.FromResult(0);
        }
    }
}
