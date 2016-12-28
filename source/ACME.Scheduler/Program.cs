using ACMESharp;
using ACMESharp.ACME;
using ACMESharp.HTTP;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using Fclp;
using Serilog;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ACME.Scheduler
{
    class Program
    {
        const string SIGNER_FILE = "\\signer.rsakey";
        const string REGISTRATION_FILE = "\\registration.json";
        const string ACME_API_PROD = "https://acme-v01.api.letsencrypt.org/";
        const string ACME_API_STAGING = "https://acme-staging.api.letsencrypt.org/";
        const string SERVER_UP_STRING = "up";
        const string WEBCONFIG_PATH = "/../web.config";

        static string PathSignerFile = string.Empty;
        static string PathRegistrationFile = string.Empty;
        static string ACME_API = string.Empty;

        static void Main(string[] args)
        {
            var p = new FluentCommandLineParser<Arguments>();
            p.SetupHelp("?", "help").Callback(help => Console.WriteLine(help));
            p.Setup(arg => arg.Email).As('e', "email").Required();
            p.Setup(arg => arg.WorkFolder).As('w', "work-folder").Required();
            p.Setup(arg => arg.Domain).As('d', "domain").Required();
            p.Setup(arg => arg.CertificateBits).As('b', "bits").Required();
            p.Setup(arg => arg.Ftp).As('f', "ftp").Required();
            p.Setup(arg => arg.FtpRoot).As('r', "root").SetDefault(new List<string>() { "", "" });
            p.Setup(arg => arg.Username).As('u', "username").Required();
            p.Setup(arg => arg.Password).As('p', "password").Required();
            p.Setup(arg => arg.DebugMode).As('x', "debug").SetDefault(false);
            p.Setup(arg => arg.Staging).As('s', "staging").SetDefault(false);

            var result = p.Parse(args);

            if (!result.HasErrors)
            {
                try
                {
                    var arguments = p.Object;
                    PathSignerFile = $"{arguments.WorkFolder}{SIGNER_FILE}";
                    PathRegistrationFile = $"{arguments.WorkFolder}{REGISTRATION_FILE}";

                    var ftpCount = arguments.Ftp.Count;

                    if (ftpCount == arguments.FtpRoot.Count
                        && ftpCount == arguments.Username.Count
                        && ftpCount == arguments.Password.Count)
                    {
                        var ftpList = new List<FtpInfo>(ftpCount);
                        for (int i = 0; i < ftpCount; i++)
                        {
                            ftpList.Add(new FtpInfo(
                                arguments.Ftp[i],
                                arguments.FtpRoot[i],
                                arguments.Username[i],
                                arguments.Password[i]
                            ));
                        }

                        var logger = new LoggerConfiguration()
                            .WriteTo.ColoredConsole()
                            .WriteTo.RollingFile("logs/log-{Date}.txt");

                        if (arguments.DebugMode)
                            logger.MinimumLevel.Debug();
                        else
                            logger.MinimumLevel.Information();

                        Log.Logger = logger.CreateLogger();

                        ACME_API = arguments.Staging 
                            ? ACME_API_STAGING 
                            : ACME_API_PROD;

                        var settings = new Settings(
                            arguments.WorkFolder,
                            arguments.Domain,
                            arguments.Email,
                            arguments.CertificateBits,
                            ftpList
                        );

                        StartProcess(settings);
                    }
                }
                catch (AcmeClient.AcmeWebException acmeEx)
                {
                    Log.Error(acmeEx, "Erro no processo de obtenção de certificados");
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Erro no processo de obtenção de certificados");
                }
            }
        }

        static void StartProcess(Settings args)
        {
            Log.Information("------------------[Inicio de Processo]------------------");
            if (!Directory.Exists(args.WorkFolder))
                Directory.CreateDirectory(args.WorkFolder);

            using (var signer = new RS256Signer())
            {
                signer.Init();

                if (File.Exists(PathSignerFile))
                {
                    using (var signerStream = File.OpenRead(PathSignerFile))
                        signer.Load(signerStream);
                }

                using (var client = new AcmeClient(
                    new Uri(ACME_API),
                    new AcmeServerDirectory(),
                    signer
                ))
                {
                    Log.Information($"Configurando client para o letsencrypt ({ACME_API})");
                    SetupAcmeClient(client, signer, PathRegistrationFile, PathSignerFile, args.Email);

                    Log.Information("Solicitando desafio");
                    var tuple = RequestChallengeFile(client, args.Domain);

                    var httpChallenge = tuple.Item1;
                    var state = tuple.Item2;
                    var challenge = httpChallenge.Challenge as HttpChallenge;
                    var filePath = RetrieveChallengePath(challenge);

                    foreach (var ftp in args.FtpList)
                    {
                        Log.Information($"Iniciando processo de envio de desafio para: {ftp.URI}");
                        var uri = new Uri($"{ftp.URI}{ftp.Root}{filePath}");
                        var webConfigUri = new Uri($"{uri.AbsoluteUri}{WEBCONFIG_PATH}");
                        var credentials = new NetworkCredential(ftp.Username, ftp.Password);

                        Log.Information("Criando diretórios no FTP");
                        SetupDirectories(uri, credentials);

                        Log.Information($"Fazendo o upload do desafio: {uri.AbsoluteUri}");
                        Upload(uri, credentials, challenge);
                        Log.Information($"Fazendo o upload de web.config para habilitar url sem extensão e retorno em json: {uri.AbsoluteUri}");
                        Upload(webConfigUri, credentials, File.ReadAllText("web.config"));
                    }

                    Log.Information("Iniciando desafio...");
                    ApplyToChallenge(client, httpChallenge, state);

                    Log.Information("Recuperando certificados gerados");
                    RetrieveCertificates(client, ACME_API, args.Domain, args.WorkFolder, args.CertificateBits);

                    foreach (var ftp in args.FtpList)
                    {
                        var uri = new Uri($"{ftp.URI}{ftp.Root}{filePath}");
                        var webConfigUri = new Uri($"{uri.AbsoluteUri}{WEBCONFIG_PATH}");
                        var credentials = new NetworkCredential(ftp.Username, ftp.Password);

                        Log.Information($"Iniciando processo de exclusão de desafio em: {uri.AbsoluteUri}");
                        DeleteFile(uri, credentials);
                        Log.Information($"Iniciando processo de exclusão de web.config em: {webConfigUri.AbsoluteUri}");
                        DeleteFile(webConfigUri, credentials);

                        var indexFile = filePath.LastIndexOf('/');
                        if (indexFile > -1)
                        {
                            var folderToDelete = filePath.Substring(0, indexFile);
                            DeleteFolder($"{ftp.URI}{ftp.Root}", folderToDelete, credentials);
                        }
                    }
                }
            }
        }

        static void Upload(Uri ftp, NetworkCredential credentials, HttpChallenge challenge)
        {
            Upload(ftp, credentials, challenge.FileContent);
        }

        static void Upload(Uri ftp, NetworkCredential credentials, string content)
        {
            var ftpConnection = $"{ftp.Scheme}://{ftp.Host}:{ftp.Port}{ftp.AbsolutePath}";
            var request = (FtpWebRequest)WebRequest.Create(ftpConnection);
            request.Credentials = credentials;
            request.Method = WebRequestMethods.Ftp.UploadFile;

            if (ftp.Scheme == "ftps")
                request.EnableSsl = request.UsePassive = true;

            using (var stream = new MemoryStream())
            using (var writer = new StreamWriter(stream))
            {
                using (var requestStream = request.GetRequestStream())
                {
                    writer.Write(content);
                    writer.Flush();
                    stream.Position = 0;
                    stream.CopyTo(requestStream);
                }

                using (var response = (FtpWebResponse)request.GetResponse())
                {
                    var message = $"[{response.StatusCode}] :: {response.StatusDescription.Replace("\r", string.Empty).Replace("\n", string.Empty)}";
                    Log.Debug(message);
                }
            }
        }

        static void ApplyToChallenge(AcmeClient client,
            AuthorizeChallenge httpChallenge, AuthorizationState state)
        {
            state.Challenges = new AuthorizeChallenge[] { httpChallenge };
            client.SubmitChallengeAnswer(state, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

            while (state.Status == "pending")
            {
                Log.Debug("Aguardando a identificação do desafio...");
                Thread.Sleep(5000);
                var newState = client.RefreshIdentifierAuthorization(state);
                if (newState.Status != "pending")
                    state = newState;
            }
        }

        static void DeleteFile(Uri ftp, NetworkCredential credentials)
        {
            var ftpConnection = $"{ftp.Scheme}://{ftp.Host}:{ftp.Port}{ftp.AbsolutePath}";
            var request = (FtpWebRequest)WebRequest.Create(ftpConnection);
            request.Method = WebRequestMethods.Ftp.DeleteFile;
            request.Credentials = credentials;

            if (ftp.Scheme == "ftps")
                request.EnableSsl = request.UsePassive = true;

            using (var response = (FtpWebResponse)request.GetResponse())
            {
                var message = $"[{response.StatusCode}] :: {response.StatusDescription.Replace("\r", string.Empty).Replace("\n", string.Empty)}";
                Log.Debug(message);
            }
        }

        static void DeleteFolder(string ftpUri, string root, NetworkCredential credentials)
        {
            var indexExclusions = root.Count(w => w == '/');
            var actual = indexExclusions;

            while (!string.IsNullOrEmpty(root))
            {
                var ftp = new Uri(
                    $"{ftpUri}{root}"
                );

                var lastChar = root.LastIndexOf('/');
                var item = lastChar >= 0
                    ? root.Substring(lastChar)
                    : root;

                var nextUri = root.Substring(0, root.Length - item.Length);

                var request = (FtpWebRequest)WebRequest.Create(ftp);
                request.Method = WebRequestMethods.Ftp.RemoveDirectory;
                request.Credentials = credentials;

                if (ftp.Scheme == "ftps")
                    request.EnableSsl = request.UsePassive = true;

                using (var response = (FtpWebResponse)request.GetResponse())
                {
                    var message = $"[{response.StatusCode}] :: {response.StatusDescription.Replace("\r", string.Empty).Replace("\n", string.Empty)}";
                    Log.Debug(message);
                }

                root = nextUri;
                actual--;
            }
        }

        static void SetupDirectories(Uri ftp, NetworkCredential credentials)
        {
            var directories = ftp.AbsolutePath.Split(
                new char[] { '/' },
                StringSplitOptions.RemoveEmptyEntries
            );

            var ftpConnection = $"{ftp.Scheme}://{ftp.Host}:{ftp.Port}/";
            if (directories.Length > 1)
            {
                for (int i = 0; i < directories.Length - 1; i++) // ignorar o arquivo final fornecido pela letsencrypt
                {
                    ftpConnection = $"{ftpConnection}{directories[i]}/";
                    var request = (FtpWebRequest)WebRequest.Create(ftpConnection);
                    request.Method = WebRequestMethods.Ftp.MakeDirectory;
                    request.Credentials = credentials;

                    if (ftp.Scheme == "ftps")
                        request.EnableSsl = request.UsePassive = true;

                    try
                    {
                        using (var response = (FtpWebResponse)request.GetResponse())
                        using (var ftpStream = response.GetResponseStream())
                        {
                            var message = $"[{response.StatusCode}] :: {response.StatusDescription.Replace("\r", string.Empty).Replace("\n", string.Empty)}";
                            Log.Debug(message);
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.Error($"Erro ao configurar o diretório {ftpConnection}", ex);
                    }
                }
            }
        }

        static void SetupAcmeClient(AcmeClient client, RS256Signer signer, string registrationFile, string signerFile, string email)
        {
            client.Init();
            client.GetDirectory(true);

            if (!File.Exists(registrationFile))
            {
                client.Register(new string[] { $"mailto:{email}" });

                using (var registrationStream = File.OpenWrite(registrationFile))
                    client.Registration.Save(registrationStream);
            }

            using (var registrationStream = File.OpenRead(registrationFile))
                client.Registration = AcmeRegistration.Load(registrationStream);

            client.UpdateRegistration(true, true);

            using (var signerStream = File.OpenWrite(signerFile))
                signer.Save(signerStream);
        }

        static Tuple<AuthorizeChallenge, AuthorizationState> RequestChallengeFile(
            AcmeClient client, string domain)
        {
            var state = client.AuthorizeIdentifier(domain);
            var challenge = client.DecodeChallenge(state, AcmeProtocol.CHALLENGE_TYPE_HTTP);
            var httpChallenge = challenge.Challenge as HttpChallenge;

            return new Tuple<AuthorizeChallenge, AuthorizationState>(challenge, state);
        }

        static string RetrieveChallengePath(HttpChallenge challenge)
        {
            var filePath = challenge.FilePath;
            if (filePath.StartsWith("/", StringComparison.OrdinalIgnoreCase))
                filePath = filePath.Substring(1);

            return filePath;
        }

        static void RetrieveCertificates(AcmeClient client, string api, string domain, string certificatesFolder, int certBits)
        {
            var cp = CertificateProvider.GetProvider();
            var rsaPkp = new RsaPrivateKeyParams() { NumBits = certBits };

            var rsaKeys = cp.GeneratePrivateKey(rsaPkp);
            var csrParams = new CsrParams
            {
                Details = new CsrDetails { CommonName = domain }
            };

            var derRaw = default(byte[]);
            var csr = cp.GenerateCsr(csrParams, rsaKeys, Crt.MessageDigest.SHA256);

            using (var bs = new MemoryStream())
            {
                cp.ExportCsr(csr, EncodingFormat.DER, bs);
                derRaw = bs.ToArray();
            }

            var derB64U = JwsHelper.Base64UrlEncode(derRaw);
            var certRequ = client.RequestCertificate(derB64U);

            if (certRequ.StatusCode == HttpStatusCode.Created)
            {
                GenerateCertFiles(cp, rsaKeys, csr, certRequ, certificatesFolder, domain);
            }
        }

        static string DownloadIssuerCertificate(CertificateProvider provider,
            CertificateRequest request, string api, string certificatesFolder)
        {
            var linksEnum = request.Links;
            var isuPemFile = string.Empty;

            if (linksEnum != null)
            {
                var links = new LinkCollection(linksEnum);
                var upLink = links.GetFirstOrDefault(SERVER_UP_STRING);
                if (upLink != null)
                {
                    var temporaryFileName = Path.GetTempFileName();
                    try
                    {
                        using (var web = new WebClient())
                        {
                            var apiUri = new Uri(new Uri(api), upLink.Uri);
                            web.DownloadFile(apiUri, temporaryFileName);
                        }

                        var cacert = new X509Certificate2(temporaryFileName);
                        var sernum = cacert.GetSerialNumberString();

                        var cacertDerFile = Path.Combine(certificatesFolder, $"ca-{sernum}-crt.der");
                        var cacertPemFile = Path.Combine(certificatesFolder, $"ca-{sernum}-crt.pem");

                        if (!File.Exists(cacertDerFile))
                            File.Copy(temporaryFileName, cacertDerFile, true);

                        if (!File.Exists(cacertPemFile))
                            using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
                                target = new FileStream(cacertPemFile, FileMode.Create))
                            {
                                var caCrt = provider.ImportCertificate(EncodingFormat.DER, source);
                                provider.ExportCertificate(caCrt, EncodingFormat.PEM, target);
                            }

                        isuPemFile = cacertPemFile;
                    }
                    finally
                    {
                        if (File.Exists(temporaryFileName))
                            File.Delete(temporaryFileName);
                    }
                }
            }

            return isuPemFile;
        }

        static void GenerateCertFiles(CertificateProvider provider, PrivateKey rsaKeys,
            Csr csr, CertificateRequest request, string certificatesFolder, string domain)
        {
            var crt = default(Crt);


            var keyGenFile = Path.Combine(certificatesFolder, $"{domain}-gen-key.json");
            Log.Debug($"Gerando arquivo: {keyGenFile}");
            using (var fs = new FileStream(keyGenFile, FileMode.Create))
                provider.SavePrivateKey(rsaKeys, fs);

            var keyPemFile = Path.Combine(certificatesFolder, $"{domain}-key.pem");
            Log.Debug($"Gerando arquivo: {keyPemFile}");
            using (var fs = new FileStream(keyPemFile, FileMode.Create))
                provider.ExportPrivateKey(rsaKeys, EncodingFormat.PEM, fs);

            var csrGenFile = Path.Combine(certificatesFolder, $"{domain}-gen-csr.json");
            Log.Debug($"Gerando arquivo: {csrGenFile}");
            using (var fs = new FileStream(csrGenFile, FileMode.Create))
                provider.SaveCsr(csr, fs);

            var csrPemFile = Path.Combine(certificatesFolder, $"{domain}-csr.pem");
            Log.Debug($"Gerando arquivo: {csrPemFile}");
            using (var fs = new FileStream(csrPemFile, FileMode.Create))
                provider.ExportCsr(csr, EncodingFormat.PEM, fs);

            var crtDerFile = Path.Combine(certificatesFolder, $"{domain}-crt.der");
            Log.Debug($"Gerando arquivo: {crtDerFile}");
            using (var file = File.Create(crtDerFile))
                request.SaveCertificate(file);

            var crtPemFile = Path.Combine(certificatesFolder, $"{domain}-crt.pem");
            var chainPemFile = Path.Combine(certificatesFolder, $"{domain}-chain.pem");

            Log.Debug($"Gerando arquivo: {crtPemFile}");
            Log.Debug($"Gerando arquivo: {chainPemFile}");
            using (FileStream source = new FileStream(crtDerFile, FileMode.Open),
                target = new FileStream(crtPemFile, FileMode.Create))
            {
                crt = provider.ImportCertificate(EncodingFormat.DER, source);
                provider.ExportCertificate(crt, EncodingFormat.PEM, target);
            }

            var pemFile = DownloadIssuerCertificate(provider, request, ACME_API, certificatesFolder);

            using (FileStream intermediate = new FileStream(pemFile, FileMode.Open),
                certificate = new FileStream(crtPemFile, FileMode.Open),
                chain = new FileStream(chainPemFile, FileMode.Create))
            {
                certificate.CopyTo(chain);
                intermediate.CopyTo(chain);
            }

            var crtPfxFile = Path.Combine(certificatesFolder, $"{domain}-all.pfx");
            Log.Debug($"Gerando arquivo: {crtPfxFile}");
            using (FileStream source = new FileStream(pemFile, FileMode.Open),
                target = new FileStream(crtPfxFile, FileMode.Create))
            {
                try
                {
                    var isuCrt = provider.ImportCertificate(EncodingFormat.PEM, source);
                    provider.ExportArchive(rsaKeys, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target, string.Empty);
                }
                catch (Exception ex)
                {
                    Log.Error($"Erro ao exportar o arquivo {crtPfxFile}", ex);
                }
            }
        }
    }

    public class FtpInfo
    {
        public FtpInfo()
        {

        }
        public FtpInfo(string uri, string root, string username, string password)
        {
            URI = uri;
            Root = root;
            Username = username;
            Password = password;
        }

        public string URI { get; set; }
        public string Root { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class Arguments
    {
        public string WorkFolder { get; set; }
        public string Domain { get; set; }
        public string Email { get; set; }
        public int CertificateBits { get; set; }
        public List<string> Ftp { get; set; }
        public List<string> FtpRoot { get; set; }
        public List<string> Username { get; set; }
        public List<string> Password { get; set; }
        public bool DebugMode { get; set; }
        public bool Staging { get; set; }
    }

    public class Settings
    {
        public Settings(string workFolder, string domain, string email,
            int certificateBits, List<FtpInfo> ftpList)
        {
            WorkFolder = workFolder;
            Domain = domain;
            Email = email;
            CertificateBits = certificateBits;
            FtpList = ftpList;
        }
        public string WorkFolder { get; set; }
        public string Domain { get; set; }
        public string Email { get; set; }
        public int CertificateBits { get; set; }
        public List<FtpInfo> FtpList { get; set; }
    }
}






