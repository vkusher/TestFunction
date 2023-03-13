using System;
using System.Security.Cryptography.X509Certificates;

using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging;

using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Discount.AzureFunc.JWTGenerator
{
    internal static class CertificateHandler
    {
        private static SecurityKey skey;

        public static SecurityKey GetPrivateKeyFromVault(ILogger log)
        {
            if (skey == null)
            {
                DateTime start = DateTime.Now;

                var vaultName = Environment.GetEnvironmentVariable("DBankCertificateVaultName");
                var akvUri = $"https://{vaultName}.vault.azure.net";

                var kvClient = new SecretClient(new Uri(akvUri), new ManagedIdentityCredential());

                var secretName = Environment.GetEnvironmentVariable("DBankCertificateSecretName");
                var secret = kvClient.GetSecretAsync(secretName).GetAwaiter().GetResult();

                byte[] certBase64 = Convert.FromBase64String(secret.Value.Value);

                if (certBase64.Length == 0)
                    throw new Exception("Certificate length is 0");

                var certCollection = new X509Certificate2Collection();
                certCollection.Import(certBase64, "", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
                if (certCollection.Count > 0)
                {
                    X509Certificate2 pfx = certCollection[certCollection.Count - 1];
                    var rsa = pfx.GetRSAPrivateKey();
                    skey = new RsaSecurityKey(rsa);
                }

                TimeSpan totalTime = DateTime.Now.Subtract(start);
                log?.LogInformation($"Get private key from AKV: {totalTime.Seconds:00}.{totalTime.Milliseconds:000}");
            }

            return skey;
        }
    }
}
