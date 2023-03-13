using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Discount.AzureFunc.JWTGenerator
{
    internal class TokenHandler
    {
        private static readonly string issuer = "CRM";
        private static readonly string audience = "API-GW";
        private static readonly int defaultExpirationInSeconds = 60;
        private static readonly string sub = "Authentication-to-internal-APIs";

        public string GetTokenBySecretFromVault(string clientId, string clerkId, ILogger log)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim("sub", sub),
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim("clerkID", clerkId)
            };

            if (!string.IsNullOrWhiteSpace(clientId))
                claims.Add(new Claim("clientId", clientId));
            
            DateTime utc0 = new DateTime(1970, 1, 1);
            var issuedAt = (int)DateTime.UtcNow.Subtract(utc0).TotalSeconds;
            claims.Add(new Claim("iat", issuedAt.ToString(), ClaimValueTypes.Integer));
           
            return GetTokenByPrivateKey(claims, log);
        }

        private string GetTokenByPrivateKey(List<Claim> claims, ILogger log)
        {
            SecurityKey privateKey = CertificateHandler.GetPrivateKeyFromVault(log);
 
            var jwtToken = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                //notBefore: DateTime.Now,
                expires: DateTime.Now.AddSeconds(defaultExpirationInSeconds),
                signingCredentials: new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256));

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            return tokenHandler.WriteToken(jwtToken);
        }

        private List<Claim> GetAdditionalClaims(string clientId, string clerkId)
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim("sub", sub),
                new Claim("jti", Guid.NewGuid().ToString()),
                new Claim("clerkID", clerkId)
            };

            if (!string.IsNullOrWhiteSpace(clientId))
                claims.Add(new Claim("clientId", clientId));

            DateTime utc0 = new DateTime(1970, 1, 1);
            var issuedAt = (int)DateTime.UtcNow.Subtract(utc0).TotalSeconds;
            claims.Add(new Claim("iat", issuedAt.ToString(), ClaimValueTypes.Integer));

            return claims;
        }


    }

}
