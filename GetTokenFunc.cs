using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace Discount.AzureFunc.JWTGenerator
{
    public static class GetTokenFunc
    {

        [FunctionName("GetToken")] 
        public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "get", Route = "GetToken/{clerkId}/{clientId?}")] HttpRequest req, string clientId, string clerkId, ILogger log)
        {
            TokenHandler handler = new TokenHandler();
            //try
            //{
                string token = handler.GetTokenBySecretFromVault(clientId, clerkId, log);
                return new OkObjectResult(token);
            //}
            //catch (Exception ex)
            //{
            //    log.LogInformation(ex.ToString());
            //    return new BadRequestObjectResult(ex.ToString());
            //}
        }

    }
}
