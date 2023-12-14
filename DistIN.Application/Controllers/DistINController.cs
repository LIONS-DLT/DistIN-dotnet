using DistIN.Client;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Text;
using System.Text.Json;

namespace DistIN.Application.Controllers
{
    [Route("distin")]
    public class DistINController : Controller
    {
        private static JsonSerializerOptions serializerOptions = new JsonSerializerOptions()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
        };

        private IActionResult signedObject<T>(T data)
        {
            byte[] json = Encoding.UTF8.GetBytes(JsonSerializer.Serialize<T>(data, serializerOptions));

            string signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, json);
            this.HttpContext.Response.Headers.Add("DistIN-Signature", signature);
            this.HttpContext.Response.Headers.Add("DistIN-ServiceVerificationType", AppConfig.Current.ServiceVerificationType.ToString());

            return File(json, "text/json");
        }

        public IActionResult PublicKey(string id, string? date)
        {
            if (id == null)
                return StatusCode(StatusCodes.Status400BadRequest);
            id = id.ToLower();

            if (!string.IsNullOrEmpty(date))
            {
                DateTime dateTime = DateTime.Parse(date);
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' AND [Date]<{1} ORDER BY [Date] DESC", 
                    id + "@" + AppConfig.Current.ServiceDomain, dateTime.Ticks)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return signedObject(key);
            }
            else
            {
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' ORDER BY [Date] DESC", id + "@" + AppConfig.Current.ServiceDomain)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return signedObject(key);
            }
        }

        public IActionResult ServiceVerificationState(string service)
        {
            DistINResponse<DistINPublicKey> publicKeyResponse = DistINClient.GetPublicKey("root@" + service).Result!;

            DistINServiceVerificationState state = new DistINServiceVerificationState();
            state.Valid = publicKeyResponse.Verify(publicKeyResponse.Result!);
            state.PublicKey = publicKeyResponse.Result!.Key;
            state.Type = publicKeyResponse.ServiceVerificationType;

            return signedObject(state);
        }
    }
}
