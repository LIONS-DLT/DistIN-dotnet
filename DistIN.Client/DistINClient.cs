using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace DistIN.Client
{
    public static class DistINClient
    {
        private const string SCHEME = "http://"; // TODO: "https://"

        private static JsonSerializerOptions serializerOptions = new JsonSerializerOptions()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
            WriteIndented = true // TODO: remove for production
        };

        public static async Task<DistINResponse<DistINPublicKey>> GetPublicKey(string id)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "publicKey", "id", address[0]);
                return await requestObject<DistINPublicKey>(address[1], url);
            }
        }

        public static async Task<DistINResponse<DistINAttribute>> GetAttributeByID(string id, string attributeId)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "attribute", "id", address[0], "attributeId", attributeId);
                return await requestObject<DistINAttribute>(address[1], url);
            }
        }
        public static async Task<DistINResponse<DistINAttribute>> GetAttributeByName(string id, string attributeName)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "attribute", "id", address[0], "attributeName", attributeName);
                return await requestObject<DistINAttribute>(address[1], url);
            }
        }
        public static async Task<DistINResponse<DistINAttributeSignature>> GetAttributeSignature(string service, string signatureId)
        {
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(service, "attributeSignature", "id", signatureId);
                return await requestObject<DistINAttributeSignature>(service, url);
            }
        }



        private static string constructUrl(string domain, string action, string parameterName, string parameterValue)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}", SCHEME, domain, action, parameterName, parameterValue);
        }
        private static string constructUrl(string domain, string action, string parameterName1, string parameterValue1, 
            string parameterName2, string parameterValue2)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}&{5}={6}", SCHEME, domain, action, parameterName1, parameterValue1, 
                parameterName2, parameterValue2);
        }
        private static string constructUrl(string domain, string action, string parameterName1, string parameterValue1,
            string parameterName2, string parameterValue2, string parameterName3, string parameterValue3)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}&{5}={6}&{7}={8}", SCHEME, domain, action, parameterName1, parameterValue1, 
                parameterName2, parameterValue2, parameterName3, parameterValue3);
        }

        private static async Task<DistINResponse<T>> requestObject<T>(string service, string url)
        {
            using (HttpClient http = new HttpClient())
            {
                HttpResponseMessage httpResponse = http.GetAsync(url).Result;
                HttpContent content = httpResponse.Content;

                DistINResponse<T> response = new DistINResponse<T>();
                response.ResultBinary = await content.ReadAsByteArrayAsync();
                response.Result = JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(response.ResultBinary), serializerOptions);
                response.Service = service;
                response.Signature = httpResponse.Headers.GetValues("DistIN-Signature").First();
                response.ServiceVerificationType = Enum.Parse<DistINServiceVerificationType>(httpResponse.Headers.GetValues("DistIN-ServiceVerificationType").First());

                return response;
            }
        }
    }
}