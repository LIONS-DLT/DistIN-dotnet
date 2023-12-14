using System.Net.Http.Json;
using System.Text.Json;

namespace DistIN
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


        public static async Task<DistINPublicKey?> GetPublicKey(string id)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "publicKey", "id", address[0]);
                return await http.GetFromJsonAsync<DistINPublicKey>(url, serializerOptions);
            }
        }

        public static async Task<DistINAttribute?> GetAttributeByID(string id, string attributeId)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "attribute", "id", address[0], "attributeId", attributeId);
                return await http.GetFromJsonAsync<DistINAttribute>(url, serializerOptions);
            }
        }
        public static async Task<DistINAttribute?> GetAttributeByName(string id, string attributeName)
        {
            string[] address = id.Split('@');
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(address[1], "attribute", "id", address[0], "attributeName", attributeName);
                return await http.GetFromJsonAsync<DistINAttribute>(url, serializerOptions);
            }
        }
        public static async Task<DistINAttributeSignature?> GetAttributeSignature(string service, string signatureId)
        {
            using (HttpClient http = new HttpClient())
            {
                string url = constructUrl(service, "attributeSignature", "id", signatureId);
                return await http.GetFromJsonAsync<DistINAttributeSignature>(url, serializerOptions);
            }
        }
    }
}