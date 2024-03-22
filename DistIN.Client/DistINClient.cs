using DistIN.DistAN;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace DistIN.Client
{
    public static class DistINClient
    {
        public static string SCHEME = "http://"; // TODO: "https://"

        private static DistINKeyPair? keyPair = null;
        private static DistINPublicKey? publicKey = null;
        private static string? token = null;

        public static async Task<DistINResponse<DistINPublicKey>> GetPublicKey(string id)
        {
            string[] address = id.Split('@');
            string url = constructUrl(address[1], "publicKey", "id", address[0]);
            return await requestObject<DistINPublicKey>(address[1], url);
        }

        public static async Task<DistINResponse<DistINAttribute>> GetAttributeByID(string id, string attributeId)
        {
            string[] address = id.Split('@');
            string url = constructUrl(address[1], "attribute", "id", address[0], "attributeId", attributeId);
            return await requestObject<DistINAttribute>(address[1], url);
        }
        public static async Task<DistINResponse<DistINAttribute>> GetAttributeByName(string id, string attributeName)
        {
            string[] address = id.Split('@');
            string url = constructUrl(address[1], "attribute", "id", address[0], "attributeName", attributeName);
            return await requestObject<DistINAttribute>(address[1], url);
        }
        public static async Task<DistINResponse<DistINAttributeSignature>> GetAttributeSignature(string service, string signatureId)
        {
            string url = constructUrl(service, "attributeSignature", "id", signatureId);
            return await requestObject<DistINAttributeSignature>(service, url);
        }

        private static async Task<DistINResponse<DistINLoginChallange>> getAuthChallange(string id)
        {
            string[] address = id.Split('@');

            string url = constructUrl(address[1], "loginRequest", "id", address[0]);
            return await requestObject<DistINLoginChallange>(address[1], url);
        }

        private static async Task<DistINResponse<DistINCredential>> login(string id, DistINLoginData loginData)
        {
            string[] address = id.Split('@');

            string url = constructUrl(address[1], "login", "id", address[0]);
            return await postObject<DistINCredential, DistINLoginData>(address[1], url, loginData);
        }

        private static async Task<DistINResponse<DistINCredential>> register(string id, DistINRegistrationData registrationData)
        {
            string[] address = id.Split('@');

            string url = constructUrl(address[1], "register", "id", address[0]);
            return await postObject<DistINCredential, DistINRegistrationData>(address[1], url, registrationData);
        }


        public static async Task<bool> Login(string identity, DistINKeyPair keys)
        {
            keyPair = keys;
            publicKey = new DistINPublicKey()
            {
                Identity = identity,
                Algorithm = keys.Algorithm,
                Key = keys.PublicKey,
                Date = DateTime.UtcNow,
                Signature = CryptHelper.SignData(keys, Encoding.UTF8.GetBytes(keys.PublicKey)),
            };

            DistINResponse<DistINLoginChallange> challangeResponse = await getAuthChallange(identity);
            if (challangeResponse.Result == null)
                return false;

            string challange = challangeResponse.Result.Challange;

            DistINLoginData loginData = new DistINLoginData();
            loginData.ID = challangeResponse.Result.ID;
            loginData.Signature = CryptHelper.SignData(keyPair, Encoding.UTF8.GetBytes(challange));

            DistINResponse<DistINCredential> loginResponse = await login(identity, loginData);
            if (loginResponse.Result == null)
                return false;

            token = loginResponse.Result.ToString();
            return true;
        }

        public static async Task<bool> Register(string identity, DistINKeyPair keys)
        {
            keyPair = keys;
            publicKey = new DistINPublicKey()
            {
                Identity = identity,
                Algorithm = keys.Algorithm,
                Key = keys.PublicKey,
                Date = DateTime.UtcNow,
                Signature = CryptHelper.SignData(keys, Encoding.UTF8.GetBytes(keys.PublicKey)),
            };

            DistINResponse<DistINLoginChallange> challangeResponse = await getAuthChallange(identity);
            if (challangeResponse.Result == null)
                return false;

            string challange = challangeResponse.Result.Challange;

            DistINRegistrationData registrationData = new DistINRegistrationData();
            registrationData.ID = challangeResponse.Result.ID;
            registrationData.PublicKey = publicKey;
            registrationData.Signature = CryptHelper.SignData(keyPair, Encoding.UTF8.GetBytes(challange));

            DistINResponse<DistINCredential> loginResponse = await register(identity, registrationData);
            if (loginResponse.Result == null)
                return false;

            token = loginResponse.Result.ToString();
            return true;
        }

        public static async Task<DistINResponse<DistANMessageList>> GetMessages()
        {
            if (publicKey == null)
                throw new Exception("auth data missing.");

            string[] address = publicKey.Identity.Split('@');

            string url = constructDistANUrl(address[1], "messages");
            return await requestObject<DistANMessageList>(true, address[1], url);
        }

        public static async Task<DistINResponse<DistANMessage>> PostMessage(DistANMessage message)
        {
            string[] address = message.Recipient.Split('@');

            string url = constructDistANUrl(address[1], "message");
            return await postObject<DistANMessage, DistANMessage>(true, address[1], url, message);
        }



        private static string constructDistANUrl(string domain, string action)
        {
            return string.Format("{0}{1}/distan/{2}", SCHEME, domain, action);
        }
        private static string constructDistANUrl(string domain, string action, string parameterName, string parameterValue)
        {
            return string.Format("{0}{1}/distan/{2}?{3}={4}", SCHEME, domain, action, parameterName, Uri.EscapeDataString(parameterValue));
        }
        private static string constructUrl(string domain, string action, string parameterName, string parameterValue)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}", SCHEME, domain, action, parameterName, Uri.EscapeDataString(parameterValue));
        }
        private static string constructUrl(string domain, string action, string parameterName1, string parameterValue1, 
            string parameterName2, string parameterValue2)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}&{5}={6}", SCHEME, domain, action, parameterName1, Uri.EscapeDataString(parameterValue1), 
                parameterName2, Uri.EscapeDataString(parameterValue2));
        }
        private static string constructUrl(string domain, string action, string parameterName1, string parameterValue1,
            string parameterName2, string parameterValue2, string parameterName3, string parameterValue3)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}&{5}={6}&{7}={8}", SCHEME, domain, action, parameterName1, Uri.EscapeDataString(parameterValue1), 
                parameterName2, Uri.EscapeDataString(parameterValue2), parameterName3, Uri.EscapeDataString(parameterValue3));
        }

        private static async Task<DistINResponse<T>> requestObject<T>(string service, string url) where T : DistINObject
        {
            return await requestObject<T>(false, service, url);
        }
        private static async Task<DistINResponse<T>> requestObject<T>(bool tokenRequred, string service, string url) where T : DistINObject
        {
            using (HttpClient http = new HttpClient())
            {
                if (tokenRequred)
                {
                    if (publicKey == null || keyPair == null || token == null)
                        throw new Exception("auth data missing.");

                    http.DefaultRequestHeaders.Add("DistIN-ID", publicKey.Identity);
                    http.DefaultRequestHeaders.Add("DistIN-Token", token);
                }

                HttpResponseMessage httpResponse = http.GetAsync(url).Result;
                HttpContent content = httpResponse.Content;

                DistINResponse<T> response = new DistINResponse<T>();
                response.ResultBinary = await content.ReadAsByteArrayAsync();
                //response.Result = JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(response.ResultBinary), DistINObject.JsonSerializerOptions);
                response.Result = DistINObject.FromJsonString<T>(Encoding.UTF8.GetString(response.ResultBinary));
                response.Service = service;
                response.Signature = httpResponse.Headers.GetValues("DistIN-Signature").First();
                response.ServiceVerificationType = Enum.Parse<DistINServiceVerificationType>(httpResponse.Headers.GetValues("DistIN-ServiceVerificationType").First());

                return response;
            }
        }

        private static async Task<DistINResponse<T>> postObject<T, Y>(string service, string url, Y obj) where T : DistINObject where Y : DistINObject
        {
            return await postObject<T, Y>(false, service, url, obj);
        }
        private static async Task<DistINResponse<T>> postObject<T,Y>(bool tokenRequred, string service, string url, Y obj) where T : DistINObject where Y : DistINObject
        {
            using (HttpClient http = new HttpClient())
            {
                byte[] data = Encoding.UTF8.GetBytes(obj.ToJsonString());
                ByteArrayContent postContent = new ByteArrayContent(data);
                postContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                postContent.Headers.ContentType.CharSet = "utf-8";
                if (tokenRequred)
                {
                    if (publicKey == null || keyPair == null || token == null)
                        throw new Exception("auth data missing.");

                    postContent.Headers.Add("DistIN-ID", publicKey.Identity);
                    postContent.Headers.Add("DistIN-Token", token);
                    postContent.Headers.Add("DistIN-Signature", CryptHelper.SignData(keyPair, data));
                }
                else
                {
                    if (publicKey != null && keyPair != null)
                    {
                        postContent.Headers.Add("DistIN-ID", publicKey.Identity);
                        postContent.Headers.Add("DistIN-Signature", CryptHelper.SignData(keyPair, data));
                    }
                }

                HttpResponseMessage httpResponse = http.PostAsync(url, postContent).Result;
                HttpContent content = httpResponse.Content;

                DistINResponse<T> response = new DistINResponse<T>();
                response.ResultBinary = await content.ReadAsByteArrayAsync();
                //response.Result = JsonSerializer.Deserialize<T>(Encoding.UTF8.GetString(response.ResultBinary), DistINObject.JsonSerializerOptions);
                response.Result = DistINObject.FromJsonString<T>(Encoding.UTF8.GetString(response.ResultBinary));
                response.Service = service;
                response.Signature = httpResponse.Headers.GetValues("DistIN-Signature").First();
                response.ServiceVerificationType = Enum.Parse<DistINServiceVerificationType>(httpResponse.Headers.GetValues("DistIN-ServiceVerificationType").First());

                return response;
            }
        }
    }
}