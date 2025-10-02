using DistIN.DistAN;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DistIN.Client
{
    public static class DistINClient
    {
        public static string SCHEME = "https://"; // TODO: "https://"

        private static DistINKeyPair? keyPair = null;
        private static DistINPublicKey? publicKey = null;
        private static string? token = null;

        public static async Task<DistINResponse<DistINSignatureResponse>?> RequestAuthentication(string id, string challenge, string? caption, IEnumerable<string>? requiredAttributes = null, IEnumerable<string>? preferredAttributes = null)
        {
            string? requiredAttributesString = null;
            string? preferredAttributesString = null;

            if(requiredAttributes != null)
                requiredAttributesString = string.Join(",", requiredAttributes);
            if (preferredAttributes != null)
                preferredAttributesString = string.Join(",", preferredAttributes);

            return await RequestAuthentication(id, challenge, caption, requiredAttributesString, preferredAttributesString);
        }
        public static async Task<DistINResponse<DistINSignatureResponse>?> RequestAuthentication(string id, string challenge, string? caption, string? requiredAttributes, string? preferredAttributes)
        {
            DistINPublicKey publicKey = GetPublicKey(id).Result.Result!;

            string[] address = id.Split('@');

            string url = constructUrl(address[1], "authenticate", "id", address[0], "challenge", challenge);
            if (!string.IsNullOrEmpty(caption))
                url += "?caption=" + Uri.EscapeDataString(caption);
            if (!string.IsNullOrEmpty(requiredAttributes))
                url += "?requiredAttributes=" + Uri.EscapeDataString(requiredAttributes);
            if (!string.IsNullOrEmpty(preferredAttributes))
                url += "?preferredAttributes=" + Uri.EscapeDataString(preferredAttributes);
            DistINResponse<DistINSignatureResponse> response = await requestObject<DistINSignatureResponse>(address[1], url);
            bool success = CryptHelper.VerifySinature(publicKey, response.Result!.Signature, Encoding.UTF8.GetBytes(challenge));

            if (success)
                return response;
            else
                return null;
        }

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


        public static async Task<bool> RegisterBlind(string identity, DistINKeyPair keys)
        {
            return await Register(identity, "", "", keys);
        }
        public static async Task<bool> Register(string identity, string registrationId, string registrationChallange, DistINKeyPair keys)
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

            if (string.IsNullOrEmpty(registrationId))
            {
                string[] address = identity.Split('@');

                string url = constructUrl(address[1], "registrationRequest", "id", address[0]);
                DistINResponse<DistINLoginChallange> challangeResponse = await requestObject<DistINLoginChallange>(address[1], url);

                if (challangeResponse.Result == null)
                    return false;

                registrationId = challangeResponse.Result.ID;
                registrationChallange = challangeResponse.Result.Challange;
            }

            DistINRegistrationData registrationData = new DistINRegistrationData();
            registrationData.ID = registrationId;
            registrationData.PublicKey = publicKey;
            registrationData.Signature = CryptHelper.SignData(keyPair, Encoding.UTF8.GetBytes(registrationChallange));

            DistINResponse<DistINCredential> loginResponse = await register(identity, registrationData);
            if (loginResponse.Result == null)
                return false;

            token = loginResponse.Result.ToString();
            return true;
        }


        public static async Task<DistINResponse<DistINSignatureRequestList>> GetSignatureRequests()
        {
            if (publicKey == null)
                throw new Exception("auth data missing.");

            string[] address = publicKey.Identity.Split('@');

            string url = constructUrl(address[1], "signatureRequests");
            return await requestObject<DistINSignatureRequestList>(true, address[1], url);
        }
        public static async Task<DistINResponse<DistINSignatureResponse>> PostSignatureResponse(DistINSignatureResponse response)
        {
            if (publicKey == null)
                throw new Exception("auth data missing.");

            string[] address = publicKey.Identity.Split('@');

            string url = constructUrl(address[1], "signatureResponse");
            return await postObject<DistINSignatureResponse, DistINSignatureResponse>(true, address[1], url, response);
        }



        public static async Task<DistINResponse<DistANMessageList>> GetMessages(string appId)
        {
            if (publicKey == null)
                throw new Exception("auth data missing.");

            string[] address = publicKey.Identity.Split('@');

            string url = constructDistANUrl(address[1], "messages", "appId", appId);
            return await requestObject<DistANMessageList>(true, address[1], url);
        }

        public static async Task<DistINResponse<DistANMessage>> PostMessage(DistANMessage message)
        {
            string[] address = message.Recipient.Split('@');

            string url = constructDistANUrl(address[1], "message");
            return await postObject<DistANMessage, DistANMessage>(true, address[1], url, message);
        }

        public static async Task<DistINResponse<OneTimeSignature>> RequestOneTimeSignature(string id, string dataAsUrlSafeBase64, OneTimeSignatureAlgorithm algorithm, string caption)
        {
            string[] address = id.Split('@');
            string url = constructUrl(address[1], "oneTimeSignature", "id", address[0], "data", dataAsUrlSafeBase64, "algorithm", algorithm.ToString(), "caption", caption);
            return await requestObject<OneTimeSignature>(address[1], url);
        }
        public static async Task<BlindSignatureResponse> RequestBlindSignature(string id, byte[] data, string caption)
        {
            string[] address = id.Split('@');

            string url = constructUrl(address[1], "startRSABlindSignature", "id", address[0]);

            DistINResponse<BlindSignatureKey> blindSignatureKeyResponse = await requestObject<BlindSignatureKey>(address[1], url);

            BlindSignatureKey blindSignatureKey = blindSignatureKeyResponse.Result!;

            var rsa = RSA.Create(1024);
            rsa.ImportRSAPublicKey(CryptHelper.DecodeUrlBase64(blindSignatureKey.Key), out _);
            RsaKeyParameters publicKey = DotNetUtilities.GetRsaPublicKey(rsa);

            // ---
            var blindingFactorGenerator = new RsaBlindingFactorGenerator();
            blindingFactorGenerator.Init(publicKey);

            var blindingFactor = blindingFactorGenerator.GenerateBlindingFactor();

            RsaBlindingParameters blindingParams = new RsaBlindingParameters(publicKey, blindingFactor);
            PssSigner signer = new PssSigner(new RsaBlindingEngine(), new Sha256Digest(), 20);

            signer.Init(true, blindingParams);

            signer.BlockUpdate(data, 0, data.Length);
            byte[] sig = signer.GenerateSignature();
            string signature = CryptHelper.EncodeUrlBase64(sig);
            // ---

            url = constructUrl(address[1], "getRSABlindSignature", "id", address[0], "keyId", blindSignatureKey.ID, "signature", signature, "caption", caption);
            DistINResponse<OneTimeSignature> blindSignatureResponse = await requestObject<OneTimeSignature>(address[1], url);
            OneTimeSignature blindSignature = blindSignatureResponse.Result!;

            byte[] blindsign = CryptHelper.DecodeUrlBase64(blindSignature.Signature);
            RsaBlindingEngine blindingEngine = new RsaBlindingEngine();
            blindingEngine.Init(false, blindingParams);
            byte[] finalSignature = blindingEngine.ProcessBlock(blindsign, 0, blindsign.Length);

            return new BlindSignatureResponse(blindSignature, finalSignature);
        }


        private static string constructDistANUrl(string domain, string action)
        {
            return string.Format("{0}{1}/distan/{2}", SCHEME, domain, action);
        }
        private static string constructDistANUrl(string domain, string action, string parameterName, string parameterValue)
        {
            return string.Format("{0}{1}/distan/{2}?{3}={4}", SCHEME, domain, action, parameterName, Uri.EscapeDataString(parameterValue));
        }
        private static string constructUrl(string domain, string action)
        {
            return string.Format("{0}{1}/distin/{2}", SCHEME, domain, action);
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
        private static string constructUrl(string domain, string action, string parameterName1, string parameterValue1,
            string parameterName2, string parameterValue2, string parameterName3, string parameterValue3, string parameterName4, string parameterValue4)
        {
            return string.Format("{0}{1}/distin/{2}?{3}={4}&{5}={6}&{7}={8}&{9}={10}", SCHEME, domain, action, parameterName1, Uri.EscapeDataString(parameterValue1),
                parameterName2, Uri.EscapeDataString(parameterValue2), parameterName3, Uri.EscapeDataString(parameterValue3), parameterName4, Uri.EscapeDataString(parameterValue4));
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