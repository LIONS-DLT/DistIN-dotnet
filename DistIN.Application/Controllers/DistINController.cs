using DistIN.Client;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Org.BouncyCastle.Asn1.Cmp;
using System.ComponentModel.DataAnnotations;
using System;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using DistIN.DistAN;
using DistIN.ECBlindSign;

namespace DistIN.Application.Controllers
{
    //[Route("distin")]
    public class DistINController : Controller
    {
        #region HELPER METHODS

        protected IActionResult getSignedObjectResult<T>(T data) where T : JsonSerializableObject
        {
            byte[] json = Encoding.UTF8.GetBytes(data.ToJsonString());

            string signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, json);
            this.HttpContext.Response.Headers.Add("DistIN-Signature", signature);
            this.HttpContext.Response.Headers.Add("DistIN-ServiceVerificationType", AppConfig.Current.ServiceVerificationType.ToString());
            this.HttpContext.Response.ContentLength = json.LongLength;
            this.HttpContext.Response.ContentType = "application/json";
            return File(json, "text/json");
        }

        protected bool checkToken()
        {
            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            string token = this.HttpContext.Request.Headers["DistIN-Token"];
            if (string.IsNullOrEmpty(token))
                return false;

            DistINCredential credential = DistINCredential.FromString(token);
            
            if (!credential.VerifySignature(AppConfig.Current.ServiceKeyPair.Algorithm, AppConfig.Current.ServiceKeyPair.PublicKey))
                return false;

            DistINCredentialContent credentialContent = credential.ExportContent();

            if(credentialContent.Subject != identity)
                return false;
            if (credentialContent.Type != "distin-token")
                return false;

            return true;
        }

        protected T? getRequestObject<T>(bool checkSignature = true) where T : DistINObject
        {
            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            string signature = this.HttpContext.Request.Headers["DistIN-Signature"];
            if (string.IsNullOrEmpty(identity))
                return null;
            if (string.IsNullOrEmpty(signature))
                return null;
            if (!this.Request.ContentLength.HasValue)
                return null;

            int length = (int)this.Request.ContentLength!;
            byte[] data = new byte[length];
            int bytesRead = 0;

            while (bytesRead < length)
                bytesRead += this.Request.Body.Read(data, bytesRead, length - bytesRead);

            if (checkSignature)
            {
                DistINPublicKey publicKey = AppCache.GetPublicKey(identity);

                if (!CryptHelper.VerifySinature(publicKey, signature, data))
                    return null;
            }

            return DistINObject.FromJsonString<T>(Encoding.UTF8.GetString(data));
            //return this.Request.ReadFromJsonAsync<T>(DistINObject.JsonSerializerOptions).Result!;
        }

        #endregion

        #region GET ACTIONS

        [HttpGet]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINPublicKey))]
        public IActionResult PublicKey(string id, string? date)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);

            id = id.ToLower();
            string identity = IDHelper.IDToIdentity(id);

            if (!string.IsNullOrEmpty(date))
            {
                DateTime dateTime = DateTime.Parse(date);
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' AND [Date]<{1} ORDER BY [Date] DESC",
                    identity.ToSqlSafeValue(), dateTime.Ticks)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return getSignedObjectResult(key);
            }
            else
            {
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' ORDER BY [Date] DESC", identity.ToSqlSafeValue())).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return getSignedObjectResult(key);
            }
        }

        [HttpGet]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINAttribute))]
        public IActionResult Attribute(string? id, string? attributeId, string? attributeName, string? token)
        {
            if (!string.IsNullOrEmpty(token))
            {
                DistINToken t = DistINToken.FromString(token);
                DistINTokenPayload payload = t.GetPayload();

                string identity = payload.Subject.Split('>')[0];
                attributeName = payload.Subject.Split('>')[1];

                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' AND [Date]<{1} ORDER BY [Date] DESC",
                    identity.ToSqlSafeValue(), payload.GetIssuedAt().Ticks)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                DistINTokenValidationResult validationResult = t.Validate(key);
                if(validationResult != DistINTokenValidationResult.Success)
                    return StatusCode(StatusCodes.Status401Unauthorized);

                DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", identity.ToSqlSafeValue(), attributeName.ToSqlSafeValue())).FirstOrDefault();
                if (attribute == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                attribute.SignatureReferences = Database.AttributeSignatureRefs.Where(string.Format("[Attribute]='{0}'", attribute.ID));

                return getSignedObjectResult(attribute);
            }
            else
            {
                if (string.IsNullOrEmpty(id))
                    return StatusCode(StatusCodes.Status400BadRequest);

                string identity = IDHelper.IDToIdentity(id);

                if (!string.IsNullOrEmpty(attributeId))
                {
                    DistINAttribute attribute = Database.Attributes.Find(attributeId)!;
                    if (attribute.Identity != identity)
                        return StatusCode(StatusCodes.Status400BadRequest);

                    attribute.SignatureReferences = Database.AttributeSignatureRefs.Where(string.Format("[Attribute]='{0}'", attribute.ID));

                    return getSignedObjectResult(attribute);
                }
                else if (!string.IsNullOrEmpty(attributeName))
                {
                    DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", identity.ToSqlSafeValue(), attributeName.ToSqlSafeValue())).FirstOrDefault();
                    if (attribute == null)
                        return StatusCode(StatusCodes.Status404NotFound);
                    if (!attribute.IsPublic)
                        return StatusCode(StatusCodes.Status404NotFound);

                    attribute.SignatureReferences = Database.AttributeSignatureRefs.Where(string.Format("[Attribute]='{0}'", attribute.ID));

                    return getSignedObjectResult(attribute);
                }
                else
                {
                    return StatusCode(StatusCodes.Status400BadRequest);
                }
            }
        }

        [HttpGet]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINAttributeSignature))]
        public IActionResult AttributeSignature(string id)
        {
            DistINAttributeSignature? signature = Database.AttributeSignatures.Find(id);
            if (signature == null)
                return StatusCode(StatusCodes.Status404NotFound);
            return getSignedObjectResult(signature);
        }

        [HttpGet]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINServiceVerificationState))]
        public IActionResult ServiceVerificationState(string service)
        {
            if (string.IsNullOrEmpty(service))
                return StatusCode(StatusCodes.Status400BadRequest);

            DistINResponse<DistINPublicKey> publicKeyResponse = DistINClient.GetPublicKey("root@" + service).Result!;

            DistINServiceVerificationState state = new DistINServiceVerificationState();
            state.Valid = publicKeyResponse.Verify(publicKeyResponse.Result!);
            state.PublicKey = publicKeyResponse.Result!.Key;
            state.Type = publicKeyResponse.ServiceVerificationType;

            return getSignedObjectResult(state);
        }

        [HttpGet]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINSignatureRequestList))]
        public IActionResult SignatureRequests()
        {
            if(!checkToken())
                return StatusCode(StatusCodes.Status401Unauthorized);

            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            DistINSignatureRequestList result = new DistINSignatureRequestList();
            result.Requests = AuthRequestCache.GetRequests(identity);

            return getSignedObjectResult(result);
        }

        #endregion


        #region POST ACTIONS

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINSignatureResponse))]
        public IActionResult SignatureRequest(string id, string data, string? caption)
        {
            return Authenticate(id, data, caption, null, null);
        }

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINSignatureResponse))]
        public IActionResult Authenticate(string id, string challenge, string? caption, string? requiredAttributes, string? preferredAttributes)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);
            if (string.IsNullOrEmpty(challenge))
                return StatusCode(StatusCodes.Status400BadRequest);

            //DistINSignatureRequest request = new DistINSignatureRequest();
            //request.Identity = IDHelper.IDToIdentity(id);
            //request.RemoteAddress = this.HttpContext.Connection.RemoteIpAddress!.ToString();
            //request.Caption = caption ?? string.Empty;
            //request.Challenge = challenge ?? string.Empty;

            //if (!string.IsNullOrEmpty(requiredAttributes))
            //{
            //    foreach (string a in requiredAttributes.Split(new char[] { ',', ';', '|' }))
            //    {
            //        request.RequiredAttributes.Add(a);
            //    }
            //}
            //if (!string.IsNullOrEmpty(preferredAttributes))
            //{
            //    foreach (string a in preferredAttributes.Split(new char[] { ',', ';', '|' }))
            //    {
            //        request.PreferredAttributes.Add(a);
            //    }
            //}

            //DateTime timeout = DateTime.Now.AddMinutes(10);

            //AuthRequestCache.AddRequest(request, timeout);
            //DistINSignatureResponse? response = null;

            //while(response == null && timeout < DateTime.Now)
            //{
            //    Thread.Sleep(1000);
            //    response = AuthRequestCache.GetAndRemoveResponse(request.ID);
            //}

            DistINSignatureResponse? response = performAuthenticationRequest(this.HttpContext, id, challenge, caption, requiredAttributes, preferredAttributes);

            if (response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            return getSignedObjectResult(response);
        }

        public static DistINSignatureResponse? performAuthenticationRequest(HttpContext httpContext, string id, string challenge, string? caption, string? requiredAttributes, string? preferredAttributes)
        {
            DistINSignatureRequest request = new DistINSignatureRequest();
            request.Identity = IDHelper.IDToIdentity(id);
            request.RemoteAddress = httpContext.Connection.RemoteIpAddress!.ToString();
            request.Caption = caption ?? string.Empty;
            request.Challenge = challenge ?? string.Empty;

            if (!string.IsNullOrEmpty(requiredAttributes))
            {
                foreach (string a in requiredAttributes.Split(new char[] { ',', ';', '|' }))
                {
                    request.RequiredAttributes.Add(a);
                }
            }
            if (!string.IsNullOrEmpty(preferredAttributes))
            {
                foreach (string a in preferredAttributes.Split(new char[] { ',', ';', '|' }))
                {
                    request.PreferredAttributes.Add(a);
                }
            }

            DateTime timeout = DateTime.Now.AddMinutes(10);

            AuthRequestCache.AddRequest(request, timeout);
            DistINSignatureResponse? response = null;

            while (response == null && timeout > DateTime.Now)
            {
                Thread.Sleep(1000);
                response = AuthRequestCache.GetAndRemoveResponse(request.ID);
            }
            return response;
        }

        [HttpPost]
        [ApiDefinition(InputType = typeof(DistINSignatureResponse), ReturnType = typeof(DistINSignatureResponse))]
        public IActionResult SignatureResponse()
        {
            if (!checkToken())
                return StatusCode(StatusCodes.Status401Unauthorized);
            DistINSignatureResponse? response = getRequestObject<DistINSignatureResponse>();
            if(response == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            AuthRequestCache.AddResponse(response);

            return getSignedObjectResult(response);
        }


        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINLoginChallange))]
        public IActionResult LoginRequest(string id)
        {
            string identity = IDHelper.IDToIdentity(id);
            DistINPublicKey? publicKey = Database.PublicKeys.Where(string.Format("[Identity]='{0}'", identity.ToSqlSafeValue())).FirstOrDefault();
            if(publicKey == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            DistINLoginChallange challange = new DistINLoginChallange();
            challange.Challange = LoginRequestCache.CreateChallange(challange.ID)!;
            return getSignedObjectResult(challange);
        }

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = typeof(DistINLoginData), ReturnType = typeof(DistINCredential))]
        public IActionResult Login(string id)
        {
            DistINLoginData? loginData = getRequestObject<DistINLoginData>();
            if(loginData == null)
                return StatusCode(StatusCodes.Status400BadRequest);
            
            string? challange = LoginRequestCache.GetChallange(loginData.ID);
            if (challange == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            string identity = IDHelper.IDToIdentity(id);
            DistINPublicKey publicKey = AppCache.GetPublicKey(identity);
            if (challange == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            if (!CryptHelper.VerifySinature(publicKey, loginData.Signature, Encoding.UTF8.GetBytes(challange)))
                return StatusCode(StatusCodes.Status401Unauthorized);

            DistINCredentialContent tokenContent = new DistINCredentialContent();
            tokenContent.Issuer = IDHelper.IDToIdentity("root");
            tokenContent.Subject = identity;
            tokenContent.IssuanceDate = DateTime.Now;
            tokenContent.Type = "distin-token";
            tokenContent.ExpirationDate = DateTime.Now.AddDays(100);
            tokenContent.MimeType = DistINMimeTypes.TEXT;
            tokenContent.Payload = challange;
            
            DistINCredential token = new DistINCredential();
            token.ImportContent(tokenContent);
            token.Sign(AppConfig.Current.ServiceKeyPair);

            return getSignedObjectResult(token);
        }


        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINLoginChallange))]
        public IActionResult RegistrationRequest(string id)
        {
            if (!AppConfig.Current.AllowBlindRegistration)
                return StatusCode(StatusCodes.Status403Forbidden);

            DistINLoginChallange challange = new DistINLoginChallange();
            challange.Challange = LoginRequestCache.CreateChallange(challange.ID)!;
            return getSignedObjectResult(challange);
        }


        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = typeof(DistINRegistrationData), ReturnType = typeof(DistINCredential))]
        public IActionResult Register()
        {
            DistINRegistrationData? registrationData = getRequestObject<DistINRegistrationData>(false);
            if (registrationData == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            if (!AppConfig.Current.AllowBlindRegistration && !LoginRequestCache.HasIdForRegistration(registrationData.PublicKey.Identity))
                return StatusCode(StatusCodes.Status403Forbidden);


            string? challange = LoginRequestCache.GetChallange(registrationData.ID);
            if (challange == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            DistINPublicKey publicKey = registrationData.PublicKey;

            if (!CryptHelper.VerifySinature(publicKey, registrationData.Signature, Encoding.UTF8.GetBytes(challange)))
                return StatusCode(StatusCodes.Status401Unauthorized);

            Database.PublicKeys.Insert(publicKey);
            LoginRequestCache.RemoveIdForRegistration(registrationData.PublicKey.Identity);

            DistINCredentialContent tokenContent = new DistINCredentialContent();
            tokenContent.Issuer = IDHelper.IDToIdentity("root");
            tokenContent.Subject = registrationData.PublicKey.Identity;
            tokenContent.IssuanceDate = DateTime.Now;
            tokenContent.Type = "distin-token";
            tokenContent.ExpirationDate = DateTime.Now.AddDays(100);
            tokenContent.MimeType = DistINMimeTypes.TEXT;
            tokenContent.Payload = challange;

            DistINCredential token = new DistINCredential();
            token.ImportContent(tokenContent);
            token.Sign(AppConfig.Current.ServiceKeyPair);

            return getSignedObjectResult(token);
        }


        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(OneTimeSignature))]
        public IActionResult OneTimeSignature(string id, string data, string algorithm, string? caption)
        {

            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);
            if (string.IsNullOrEmpty(data))
                return StatusCode(StatusCodes.Status400BadRequest);


            OneTimeSignature ots = new OneTimeSignature();
            ots.Algorithm = Enum.Parse<OneTimeSignatureAlgorithm>(algorithm);
            ots.CreateSignatureAndKey(data);

            string dataToSign = ots.GetSignedPayloadString();

            DistINSignatureResponse? response = performAuthenticationRequest(this.HttpContext, id, dataToSign, caption, null, null);

            if (response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            ots.Identity = id;
            ots.IdentitySignature = response.Signature;

            return getSignedObjectResult(ots);
        }


        private static Dictionary<string, RSA> _rsaKeyPairs = new Dictionary<string, RSA>();

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(BlindSignatureKey))]
        public IActionResult StartRSABlindSignature(string id)
        {
            var rsa = RSA.Create(1024);
            BlindSignatureKey blindSignatureKey = new BlindSignatureKey();
            blindSignatureKey.Key = CryptHelper.EncodeUrlBase64(rsa.ExportRSAPublicKey());

            lock (_rsaKeyPairs)
            {
                _rsaKeyPairs.Add(blindSignatureKey.ID, rsa);
            }

            return getSignedObjectResult(blindSignatureKey);
        }

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(OneTimeSignature))]
        public IActionResult GetRSABlindSignature(string id, string keyId, string signature, string caption)
        {
            RSA rsa;
            lock(_rsaKeyPairs)
            {
                rsa = _rsaKeyPairs[keyId];
                _rsaKeyPairs.Remove(keyId);
            }

            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)DotNetUtilities.GetRsaKeyPair(rsa).Private;
            RsaEngine engine = new RsaEngine();
            engine.Init(true, privateKey);
            byte[] sig = CryptHelper.DecodeUrlBase64(signature);
            var blindsign = engine.ProcessBlock(sig, 0, sig.Length);

            OneTimeSignature ots = new OneTimeSignature();
            ots.Algorithm = OneTimeSignatureAlgorithm.RSA;
            ots.ID = keyId;
            ots.Key = CryptHelper.EncodeUrlBase64(rsa.ExportRSAPublicKey());
            ots.Signature = CryptHelper.EncodeUrlBase64(blindsign);

            ots.Identity = id;
            string dataToSign = ots.GetSignedPayloadString();

            DistINSignatureResponse? response = performAuthenticationRequest(this.HttpContext, id, dataToSign, caption, null, null);

            if (response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            ots.IdentitySignature = response.Signature;

            return getSignedObjectResult(ots);
        }


        private static Dictionary<string, KeyValuePair<ECBlindKeyPair, ECBlindSignerSession>> _ecKeyPairs = new Dictionary<string, KeyValuePair<ECBlindKeyPair, ECBlindSignerSession>>();

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(ECBlindSignatureSession))]
        public IActionResult StartECBlindSignature(string id)
        {
            ECBlindSchnorr signerService = new ECBlindSchnorr(ECBlindCurve.secp256k1);
            ECBlindKeyPair keyPair = signerService.GenerateKeyPair();
            ECBlindSignerSession session = signerService.SignerBeginSession();


            ECBlindSignatureSession result = new ECBlindSignatureSession()
            {
                Key = CryptHelper.EncodeUrlBase64(keyPair.PublicKey.GetEncoded()),
                R = CryptHelper.EncodeUrlBase64(session.R.GetEncoded())
            };

            lock (_ecKeyPairs)
            {
                _ecKeyPairs.Add(result.ID, new KeyValuePair<ECBlindKeyPair, ECBlindSignerSession>(keyPair, session));
            }

            return getSignedObjectResult(result);
        }

        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(OneTimeSignature))]
        public IActionResult GetECBlindSignature(string id, string keyId, string eprime, string caption)
        {
            KeyValuePair<ECBlindKeyPair, ECBlindSignerSession> session;
            lock (_ecKeyPairs)
            {
                session = _ecKeyPairs[keyId];
                _ecKeyPairs.Remove(keyId);
            }

            ECBlindSchnorr signerService = new ECBlindSchnorr(ECBlindCurve.secp256k1);
            Org.BouncyCastle.Math.BigInteger ePrime = new Org.BouncyCastle.Math.BigInteger(CryptHelper.DecodeUrlBase64(eprime));
            Org.BouncyCastle.Math.BigInteger sPrime = signerService.SignerFinish(session.Value, session.Key.PrivateKey, ePrime);


            OneTimeSignature ots = new OneTimeSignature();
            ots.Algorithm = OneTimeSignatureAlgorithm.ECDSA;
            ots.ID = keyId;
            ots.Key = CryptHelper.EncodeUrlBase64(session.Key.PublicKey.GetEncoded());
            ots.Signature = CryptHelper.EncodeUrlBase64(sPrime.ToByteArray());

            ots.Identity = id;
            string dataToSign = ots.GetSignedPayloadString();

            DistINSignatureResponse? response = performAuthenticationRequest(this.HttpContext, id, dataToSign, caption, null, null);

            if (response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            ots.IdentitySignature = response.Signature;

            return getSignedObjectResult(ots);
        }


        [HttpGet]
        [HttpPost]
        [ApiDefinition(InputType = null, ReturnType = typeof(DistINSignatureResponse))]
        public IActionResult SDCRequest(string id, string attributeName, string nonce, string? caption)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);
            if (string.IsNullOrEmpty(attributeName))
                return StatusCode(StatusCodes.Status400BadRequest);
            if (string.IsNullOrEmpty(nonce))
                return StatusCode(StatusCodes.Status400BadRequest);

            string identity = IDHelper.IDToIdentity(id);
            DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", identity.ToSqlSafeValue(), attributeName.ToSqlSafeValue())).FirstOrDefault();
            if (attribute == null)
                return StatusCode(StatusCodes.Status404NotFound);

            DistINSelectiveDisclosureCredential credential = attribute.GetValue<DistINSelectiveDisclosureCredential>();
            if(credential == null)
                return StatusCode(StatusCodes.Status404NotFound);

            string preferredAttributes = string.Join(',', credential.Messages);

            DistINSignatureResponse? response = performAuthenticationRequest(this.HttpContext, id, nonce, $"SDC ({attributeName}): {caption}", null, preferredAttributes);
            if(response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            List<int> indices = new List<int>();
            foreach (string attr in response.PermittedAttributes)
            {
                int idx = Array.IndexOf(credential.Messages, attr);
                if (idx >= 0)
                    indices.Add(idx);
            }
            
            DistINSelectiveDisclosureProof proof = credential.CreateProof(indices.ToArray(), nonce);

            DistINSelectiveDisclosureResponse selectiveDisclosureResponse = new DistINSelectiveDisclosureResponse();
            selectiveDisclosureResponse.Identity = identity;
            selectiveDisclosureResponse.Nonce = nonce;
            selectiveDisclosureResponse.IdentitySignature = response.Signature;
            selectiveDisclosureResponse.Proof = proof;

            return getSignedObjectResult(selectiveDisclosureResponse);
        }

        #endregion


        #region PUT ACTIONS

        #endregion


        #region DELETE ACTIONS

        #endregion

    }
}
