using DistIN.Client;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace DistIN.Application.Controllers
{
    [Route("distin")]
    public class DistINController : Controller
    {
        #region HELPER METHODS

        private IActionResult getSignedObjectResult<T>(T data) where T : DistINObject
        {
            byte[] json = Encoding.UTF8.GetBytes(data.ToJsonString());

            string signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, json);
            this.HttpContext.Response.Headers.Add("DistIN-Signature", signature);
            this.HttpContext.Response.Headers.Add("DistIN-ServiceVerificationType", AppConfig.Current.ServiceVerificationType.ToString());

            return File(json, "text/json");
        }

        private bool checkToken()
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

            return false;
        }

        private T? getRequestObject<T>() where T : DistINObject
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

            DistINPublicKey publicKey = AppCache.GetPublicKey(identity);

            if (!CryptHelper.VerifySinature(publicKey, signature, data))
                return null;

            return this.Request.ReadFromJsonAsync<T>(DistINObject.JsonSerializerOptions).Result!;
        }

        #endregion

        #region GET ACTIONS

        [HttpGet]
        public IActionResult PublicKey(string id, string? date)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);

            id = id.ToLower();
            string identity = id + "@" + AppConfig.Current.ServiceDomain;

            if (!string.IsNullOrEmpty(date))
            {
                DateTime dateTime = DateTime.Parse(date);
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' AND [Date]<{1} ORDER BY [Date] DESC",
                    identity, dateTime.Ticks)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return getSignedObjectResult(key);
            }
            else
            {
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' ORDER BY [Date] DESC", identity)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return getSignedObjectResult(key);
            }
        }

        [HttpGet]
        public IActionResult Attribute(string id, string? attributeId, string? attributeName)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);

            string identity = id + "@" + AppConfig.Current.ServiceDomain;

            if (!string.IsNullOrEmpty(attributeId))
            {
                DistINAttribute attribute = Database.Attributes.Find(attributeId)!;
                if(attribute.Identity != identity)
                    return StatusCode(StatusCodes.Status400BadRequest);

                return getSignedObjectResult(attribute);
            }
            else if(!string.IsNullOrEmpty(attributeName))
            {
                DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", identity, attributeName)).FirstOrDefault();
                if(attribute == null)
                    return StatusCode(StatusCodes.Status404NotFound);

                return getSignedObjectResult(attribute);
            }
            else
            {
                return StatusCode(StatusCodes.Status400BadRequest);
            }
        }

        [HttpGet]
        public IActionResult AttributeSignature(string id)
        {
            DistINAttributeSignature? signature = Database.AttributeSignatures.Find(id);
            if (signature == null)
                return StatusCode(StatusCodes.Status404NotFound);
            return getSignedObjectResult(signature);
        }

        [HttpGet]
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
        public IActionResult Authenticate(string id, string challenge, string? caption, string? requiredAttributes, string? preferredAttributes)
        {
            if (string.IsNullOrEmpty(id))
                return StatusCode(StatusCodes.Status400BadRequest);
            if (string.IsNullOrEmpty(challenge))
                return StatusCode(StatusCodes.Status400BadRequest);

            DistINSignatureRequest request = new DistINSignatureRequest();
            request.Identity = id + "@" + AppConfig.Current.ServiceDomain;
            request.RemoteAddress = this.HttpContext.Connection.RemoteIpAddress!.ToString();
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

            while(response == null && timeout < DateTime.Now)
            {
                Thread.Sleep(1000);
                response = AuthRequestCache.GetAndRemoveResponse(request.ID);
            }

            if(response == null)
                return StatusCode(StatusCodes.Status419AuthenticationTimeout);

            return getSignedObjectResult(response);
        }


        [HttpPost]
        public IActionResult SignatureResponse()
        {
            if (!checkToken())
                return StatusCode(StatusCodes.Status401Unauthorized);
            DistINSignatureResponse? response = getRequestObject<DistINSignatureResponse>();
            if(response == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            AuthRequestCache.AddResponse(response);

            return StatusCode(StatusCodes.Status200OK);
        }


        [HttpGet]
        [HttpPost]
        public IActionResult LoginRequest(string id)
        {
            DistINLoginChallange challange = new DistINLoginChallange();
            challange.Challange = LoginRequestCache.CreateChallange(id)!;
            return getSignedObjectResult(challange);
        }

        [HttpGet]
        [HttpPost]
        public IActionResult Login()
        {
            DistINLoginData? loginData = getRequestObject<DistINLoginData>();
            if(loginData == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            string? challange = LoginRequestCache.GetChallange(loginData.ID);
            if (challange == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            string identity = loginData.ID + "@" + AppConfig.Current.ServiceDomain;
            DistINPublicKey publicKey = AppCache.GetPublicKey(identity);

            if (!CryptHelper.VerifySinature(publicKey, loginData.Signature, Encoding.UTF8.GetBytes(challange)))
                return StatusCode(StatusCodes.Status401Unauthorized);

            DistINCredentialContent tokenContent = new DistINCredentialContent();
            tokenContent.Issuer = "root@" + AppConfig.Current.ServiceDomain;
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
        public IActionResult Register()
        {
            DistINRegistrationData? registrationData = getRequestObject<DistINRegistrationData>();
            if (registrationData == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            string? challange = LoginRequestCache.GetChallange(registrationData.ID);
            if (challange == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            string identity = registrationData.ID + "@" + AppConfig.Current.ServiceDomain;
            DistINPublicKey publicKey = registrationData.PublicKey;

            if (!CryptHelper.VerifySinature(publicKey, registrationData.Signature, Encoding.UTF8.GetBytes(challange)))
                return StatusCode(StatusCodes.Status401Unauthorized);

            Database.PublicKeys.Insert(publicKey);

            DistINCredentialContent tokenContent = new DistINCredentialContent();
            tokenContent.Issuer = "root@" + AppConfig.Current.ServiceDomain;
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

        #endregion


        #region PUT ACTIONS

        #endregion


        #region DELETE ACTIONS

        #endregion

    }
}
