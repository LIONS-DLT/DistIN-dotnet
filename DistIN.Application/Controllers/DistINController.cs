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
        private IActionResult getSignedObjectResult<T>(T data) where T : DistINObject
        {
            //byte[] json = Encoding.UTF8.GetBytes(JsonSerializer.Serialize<T>(data, serializerOptions));
            byte[] json = Encoding.UTF8.GetBytes(data.ToJsonString());

            string signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, json);
            this.HttpContext.Response.Headers.Add("DistIN-Signature", signature);
            this.HttpContext.Response.Headers.Add("DistIN-ServiceVerificationType", AppConfig.Current.ServiceVerificationType.ToString());

            return File(json, "text/json");
        }

        private bool checkRequestingIdentityAuth()
        {
            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            //string signature = this.HttpContext.Request.Headers["DistIN-Signature"];
            string token = this.HttpContext.Request.Headers["DistIN-Token"];
            if (string.IsNullOrEmpty(token))
                return false;

            DistINCredential credential = DistINCredential.FromString(token);

            if (!credential.VerifySignature(AppConfig.Current.ServiceKeyPair.Algorithm, AppConfig.Current.ServiceKeyPair.PublicKey))
                return false;

            if(identity != credential.ExportContent().Subject)
                return false;

            return false;
        }

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

        public IActionResult SignatureRequests()
        {
            if(!checkRequestingIdentityAuth())
                return StatusCode(StatusCodes.Status401Unauthorized);

            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            DistINSignatureRequestList result = new DistINSignatureRequestList();
            result.Requests = AuthRequestCache.GetRequests(identity);

            return getSignedObjectResult(result);
        }
    }
}
