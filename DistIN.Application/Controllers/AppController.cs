using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Text;

namespace DistIN.Application.Controllers
{
    public class AppController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        //[HttpPost]
        //public IActionResult Login(string id)
        //{
        //    string identity = IDHelper.IDToIdentity(id);
        //    DistINPublicKey? publicKey = Database.PublicKeys.Where(string.Format("[Identity]='{0}'", identity.ToSqlSafeValue())).FirstOrDefault();
        //    if(publicKey == null)
        //    {
        //        return Json(new { success = false, reason = "Unknown ID." });
        //    }

        //    DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", id.ToSqlSafeValue(), "admin")).FirstOrDefault();
        //    bool isAdmin = attribute != null && attribute.Value.ToLower() == "true";


        //    DistINSignatureRequest signatureRequest = new DistINSignatureRequest()
        //    {
        //        Caption = "Login",
        //        Identity = identity,
        //        RemoteAddress = "",
        //        Challenge = IDGenerator.GenerateRandomString(128)
        //    };

        //    DateTime timeout = DateTime.Now.AddMinutes(3);

        //    AuthRequestCache.AddRequest(signatureRequest, timeout);
        //    DistINSignatureResponse? response = null;

        //    while (response == null && timeout < DateTime.Now)
        //    {
        //        Thread.Sleep(1000);
        //        response = AuthRequestCache.GetAndRemoveResponse(signatureRequest.ID);
        //    }

        //    if (response == null)
        //        return Json(new { success = false, reason = "Authentication timed out." });

        //    bool isValid = CryptHelper.VerifySinature(publicKey, response.Signature, Encoding.UTF8.GetBytes(signatureRequest.Challenge));

        //    if (!isValid)
        //        return Json(new { success = false, reason = "Invalid authentication signature." });

        //    this.HttpContext.Login(identity, isAdmin);

        //    return Json(new { success = true, reason = "Valid." });
        //}
    }
}
