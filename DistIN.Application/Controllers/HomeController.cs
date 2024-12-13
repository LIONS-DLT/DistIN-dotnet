using DistIN.Application.Models;
using Microsoft.AspNetCore.Mvc;
using Net.Codecrete.QrCodeGenerator;
using Org.BouncyCastle.Asn1.Cmp;
using System.ComponentModel.DataAnnotations;
using System;
using System.Diagnostics;
using System.Text;
using System.Security.Principal;

namespace DistIN.Application.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            if(AppInit.IsFirstStart)
            {
                return RedirectToAction("FirstStart", "Home");
            }
            return View();
        }
        public IActionResult Login(string id)
        {
            if (string.IsNullOrEmpty(id))
                return Json(new { success = false, reason = "Invalid identity." });

            if (!id.EndsWith("@" + AppConfig.Current.ServiceDomain))
                return Json(new { success = false, reason = "Invalid identity." });

            DistINPublicKey publicKey = AppCache.GetPublicKey(id);
            if (publicKey == null)
                return Json(new { success = false, reason = "Invalid identity." });


            string challenge = IDGenerator.GenerateRandomString(32);

            DistINSignatureResponse? response = Controllers.DistINController.performAuthenticationRequest(this.HttpContext, IDHelper.IdentityToID(id), challenge, "Login", null, null);
            if (response == null)
                return Json(new { success = false, reason = "Timed out." });

            if (!CryptHelper.VerifySinature(publicKey, response.Signature, Encoding.UTF8.GetBytes(challenge)))
                return Json(new { success = false, reason = "Invalid signature." });

            DistINAttribute? attribute = Database.Attributes.Where(string.Format("[Identity]='{0}' AND [Name]='{1}'", id.ToSqlSafeValue(), "admin")).FirstOrDefault();
            bool isAdmin = attribute != null && attribute.Value.ToLower() == "true";

            this.HttpContext.Login(id, isAdmin);

            return Json(new { success = true, reason = "Valid." });
        }

        public IActionResult FirstStart()
        {
            if (!AppInit.IsFirstStart)
                return RedirectToAction("Index", "Home");

            return View();
        }
        public IActionResult FirstStartContinue(string domain)
        {
            if (!AppInit.IsFirstStart)
                return RedirectToAction("Index", "Home");

            AppConfig.Current.ServiceDomain = domain;
            AppConfig.Save();


            string identity = IDHelper.IDToIdentity("admin");
            LoginRequestCache.AddIdForRegistration(identity);

            ViewData["domain"] = domain;
            ViewData["qrcontent"] = "create|" + identity;

            return View();
        }
        public IActionResult FirstStartConfirm(string domain)
        {
            string identity = IDHelper.IDToIdentity("admin");
            if (LoginRequestCache.HasIdForRegistration(identity))
                return RedirectToAction("FirstStartContinue", "Home", new { domain = domain });
            else
            {
                AppInit.IsFirstStart = false;

                DistINAttribute attribute =new DistINAttribute();
                attribute.Identity = IDHelper.IDToIdentity("admin");
                attribute.Name = "admin";
                attribute.Value = "true";
                attribute.MimeType = "text/plain";
                attribute.IsPublic = false;
                
                Database.Attributes.Insert(attribute);

                return RedirectToAction("Index", "Home");
            }
        }

        public IActionResult QR(string qrcontent)
        {
            byte[] data = Encoding.UTF8.GetBytes(QrCode.EncodeText(qrcontent, QrCode.Ecc.Low).ToSvgString(4, "#000000", "#ffffff"));
            return File(data, "image/svg+xml", "qr.svg");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}