using Microsoft.AspNetCore.Mvc;
using System.Security.Principal;

namespace DistIN.Application.Controllers
{
    [AdminRequired]
    public class AdminController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Identities()
        {
            return View(Database.PublicKeys.All());
        }

        public IActionResult RegisterIdentity()
        {
            return View();
        }
        public IActionResult StartRegistration(string id)
        {
            string identity = id.Contains('@') ? id : IDHelper.IDToIdentity(id);

            LoginRequestCache.AddIdForRegistration(identity);

            string challangeId = IDGenerator.GenerateGUID();
            string challangeCode = LoginRequestCache.CreateChallange(challangeId);

            ViewData["id"] = identity;
            ViewData["qrcontent"] = "create|" + identity + "|" + challangeId + "|" + challangeCode;

            return View();
        }
        public IActionResult FinishRegistration(string id)
        {
            if (LoginRequestCache.HasIdForRegistration(id))
                return RedirectToAction("StartRegistration", "Admin", new { id = id });
            else
            {
                DistINAttribute attribute = new DistINAttribute();
                attribute.Identity = id;
                attribute.Name = "DistINRole";
                attribute.Value = "Identity";
                attribute.MimeType = DistINMimeTypes.TEXT;
                attribute.IsPublic = true;

                Database.Attributes.Insert(attribute);

                return RedirectToAction("Index", "Admin");
            }
        }
    }
}
