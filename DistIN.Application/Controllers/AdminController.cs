using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    public class AdminController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult RegisterIdentity()
        {
            return View();
        }
        public IActionResult StartRegistration(string id)
        {
            string identity = IDHelper.IDToIdentity(id);
            LoginRequestCache.AddIdForRegistration(identity);

            // TODO: generate QR

            return View();
        }
        public IActionResult CancelRegistration(string id)
        {
            string identity = IDHelper.IDToIdentity(id);
            LoginRequestCache.RemoveIdForRegistration(identity);

            return View();
        }
    }
}
