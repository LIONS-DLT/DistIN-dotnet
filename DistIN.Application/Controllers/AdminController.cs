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
            return View();
        }
    }
}
