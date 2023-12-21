using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    public class AppController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
