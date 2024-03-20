using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    [Route("distan")]
    public class DistANController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
