using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    [Route("distin")]
    public class DistINController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
