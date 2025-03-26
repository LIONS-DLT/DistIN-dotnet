using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    public class OpenIDController : Controller
    {
        [Route(".well-known/openid-configuration")]
        public IActionResult Config()
        {
            return null;
        }

        [Route("token")]
        public IActionResult Token()
        {
            return null;
        }

        [Route("authorize")]
        public IActionResult Authorize()
        {
            return null;
        }

        [Route("userinfo")]
        public IActionResult UserInfo()
        {
            return null;
        }
    }
}
