using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application
{
    public class LoginRequiredAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!filterContext.HttpContext.IsLoggedIn())
                filterContext.Result = new RedirectResult("/Home/Index");
        }
    }
    public class AdminRequiredAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!filterContext.HttpContext.IsLoggedInAdmin())
                filterContext.Result = new RedirectResult("/Home/Index");
        }
    }
}
