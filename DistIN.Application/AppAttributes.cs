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

    //[AttributeUsage(AttributeTargets.Method)]
    //public class ApiReturnTypeAttribute : Attribute
    //{
    //    public Type ReturnType { get; set; }

    //    public ApiReturnTypeAttribute(Type type) 
    //    { 
    //        ReturnType = type;
    //    }
    //}

    [AttributeUsage(AttributeTargets.Method)]
    public class ApiDefinitionAttribute : Attribute
    {
        public Type? InputType { get; set; }
        public Type? ReturnType { get; set; }

        public ApiDefinitionAttribute(Type inputType, Type returnType)
        {
            InputType = inputType;
            ReturnType = returnType;
        }
        public ApiDefinitionAttribute(Type returnType)
        {
            InputType = null;
            ReturnType = returnType;
        }
        public ApiDefinitionAttribute()
        {
            InputType = null;
            ReturnType = null;
        }
    }
}
