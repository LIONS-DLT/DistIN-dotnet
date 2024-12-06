using Microsoft.AspNetCore.Http;
using System.Text;

namespace DistIN.Application
{
    public static class Extensions
    {
        public static string ToSqlSafeValue(this string value)
        {
            return value.Replace("'", "");
        }

        #region SESSION_EXTENSIONS

        public static bool IsLoggedIn(this HttpContext context)
        {
            return !string.IsNullOrEmpty(context.Session.GetString("identity"));
        }
        public static bool IsLoggedInAdmin(this HttpContext context)
        {
            return !string.IsNullOrEmpty(context.Session.GetString("identity")) && context.Session.GetInt32("admin")! > 0;
        }
        public static void Login(this HttpContext context, string identity, bool admin)
        {
            context.Session.SetString("identity", identity);
            context.Session.SetInt32("admin", admin ? 1 : 0);
        }
        public static void Logout(this HttpContext context)
        {
            context.Session.Remove("identity");
            context.Session.Remove("admin");
        }

        #endregion

    }

    public static class IDHelper
    {
        public static string IdentityToID(string identity)
        {
            return identity.Split('@')[0];
        }
        public static string IDToIdentity(string id)
        {
            return id + "@" + AppConfig.Current.ServiceDomain;
        }
    }
}
