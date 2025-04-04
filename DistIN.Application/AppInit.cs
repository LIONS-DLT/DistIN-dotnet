using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using System.Globalization;
using System.Text;
using DistIN.Application.DistNet;

namespace DistIN.Application
{
    public static class AppInit
    {
        public static bool IsFirstStart { get; set; } = false;
        public static string AppDataPath { get; private set; } = string.Empty;
        public static string ProductName { get; private set; } = "DistIN";

        public static void Init(IWebHostEnvironment environment)
        {
            AppDataPath = Path.Combine(environment.ContentRootPath, "App_Data");
            if (!Directory.Exists(AppDataPath))
                Directory.CreateDirectory(AppDataPath);

            string databaseFile = Path.Combine(AppDataPath, "distin.db");

            AppConfig.Init();
            Database.Init(databaseFile, () =>
            {
                // database seed
                Database.PublicKeys.Insert(new DistINPublicKey()
                {
                    Identity = IDHelper.IDToIdentity("root"),
                    Algorithm = AppConfig.Current.ServiceKeyPair.Algorithm,
                    Key = AppConfig.Current.ServiceKeyPair.PublicKey,
                    Date = DateTime.Now,
                    Signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, Encoding.UTF8.GetBytes(AppConfig.Current.ServiceKeyPair.PublicKey)),
                });

                IsFirstStart = true;

                //demoSeed();
            });

            Controllers.NodeController.InitNeighbours();

            AsyncWorker.Init();
        }

        private static void demoSeed()
        {
            List<object> demoIdentities = new List<object>();
            string demoFile = Path.Combine(AppDataPath, "demo.json");

            for (int i = 0; i <= 9; i++)
            {
                DistINKeyPair keyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.DILITHIUM);
                DistINPublicKey id = new DistINPublicKey()
                {
                    Identity = string.Format("demo{0}@", i) + AppConfig.Current.ServiceDomain,
                    Algorithm = keyPair.Algorithm,
                    Key = keyPair.PublicKey,
                    Date = DateTime.Now,
                    Signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, Encoding.UTF8.GetBytes(AppConfig.Current.ServiceKeyPair.PublicKey)),
                };
                Database.PublicKeys.Insert(id);

                DistINKeyPair mpk = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.KYBER);

                DistINAttribute attribute = new DistINAttribute()
                {
                    Identity = id.Identity,
                    MimeType = DistINMimeTypes.TEXT,
                    Name = "DistINMessagingKey",
                    Value = mpk.PublicKey,
                    IsPublic = true,
                };
                Database.Attributes.Insert(attribute);

                var obj = new
                {
                    id = id.Identity,
                    dilithium = keyPair,
                    kyber = mpk
                };

                demoIdentities.Add(obj);
            }

            File.WriteAllText(demoFile, System.Text.Json.JsonSerializer.Serialize(demoIdentities, new System.Text.Json.JsonSerializerOptions()
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }));
        }



        public static void OnActionExecuting(Controller controller, ActionExecutingContext context)
        {
            // handle optional alert parameters
            controller.ViewData["alert_success"] = controller.Request.Query["alert_success"].FirstOrDefault();
            controller.ViewData["alert_error"] = controller.Request.Query["alert_error"].FirstOrDefault();
            controller.ViewData["alert_info"] = controller.Request.Query["alert_info"].FirstOrDefault();

            // set culture from session / browser settings

            CultureInfo culture = CultureInfo.InvariantCulture;
            string? sessionCulture = controller.HttpContext.Session.GetString("CultureInfo");

            if (!string.IsNullOrEmpty(sessionCulture))
            {
                culture = new CultureInfo(sessionCulture);
            }
            else
            {
                string? lang = controller.Request.Headers["Accept-Language"];
                if (!string.IsNullOrEmpty(lang))
                {
                    var firstLang = lang.Split(',').FirstOrDefault();
                    if (!string.IsNullOrEmpty(firstLang))
                        culture = new CultureInfo(firstLang);
                }


                controller.HttpContext.Session.SetString("CultureInfo", culture.TwoLetterISOLanguageName);
            }

            CultureInfo.CurrentCulture = culture;
            CultureInfo.CurrentUICulture = culture;
        }

        public static void RenewKey()
        {
            var oldKeyPair = AppConfig.Current.ServiceKeyPair;
            AppConfig.Current.ServiceKeyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.DILITHIUM);
            Database.PublicKeys.Insert(new DistINPublicKey()
            {
                Identity = IDHelper.IDToIdentity("root"),
                Algorithm = AppConfig.Current.ServiceKeyPair.Algorithm,
                Key = AppConfig.Current.ServiceKeyPair.PublicKey,
                Date = DateTime.Now,
                Signature = CryptHelper.SignData(oldKeyPair, Encoding.UTF8.GetBytes(AppConfig.Current.ServiceKeyPair.PublicKey)),
            });
            AppConfig.Save();

            DistNet_BroadcastKey();
        }

        public static System.Net.HttpStatusCode DistNet_Connect(string connectionNodeID)
        {
            var keys = Database.PublicKeys.All().OrderBy(x => x.Date).ToList();

            var key = keys.Last();

            DistNetMessage msg = new DistNetMessage();
            msg.Serial = Database.PublicKeys.All().Count();
            msg.NewKey = key.Algorithm.ToString() + ":" + key.Key;
            msg.NewSignature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, Encoding.UTF8.GetBytes(key.Key));
            msg.Signature = key.Signature;

            using (HttpClient http = new HttpClient())
            {
                return http.PostAsync(string.Format("https://{0}/Node/Connect", connectionNodeID), JsonContent.Create(msg)).Result.StatusCode;
            }
        }

        public static void DistNet_BroadcastKey()
        {
            var keys = Database.PublicKeys.All().OrderBy(x => x.Date).ToList();

            var key = keys.Last();

            DistNetMessage msg = new DistNetMessage();
            msg.Serial = Database.PublicKeys.All().Count();
            msg.NewKey = key.Algorithm.ToString() + ":" + key.Key;
            msg.NewSignature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, Encoding.UTF8.GetBytes(key.Key));
            msg.Signature = key.Signature;
            
            Controllers.NodeController.ForwardMessage(msg);
        }
    }
}
