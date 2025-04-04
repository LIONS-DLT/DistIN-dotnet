using DistIN.Application.DistNet;
using Microsoft.AspNetCore.Mvc;
using System.Security.Principal;
using System.Text;

namespace DistIN.Application.Controllers
{
    public class NodeController : Controller
    {
        private static List<DistNetNode> _neighbours = new List<DistNetNode>();
        private static List<DistNetNode> _neighboursNeighbours = new List<DistNetNode>();
        private static List<KeyValuePair<string, DistNetMessage>> _delayedMessages = new List<KeyValuePair<string, DistNetMessage>>();

        public static void InitNeighbours()
        {
            _neighbours = Database.DistNetNodes.Where("[IsNeighbour]=1");
            _neighboursNeighbours = Database.DistNetNodes.Where("[IsNeighboursNeighbour]=1");
        }


        [HttpGet]
        public IActionResult PublicKey(string? date)
        {
            string identity = IDHelper.IDToIdentity("root");

            if (!string.IsNullOrEmpty(date))
            {
                DateTime dateTime = DateTime.Parse(date);
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' AND [Date]<{1} ORDER BY [Date] DESC",
                    identity.ToSqlSafeValue(), dateTime.Ticks)).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return Json(key);
            }
            else
            {
                DistINPublicKey? key = Database.PublicKeys.Where(
                    string.Format("Identity='{0}' ORDER BY [Date] DESC", identity.ToSqlSafeValue())).FirstOrDefault();
                if (key == null)
                    return StatusCode(StatusCodes.Status404NotFound);
                return Json(key);
            }
        }

        [HttpGet]
        public IActionResult ID()
        {
            DistNetID id = new DistNetID()
            {
                ID = AppConfig.Current.ServiceDomain,
                Key = AppConfig.Current.ServiceKeyPair.Algorithm.ToString() + ":" + AppConfig.Current.ServiceKeyPair.PublicKey,
                Signature = CryptHelper.SignData(AppConfig.Current.ServiceKeyPair, Encoding.UTF8.GetBytes(AppConfig.Current.ServiceKeyPair.PublicKey)) 
                // TODO: hash signature for performance reasons
            };

            return Json(id);
        }

        [HttpGet]
        public IActionResult List(string? filter)
        {
            if (string.IsNullOrEmpty(filter))
                return Json(new { nodes = Database.DistNetNodes.All() });
            else if (filter.ToLower() == "n")
                return Json(new { nodes = _neighbours });
            else if (filter.ToLower() == "nn")
            {
                List<DistNetNode> result = new List<DistNetNode>();
                result.AddRange(_neighbours);
                result.AddRange(_neighboursNeighbours);
                return Json(new { nodes = result });
            }
            else
                return StatusCode(StatusCodes.Status400BadRequest);
        }

        public IActionResult Connect(DistNetMessage msg)
        {
            if(!validateMessage(msg))
                return StatusCode(StatusCodes.Status400BadRequest);

            DistNetNode node = new DistNetNode()
            {
                Serial = msg.Serial,
                ID = msg.ID,
                Key = msg.NewKey,
                IsNeighbour = true
            };

            Database.DistNetNodes.InsertOrUpdate(node);

            // remove old:
            _neighbours.RemoveAll(n => n.ID == node.ID);

            // add new neighbour to cache:
            _neighbours.Add(node);

            return Json(new { neighbours = _neighbours });
        }

        public IActionResult Message(DistNetMessage msg)
        {
            if (!validateMessage(msg))
                return StatusCode(StatusCodes.Status400BadRequest);

            DistNetNode? node = Database.DistNetNodes.Find(msg.ID);

            if(node == null)
            {
                Database.DistNetNodes.Insert(new DistNetNode()
                {
                    Serial = msg.Serial,
                    ID = msg.ID,
                    Key = msg.NewKey,
                    IsNeighbour = true
                });

                ForwardMessage(msg);
            }
            else
            {
                if (node.Serial >= msg.Serial)
                    return StatusCode(StatusCodes.Status200OK); // already received

                node.Key = msg.NewKey;
                node.Serial = msg.Serial;

                Database.DistNetNodes.Update(node);

                ForwardMessage(msg);
            }

            return StatusCode(StatusCodes.Status200OK);
        }



        public static void ForwardMessage(DistNetMessage msg)
        {
            List<DistNetNode> nodelist = new List<DistNetNode>();
            nodelist.AddRange(_neighbours);
            nodelist.AddRange(_neighboursNeighbours);

            foreach(DistNetNode node in nodelist)
            {
                sendMessage(node.ID, msg);
            }
        }

        private static void sendMessage(string id, DistNetMessage msg)
        {
            using (HttpClient http = new HttpClient())
            {
                var status = http.PostAsync(string.Format("https://{0}/Node/Message", id), JsonContent.Create(msg)).Result.StatusCode;

                if (status != System.Net.HttpStatusCode.OK && status != System.Net.HttpStatusCode.BadRequest)
                {
                    // remember and try again later...
                    lock (_delayedMessages)
                    {
                        _delayedMessages.Add(new KeyValuePair<string, DistNetMessage>(id, msg));
                    }
                }
            }
        }

        private bool validateMessage(DistNetMessage msg)
        {
            if (!validateSignature(msg.NewKey, msg.NewKey, msg.NewSignature))
                return false;

            DistNetNode? node = Database.DistNetNodes.Find(msg.ID);

            if(node != null)
            {
                return validateSignature(node.Key, msg.NewKey, msg.Signature);
            }
            else
            {
                using (HttpClient http = new HttpClient())
                {
                    DistNetID? id = http.GetAsync(string.Format("https://{0}/Node/ID", msg.ID)).Result.Content.ReadFromJsonAsync<DistNetID>().Result;

                    if (id == null)
                        return false;

                    return id.Key == msg.NewKey;
                }
            }
        }

        private bool validateSignature(string key, string data, string signature)
        {
            DistINKeyAlgorithm algorithm = Enum.Parse<DistINKeyAlgorithm>(key.Split(':')[0]);
            string pKey = key.Split(':')[1];
            return CryptHelper.VerifySinature(algorithm, pKey, signature, Encoding.UTF8.GetBytes(data));
        }
    }
}
