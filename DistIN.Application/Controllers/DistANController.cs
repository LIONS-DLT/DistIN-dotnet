using DistIN.DistAN;
using Microsoft.AspNetCore.Mvc;

namespace DistIN.Application.Controllers
{
    [Route("distan")]
    public class DistANController : DistINController
    {

        [HttpPost]
        public IActionResult Message()
        {
            string identity = this.HttpContext.Request.Headers["DistIN-ID"];

            if (!string.IsNullOrEmpty(identity) || !identity.Contains('@'))
                return StatusCode(StatusCodes.Status401Unauthorized);

            string domain = identity.Split('@')[1];

            DistANMessage? msg = getRequestObject<DistANMessage>();
            if (msg == null || string.IsNullOrEmpty(msg.Recipient) || !msg.Recipient.Contains('@') || identity != msg.Sender || msg.Recipient.Split('@')[1] != AppConfig.Current.ServiceDomain)
                return StatusCode(StatusCodes.Status400BadRequest);

            if(msg.Recipient.Split('@')[1] != AppConfig.Current.ServiceDomain)
                return StatusCode(StatusCodes.Status400BadRequest);

            msg.ID = IDGenerator.GenerateStrongGUID();
            Database.Messages.Insert(msg);

            return getSignedObjectResult(msg);
        }

        [HttpGet]
        public IActionResult Messages()
        {
            if (!checkToken())
                return StatusCode(StatusCodes.Status401Unauthorized);

            string identity = this.HttpContext.Request.Headers["DistIN-ID"];
            DistANMessage? msg = getRequestObject<DistANMessage>();
            if (msg == null)
                return StatusCode(StatusCodes.Status400BadRequest);

            DistANMessageList result = new DistANMessageList();
            result.Messages = Database.Messages.Where(string.Format("[Recipient]='{0}'", identity));

            foreach (DistANMessage m in result.Messages)
                Database.Messages.Delete(m.ID);

            return getSignedObjectResult(result);
        }
    }
}
