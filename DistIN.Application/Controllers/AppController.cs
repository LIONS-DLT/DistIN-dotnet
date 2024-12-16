using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Text;

namespace DistIN.Application.Controllers
{
    [LoginRequired]
    public class AppController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Attributes()
        {
            List<DistINAttribute> attributes = Database.Attributes.Where(string.Format("[Identity]='{0}'", this.HttpContext.GetIdentity()));

            return View(attributes);
        }

        public IActionResult Attribute(string id)
        {
            DistINAttribute? attribute = Database.Attributes.Find(id);
            if(attribute != null && attribute.Identity != this.HttpContext.GetIdentity())
                return StatusCode(StatusCodes.Status403Forbidden);

            if(attribute == null)
            {
                attribute = new DistINAttribute();
                attribute.Identity = this.HttpContext.GetIdentity();
                attribute.MimeType = DistINMimeTypes.TEXT;
            }

            return View(attribute);
        }

        public IActionResult ApplyAttribute(DistINAttribute attr)
        {
            DistINAttribute? attribute = Database.Attributes.Find(attr.ID);
            if (attribute == null)
                attribute = attr;

            if (attribute.Identity != this.HttpContext.GetIdentity())
                return StatusCode(StatusCodes.Status403Forbidden);

            Database.Attributes.InsertOrUpdate(attribute);
            return RedirectToAction("Attributes", "App");
        }

        public IActionResult DeleteAttribute(string id)
        {
            DistINAttribute? attribute = Database.Attributes.Find(id);
            if (attribute == null)
                return StatusCode(StatusCodes.Status404NotFound);

            if (attribute.Identity != this.HttpContext.GetIdentity())
                return StatusCode(StatusCodes.Status403Forbidden);


            Database.Attributes.Delete(attribute.ID);

            return RedirectToAction("Attributes", "App");
        }

        public IActionResult AttributeSignatures()
        {
            List<DistINAttributeSignature> signatures = Database.AttributeSignatures.Where(string.Format("[Signer]='{0}'", this.HttpContext.GetIdentity()));
            return View(signatures);
        }

        public IActionResult RevokeAttributeSignature(string id)
        {
            DistINAttributeSignature? signature = Database.AttributeSignatures.Find(id);

            if (signature == null)
                return StatusCode(StatusCodes.Status404NotFound);

            if (signature.Signer != this.HttpContext.GetIdentity())
                return StatusCode(StatusCodes.Status403Forbidden);

            Database.AttributeSignatures.Delete(id);

            return RedirectToAction("AttributeSignatures", "App");
        }
    }
}
