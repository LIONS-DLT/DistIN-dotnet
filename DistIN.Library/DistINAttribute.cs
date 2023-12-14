using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINAttribute : DistINObject
    {
        [PropertyIsPrimaryKey]
        public override string ID { get; set; } = IDGenerator.GenerateStrongGUID();

        public string Name { get; set; } = string.Empty;
        public string MimeType { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public string Identity { get; set; } = string.Empty;


        [PropertyNotInDatabase]
        public List<DistINAttributeSignatureReference> SignatureReferences { get; set; } = new List<DistINAttributeSignatureReference>();
    }

    public static class DistINMimeTypes
    {
        public const string JSON = "application/json";
        public const string XML = "application/xml";
        public const string PDF = "application/pdf";
        public const string Binary = "application/octet-stream";
        public const string TEXT = "text/plain";
        public const string IMAGE = "image/*";
        public const string IMAGE_PNG = "image/png";
        public const string IMAGE_JPG = "image/jpg";
    }
}
