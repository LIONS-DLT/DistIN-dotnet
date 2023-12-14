using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINCredential : DistINObject
    {
        public string Type { get; set; } = string.Empty;
        public string MimeType { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;

        public string Subject { get; set; } = string.Empty;

        public string Issuer { get; set; } = string.Empty;
        public DateTime IssuanceDate { get; set; } = DateTime.Now;
        public string Signature { get; set; } = string.Empty;
    }
}
