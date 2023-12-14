using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINAttributeSignature : DistINObject
    {
        public string Identity { get; set; } = string.Empty;
        public string Attribute { get; set; } = string.Empty;
        public string Signer { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
        public DateTime Date { get; set; } = DateTime.Now;
    }
}
