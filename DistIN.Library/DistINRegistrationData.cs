using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINRegistrationData : DistINObject
    {
        public DistINPublicKey PublicKey { get; set; } = new DistINPublicKey();
        public string Signature { get; set; } = string.Empty;
    }
}
