using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINServiceVerificationState : DistINObject
    {
        public string PublicKey { get; set; } = string.Empty;
        public DistINServiceVerificationType Type { get; set; } = DistINServiceVerificationType.DNS;
        public bool Valid { get; set; } = false;
    }

    public enum DistINServiceVerificationType
    {
        DNS,
        ETHEREUM
    }
}
