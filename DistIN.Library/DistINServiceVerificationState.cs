using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINServiceVerificationState
    {
        public ServiceVerificationType Type { get; set; } = ServiceVerificationType.DNS;
        public bool Valid { get; set; } = false;
    }

    public enum ServiceVerificationType
    {
        DNS,
        ETHEREUM
    }
}
