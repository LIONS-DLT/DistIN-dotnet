using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN.Client
{
    public class BlindSignatureResponse
    {
        public OneTimeSignature BlindSignature { get; set; }

        public byte[] Signature { get; set; }

        public BlindSignatureResponse(OneTimeSignature blindSignature, byte[] signature)
        {
            BlindSignature = blindSignature;
            Signature = signature;
        }
    }
}
