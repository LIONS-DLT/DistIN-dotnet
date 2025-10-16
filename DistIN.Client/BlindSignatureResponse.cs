using DistIN.ECBlindSign;
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
    public class ECBlindSignatureResponse
    {
        public OneTimeSignature BlindSignature { get; set; }

        public ECBlindSignature Signature { get; set; }

        public ECBlindSignatureResponse(OneTimeSignature blindSignature, ECBlindSignature signature)
        {
            BlindSignature = blindSignature;
            Signature = signature;
        }
    }
}
