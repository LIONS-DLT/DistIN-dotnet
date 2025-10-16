using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace DistIN.ECBlindSign
{
    public class ECBlindSignature
    {
        public ECPoint RPrime {  get; set; }
        public BigInteger S {  get; set; }

        public ECBlindSignature(ECPoint rprime, BigInteger s)
        {
            RPrime = rprime;
            S = s;
        }
    }
}
