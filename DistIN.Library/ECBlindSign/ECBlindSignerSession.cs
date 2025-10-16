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
    public class ECBlindSignerSession
    {
        public Guid SessionGuid { get; set; }
        public BigInteger K {  get; set; }

        public ECPoint R { get; set; }

        public ECBlindSignerSession(Guid sessionGuid, BigInteger k, ECPoint r)
        {
            SessionGuid = sessionGuid;
            K = k;
            R = r;
        }
    }
}
