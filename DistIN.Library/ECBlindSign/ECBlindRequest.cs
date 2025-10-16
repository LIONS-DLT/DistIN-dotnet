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
    public class ECBlindRequest
    {
        public ECPoint RPrime {  get; set; }
        public BigInteger EPrime { get; set; }
        public BigInteger BlindingFactor {  get; set; }

        public ECBlindRequest(ECPoint rPrime, BigInteger ePrime, BigInteger blindingFactor)
        {
            RPrime = rPrime;
            EPrime = ePrime;
            BlindingFactor = blindingFactor;
        }
    }
}
