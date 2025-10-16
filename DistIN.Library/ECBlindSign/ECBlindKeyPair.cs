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
    public class ECBlindKeyPair
    {
        public BigInteger PrivateKey { get; set; }
        public ECPoint PublicKey { get; set; }

        public ECBlindKeyPair(BigInteger privateKey, ECPoint publicKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}
