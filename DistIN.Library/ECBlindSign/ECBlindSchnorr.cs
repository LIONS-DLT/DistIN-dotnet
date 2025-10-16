using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace DistIN.ECBlindSign
{


    public class ECBlindSchnorr
    {
        private readonly ECDomainParameters _domain;
        public ECDomainParameters Domain { get { return _domain; } }

        private readonly SecureRandom _rng;
        public SecureRandom Random { get { return _rng; } }

        public ECBlindSchnorr()
        {
            var p = SecNamedCurves.GetByName(ECBlindCurve.secp256k1.ToString())
                    ?? throw new ArgumentException($"Unknown curve '{ECBlindCurve.secp256k1.ToString()}'. Try 'secp256k1' or 'secp256r1'.");
            _domain = new ECDomainParameters(p.Curve, p.G, p.N, p.H, p.GetSeed());
            _rng = new SecureRandom();
        }
        public ECBlindSchnorr(ECBlindCurve curve, SecureRandom? rng = null)
        {
            var p = SecNamedCurves.GetByName(curve.ToString())
                    ?? throw new ArgumentException($"Unknown curve '{curve.ToString()}'. Try 'secp256k1' or 'secp256r1'.");
            _domain = new ECDomainParameters(p.Curve, p.G, p.N, p.H, p.GetSeed());
            _rng = rng ?? new SecureRandom();
        }

        public ECBlindKeyPair GenerateKeyPair()
        {
            // x in [1, n-1]
            BigInteger x;
            do
            {
                x = new BigInteger(_domain.N.BitLength, _rng).Mod(_domain.N);
            } while (x.SignValue == 0);

            var P = _domain.G.Multiply(x).Normalize();
            return new ECBlindKeyPair(x, P);
        }

        // === Signer side ===

        /// <summary>
        /// Begin a signing session: picks nonce k and returns session (id, k, R=kG) and R for the requester.
        /// The signer must keep 'k' secret until 'SignerFinish' is called, then discard it.
        /// </summary>
        public ECBlindSignerSession SignerBeginSession()
        {
            BigInteger k;
            do
            {
                k = new BigInteger(_domain.N.BitLength, _rng).Mod(_domain.N);
            } while (k.SignValue == 0);

            var R = _domain.G.Multiply(k).Normalize();
            return new ECBlindSignerSession(Guid.NewGuid(), k, R);
        }

        /// <summary>
        /// Completes signing with blinded challenge e' from requester.
        /// Computes s' = k + e' * x mod n. Discard the session afterwards.
        /// </summary>
        public BigInteger SignerFinish(ECBlindSignerSession session, BigInteger signerPrivateKey, BigInteger ePrime)
        {
            var n = _domain.N;
            // s' = k + e' * x mod n
            var sPrime = session.K.Add(ePrime.Multiply(signerPrivateKey)).Mod(n);
            return sPrime;
        }

        // === Requester side ===

        /// <summary>
        /// Requester computes R' = R + bG and e' = H(R' || P || m)  (mod n), returns BlindRequest with (R', e', b).
        /// The requester sends only e' to the signer. Keep b secret for unblinding.
        /// </summary>
        public ECBlindRequest RequesterBlindMessage(ECPoint signerPublicKey, ECPoint R_fromSigner, byte[] message)
        {
            var n = _domain.N;

            BigInteger b;
            ECPoint Rprime;
            do
            {
                do { b = new BigInteger(n.BitLength, _rng).Mod(n); } while (b.SignValue == 0);
                Rprime = R_fromSigner.Add(_domain.G.Multiply(b)).Normalize();
            } while (Rprime.IsInfinity); // extrem selten, aber sicher ist sicher

            var ePrime = HashToScalar(Concat(
                Rprime.GetEncoded(true),
                signerPublicKey.GetEncoded(true),
                message));

            return new ECBlindRequest(Rprime, ePrime, b);
        }

        /// <summary>
        /// Requester unblinds the signer response s' using b: s = s' - b mod n, producing final signature (R', s).
        /// </summary>
        public ECBlindSignature RequesterUnblind(ECBlindRequest br, BigInteger sPrime)
        {
            var n = _domain.N;
            // Korrektur: + b statt - b
            var s = sPrime.Add(br.BlindingFactor).Mod(n);
            if (s.SignValue < 0) s = s.Add(n);
            return new ECBlindSignature(br.RPrime, s);
        }

        // === Verification ===

        /// <summary>
        /// Verify Schnorr signature: check sG == R' + eP with e = H(R' || P || m) mod n.
        /// </summary>
        public bool Verify(ECPoint publicKey, byte[] message, ECBlindSignature sig)
        {
            if (sig.RPrime.IsInfinity) return false;

            var n = _domain.N;

            var e = HashToScalar(Concat(
                sig.RPrime.GetEncoded(true),
                publicKey.GetEncoded(true),
                message));

            // left = sG
            var left = _domain.G.Multiply(NormalizeScalar(sig.S, n)).Normalize();

            // right = R' + eP
            var right = sig.RPrime.Add(publicKey.Multiply(e)).Normalize();

            return left.Equals(right);
        }

        // === Utilities ===

        private static byte[] Concat(params byte[][] arrays)
        {
            var total = 0;
            foreach (var a in arrays) total += a.Length;
            var buf = new byte[total];
            var pos = 0;
            foreach (var a in arrays)
            {
                Buffer.BlockCopy(a, 0, buf, pos, a.Length);
                pos += a.Length;
            }
            return buf;
        }

        /// <summary>
        /// Hash to scalar in [0, n-1] using SHA-256, reduced mod n.
        /// </summary>
        private BigInteger HashToScalar(byte[] data)
        {
            // SHA-256
            using var sha = System.Security.Cryptography.SHA256.Create();
            var h = sha.ComputeHash(data);

            // Interpret as positive integer and reduce mod n
            var bi = new BigInteger(1, h);
            return bi.Mod(_domain.N);
        }

        private static BigInteger NormalizeScalar(BigInteger x, BigInteger n)
        {
            var r = x.Mod(n);
            if (r.SignValue < 0) r = r.Add(n);
            return r;
        }

        // === Optional helpers for encoding signatures ===

        public byte[] EncodeSignatureCompact(ECBlindSignature sig)
        {
            // [lenR || R'(compressed) || s (fixed to curve order size)]
            var rEnc = sig.RPrime.GetEncoded(true);
            var sEnc = ToFixedLength(sig.S, _domain.N);
            var len = new byte[] { (byte)rEnc.Length };
            return Concat(len, rEnc, sEnc);
        }

        public ECBlindSignature DecodeSignatureCompact(byte[] blob)
        {
            if (blob.Length < 1) throw new ArgumentException("Invalid signature encoding.");
            int rLen = blob[0];
            if (blob.Length < 1 + rLen) throw new ArgumentException("Invalid signature encoding.");

            var rEnc = new byte[rLen];
            Buffer.BlockCopy(blob, 1, rEnc, 0, rLen);

            var sLen = blob.Length - 1 - rLen;
            var sEnc = new byte[sLen];
            Buffer.BlockCopy(blob, 1 + rLen, sEnc, 0, sLen);

            var Rprime = _domain.Curve.DecodePoint(rEnc).Normalize();
            var s = new BigInteger(1, sEnc);
            return new ECBlindSignature(Rprime, s);
        }

        private byte[] ToFixedLength(BigInteger x, BigInteger n)
        {
            var bytes = x.ToByteArrayUnsigned();
            var targetLen = (n.BitLength + 7) / 8;
            if (bytes.Length == targetLen) return bytes;
            if (bytes.Length > targetLen)
            {
                // Trim leading zeros if any
                var trimmed = new byte[targetLen];
                Buffer.BlockCopy(bytes, bytes.Length - targetLen, trimmed, 0, targetLen);
                return trimmed;
            }
            else
            {
                var padded = new byte[targetLen];
                Buffer.BlockCopy(bytes, 0, padded, targetLen - bytes.Length, bytes.Length);
                return padded;
            }
        }

    }

    public enum ECBlindCurve
    {
        secp256k1,
        secp256r1
    }
}
