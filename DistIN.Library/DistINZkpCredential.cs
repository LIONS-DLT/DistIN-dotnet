using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Hyperledger.Ursa.BbsSignatures;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace DistIN
{
    public class DistINZkpCredential : JsonSerializableObject
    {
        public string Issuer { get; set; } = string.Empty;
        public string IssuerPublicBbsKey { get; set; } = string.Empty;
        public string IssuerSignature { get; set; } = string.Empty;
        public string[] Messages { get; set; } = new string[0];


        public static string GenerateIssuerBBSKey()
        {
            var bbs = new BbsSignatureService();
            var keyPair = bbs.GenerateBlsKey();

            return CryptHelper.EncodeUrlBase64(keyPair.SecretKey!.ToArray());
        }

        public static DistINZkpCredential IssueCredential(string issuerIdentity, string issuerBBSKey, string[] messages)
        {
            var bbs = new BbsSignatureService();
            BlsKeyPair keyPair = new BlsKeyPair(CryptHelper.DecodeUrlBase64(issuerBBSKey));
            var signature = bbs.Sign(new SignRequest(keyPair, messages));

            DistINZkpCredential credential = new DistINZkpCredential()
            {
                Issuer = issuerIdentity,
                IssuerPublicBbsKey = CryptHelper.EncodeUrlBase64(keyPair.PublicKey!.ToArray()),
                IssuerSignature = CryptHelper.EncodeUrlBase64(signature),
                Messages = messages.ToArray()
            };

            return credential;
        }

        public DistINZkpProof CreateProof(int[] messagesToRevealIndices, string nonce)
        {
            DistINZkpProof proof = new DistINZkpProof();

            proof.Issuer = this.Issuer;
            proof.IssuerPublicBbsKey = this.IssuerPublicBbsKey;
            proof.IssuerSignature = this.IssuerSignature;
            proof.MessageCount = this.Messages.Length;

            List<DistINZkpProofMessage> messageList = new List<DistINZkpProofMessage>();
            foreach (int i in messagesToRevealIndices)
            {
                messageList.Add(new DistINZkpProofMessage()
                {
                    Index = i,
                    Message = this.Messages[i]
                });
            }
            proof.Messages = messageList.ToArray();

            List<ProofMessage> proofMessages = new List<ProofMessage>();
            for (int i = 0; i < this.Messages.Length; i++)
            {
                proofMessages.Add(new ProofMessage()
                {
                    Message = this.Messages[i],
                    ProofType = messagesToRevealIndices.Contains(i) ? ProofMessageType.Revealed : ProofMessageType.HiddenProofSpecificBlinding
                });
            }

            var bbs = new BbsSignatureService();
            var blindingFactor = generateBlindingFactorBytes();
            BlsKeyPair keyPair = new BlsKeyPair(CryptHelper.DecodeUrlBase64(this.IssuerPublicBbsKey));
            BbsKeyPair bbsPublicKey = keyPair.GeyBbsKeyPair((uint)proof.MessageCount);

            proof.Proof = CryptHelper.EncodeUrlBase64(bbs.CreateProof(new CreateProofRequest(bbsPublicKey, proofMessages.ToArray(), 
                CryptHelper.DecodeUrlBase64(this.IssuerSignature), blindingFactor, nonce)));

            return proof;
        }

        public static bool VerifyProof(DistINZkpProof proof, string nonce)
        {
            var bbs = new BbsSignatureService();

            BlsKeyPair keyPair = new BlsKeyPair(CryptHelper.DecodeUrlBase64(proof.IssuerPublicBbsKey));
            BbsKeyPair bbsPublicKey = keyPair.GeyBbsKeyPair((uint)proof.MessageCount);

            List<IndexedMessage> indexedMessages = new List<IndexedMessage>();
            foreach(var msg in proof.Messages)
            {
                indexedMessages.Add(new IndexedMessage()
                {
                    Message = msg.Message,
                    Index = (uint)msg.Index
                });
            }

            return bbs.VerifyProof(new VerifyProofRequest(bbsPublicKey, CryptHelper.DecodeUrlBase64(proof.Proof), indexedMessages.ToArray(), nonce)) == SignatureProofStatus.Success;
        }

        private static readonly BigInteger FrOrder = new BigInteger(
"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

        private static byte[] generateBlindingFactorBytes()
        {
            // Ziel: gleichverteiltes b in [1, r-1] (NICHT 0)
            var rng = new SecureRandom();
            byte[] buf = new byte[FrOrder.ToByteArrayUnsigned().Length]; // 32 Bytes
            BigInteger b;

            do
            {
                rng.NextBytes(buf);
                // Interpretiere als UNSIGNED BigInteger (big-endian)
                b = new BigInteger(1, buf);
                // Reduktion via Rejection Sampling statt Mod, um Uniformität zu wahren:
                // -> verwerfe, wenn b >= r oder b == 0
            } while (b.SignValue == 0 || b.CompareTo(FrOrder) >= 0);

            // Falls die Bibliothek LITTLE-ENDIAN will, kehre die Bytes um:
            // (Viele BBS/BLS-Bindings erwarten little-endian 32B für Skalar.)
            Array.Reverse(buf); // jetzt little-endian Repräsentation

            return buf; // 32-Byte little-endian Skalar in [1, r-1]
        }
    }

    public class DistINZkpProof : JsonSerializableObject
    {
        public string Issuer { get; set; } = string.Empty;
        public string IssuerPublicBbsKey { get; set; } = string.Empty;
        public string IssuerSignature { get; set; } = string.Empty;
        public int MessageCount { get; set; }
        public string Proof { get; set; } = string.Empty;
        public DistINZkpProofMessage[] Messages { get; set; } = new DistINZkpProofMessage[0];
    }

    public class DistINZkpProofMessage : JsonSerializableObject
    {
        public string Message { get; set; } = string.Empty;
        public int Index { get; set; }
    }
}
