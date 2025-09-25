using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace DistIN
{
    public class OneTimeSignature : DistINObject
    {
        public string Identity { get; set; } = string.Empty;
        public string IdentitySignature { get; set; } = string.Empty;

        public OneTimeSignatureAlgorithm Algorithm { get; set; } = OneTimeSignatureAlgorithm.RSA;
        public string Key { get; set; } = string.Empty;
        public string Date { get; set; } = DateTime.Now.ToString("yyyy/MM/dd");
        public string Signature { get; set; } = string.Empty;

        public string GetSignedPayloadString()
        {
            return string.Format("{0}|{1}|{2}|{3}|{4}", this.ID, this.Identity, this.Key, this.Signature, this.Date);
        }

        public byte[] GetSignedPayload()
        {
            return Encoding.UTF8.GetBytes(this.GetSignedPayloadString());
        }

        public void CreateSignatureAndKey(string data)
        {
                    this.Date = DateTime.Now.ToString("yyyy/MM/dd");
            if (this.Algorithm == OneTimeSignatureAlgorithm.RSA)
            {
                byte[] bytes = CryptHelper.DecodeUrlBase64(data);
                using (RSA rsa = RSA.Create(1024))
                {
                    this.Key = CryptHelper.EncodeUrlBase64(rsa.ExportRSAPublicKey());
                    this.Signature = CryptHelper.EncodeUrlBase64(rsa.SignData(bytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
                }
            }
            else if (this.Algorithm == OneTimeSignatureAlgorithm.ECDSA)
            {
                byte[] bytes = CryptHelper.DecodeUrlBase64(data);
                using (ECDsa rsa = ECDsa.Create())
                {
                    this.Key = CryptHelper.EncodeUrlBase64(rsa.ExportSubjectPublicKeyInfo());
                    this.Signature = CryptHelper.EncodeUrlBase64(rsa.SignData(bytes, HashAlgorithmName.SHA512));
                }
            }
            else if (this.Algorithm == OneTimeSignatureAlgorithm.DILITHIUM)
            {
                byte[] bytes = CryptHelper.DecodeUrlBase64(data);

                DistINKeyPair keyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.DILITHIUM);
                this.Key = keyPair.PublicKey;
                this.Signature = CryptHelper.SignData(keyPair, bytes);
            }
            else if (this.Algorithm == OneTimeSignatureAlgorithm.FALCON)
            {
                byte[] bytes = CryptHelper.DecodeUrlBase64(data);

                DistINKeyPair keyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.FALCON_512);
                this.Key = keyPair.PublicKey;
                this.Signature = CryptHelper.SignData(keyPair, bytes);
            }
        }
    }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum OneTimeSignatureAlgorithm
    {
        DILITHIUM,
        FALCON,
        RSA,
        ECDSA
    }
}
