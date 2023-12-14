using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINCredential : DistINObject
    {
        public string Content { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;

        public DistINCredentialContent ExportContent()
        {
            return JsonSerializer.Deserialize<DistINCredentialContent>(Encoding.UTF8.GetString(CryptHelper.DecodeUrlBase64(this.Content)), DistINObject.JsonSerializerOptions)!;
        }
        public void ImportContent(DistINCredentialContent content)
        {
            this.Content = CryptHelper.EncodeUrlBase64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(content, DistINObject.JsonSerializerOptions)));
        }

        public override string ToString()
        {
            return string.Format("{0}.{1}.{2}", this.ID, this.Content, this.Signature);
        }
        public static DistINCredential FromString(string credentialString)
        {
            string[] parts = credentialString.Split('.');
            DistINCredential credential = new DistINCredential();
            credential.ID = parts[0];
            credential.Content = parts[1];
            credential.Signature = parts[2];

            return credential;
        }

        public bool VerifySignature(DistINKeyAlgorithm algorithm, string publicKey)
        {
            return CryptHelper.VerifySinature(algorithm, publicKey, this.Signature, CryptHelper.DecodeUrlBase64(this.Content));
        }
        public bool VerifySignature(DistINPublicKey publicKey)
        {
            return CryptHelper.VerifySinature(publicKey, this.Signature, CryptHelper.DecodeUrlBase64(this.Content));
        }

        public void Sign(DistINKeyPair keyPair)
        {
            this.Signature = CryptHelper.SignData(keyPair, CryptHelper.DecodeUrlBase64(this.Content));
        }
    }

    public class DistINCredentialContent
    {
        public string Type { get; set; } = string.Empty;
        public string MimeType { get; set; } = string.Empty;
        public string Payload { get; set; } = string.Empty;

        public string Subject { get; set; } = string.Empty;

        public string Issuer { get; set; } = string.Empty;
        public DateTime IssuanceDate { get; set; } = DateTime.Now;
        public DateTime? ExpirationDate { get; set; } = null;
    }
}
