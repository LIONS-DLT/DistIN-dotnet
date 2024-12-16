using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN.DistAN
{
    public class DistANMessage : DistINObject
    {
        public string AppId { get; set; } = string.Empty;
        public string Sender { get; set; } = string.Empty;
        public string Recipient { get; set; } = string.Empty;
        public string EncryptedKey { get; set; } = string.Empty;
        public string EncryptedMessage { get; set; } = string.Empty;

        public byte[] GetDecryptedMessage(string privateMsgKey)
        {
            byte[] aesKey = CryptHelper.DecryptKyberAESKey(privateMsgKey, this.EncryptedKey);
            return CryptHelper.DecryptAES(CryptHelper.DecodeUrlBase64(this.EncryptedMessage), aesKey);
        }

        public static DistANMessage CreateMessage(string appId, string sender, string recipient, string recipientPublicMsgKey, byte[] data)
        {
            DistANMessage msg = new DistANMessage();
            msg.AppId = appId;
            msg.Sender = sender;
            msg.Recipient = recipient;

            byte[] aes;
            msg.EncryptedKey = CryptHelper.GenerateAndEncryptKyberAESKey(recipientPublicMsgKey, out aes);
            msg.EncryptedMessage = CryptHelper.EncodeUrlBase64(CryptHelper.EncryptAES(data, aes));

            return msg;
        }
    }

    public class DistANMessageList : DistINObject
    {
        public List<DistANMessage> Messages { get; set; } = new List<DistANMessage>();
    }
}
