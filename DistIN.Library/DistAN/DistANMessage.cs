using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN.DistAN
{
    public class DistANMessage : DistINObject
    {
        public string Sender { get; set; } = string.Empty;
        public string Recipient { get; set; } = string.Empty;
        public string EncryptedKey { get; set; } = string.Empty;
        public string EncryptedMessage { get; set; } = string.Empty;
    }

    public class DistANMessageList : DistINObject
    {
        public List<DistANMessage> Messages { get; set; } = new List<DistANMessage>();
    }
}
