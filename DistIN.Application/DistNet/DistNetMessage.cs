namespace DistIN.Application.DistNet
{
    public class DistNetMessage
    {
        public int Serial { get; set; }
        public string ID {  get; set; } = string.Empty;
        public string NewKey { get; set; } = string.Empty;
        public string NewSignature { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
    }

    public class DistNetDelayedMessage : DistINObject
    {
        public string NodeID { get; set; } = string.Empty;
        public int Serial { get; set; }
        public string NewKey { get; set; } = string.Empty;
        public string NewSignature { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
        public DateTime LastAttempt { get; set; } = DateTime.Now;
    }
}
