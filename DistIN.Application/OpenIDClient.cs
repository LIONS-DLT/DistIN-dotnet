namespace DistIN.Application
{
    public class OpenIDClient : DistINObject
    {
        public string Secret { get; set; } = IDGenerator.GenerateStrongGUID();
    }
}
