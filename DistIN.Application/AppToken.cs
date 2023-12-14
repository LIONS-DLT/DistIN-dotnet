namespace DistIN.Application
{
    public class AppToken : DistINObject
    {
        [PropertyIsPrimaryKey]
        public override string ID { get; set; } = IDGenerator.GenerateStrongGUID();
        public string Identity { get; set; } = string.Empty;
        public DateTime ExpirationDate { get; set; } = DateTime.Now.AddDays(365);
    }
}
