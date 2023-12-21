namespace DistIN.Application
{
    public class AppConfig
    {
        public static AppConfig Current { get; private set; } = new AppConfig();


        public string ServiceDomain { get; set; } = "id.example.org";
        public DistINServiceVerificationType ServiceVerificationType { get; set; } = DistINServiceVerificationType.DNS;

        public DistINKeyPair ServiceKeyPair { get; set; } = new DistINKeyPair();

        public string EthereumUrl { get; set; } = string.Empty;
        public string EthereumPrivateKey { get; set; } = string.Empty;
        public string EthereumContractAddressDocs { get; set; } = string.Empty;
        public string EthereumContractAddressSigns { get; set; } = string.Empty;


        public static void Init()
        {
            string filepath = Path.Combine(AppInit.AppDataPath, "config.json");

            if (File.Exists(filepath))
            {
                Current = System.Text.Json.JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(filepath), new System.Text.Json.JsonSerializerOptions()
                {
                    PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                    WriteIndented = true
                })!;
                if(Current.ServiceKeyPair == null)
                    Current.ServiceKeyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.DILITHIUM);
            }
            else
            {
                Current.ServiceKeyPair = CryptHelper.GenerateKeyPair(DistINKeyAlgorithm.DILITHIUM);
                Save();
            }
        }
        public static void Save()
        {
            string filepath = Path.Combine(AppInit.AppDataPath, "config.json");

            File.WriteAllText(filepath, System.Text.Json.JsonSerializer.Serialize(Current, new System.Text.Json.JsonSerializerOptions()
            {
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                WriteIndented = true
            }));
        }
    }
}
