namespace DistIN.Application
{
    public class AppConfig
    {
        public static AppConfig Current { get; private set; } = new AppConfig();


        public string ServiceDomain { get; set; } = string.Empty;
        public string ServicePublicKey { get; set; } = string.Empty;
        public string ServicePrivateKey { get; set; } = string.Empty;
        public DistINKeyAlgorithm ServiceAlgorithm { get; set; } = DistINKeyAlgorithm.DILITHIUM;

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
            }
            else
            {
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
