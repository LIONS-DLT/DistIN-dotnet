using System.Text.Json.Serialization;

namespace DistIN.Application.DistNet
{
    public class DistNetNode : DistINObject
    {
        public int Serial { get; set; }
        public string Key { get; set; } = string.Empty;

        [JsonIgnore]
        public bool IsNeighbour { get; set; } = false;

        [JsonIgnore]
        public bool IsNeighboursNeighbour { get; set; } = false;
    }
}
