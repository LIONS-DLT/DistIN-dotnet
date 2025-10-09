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
    public class DistNetNodeList : DistINObject
    {
        public List<DistNetNode> Nodes { get; set; } = new List<DistNetNode>();
    }
    public class DistNetNeighbourList : DistINObject
    {
        public List<DistNetNode> Neighbours { get; set; } = new List<DistNetNode>();
    }
}
