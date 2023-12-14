using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public abstract class DistINObject
    {
        [PropertyIsPrimaryKey]
        public virtual string ID { get; set; } = IDGenerator.GenerateGUID();
    }
}
