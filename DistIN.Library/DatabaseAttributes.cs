using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    [AttributeUsage(AttributeTargets.Property)]
    public class PropertyNotInDatabaseAttribute : Attribute
    {
        public PropertyNotInDatabaseAttribute()
        {
        }
    }

    [AttributeUsage(AttributeTargets.Property)]
    public class PropertyIsPrimaryKeyAttribute : Attribute
    {
        public PropertyIsPrimaryKeyAttribute()
        {
        }
    }
}
