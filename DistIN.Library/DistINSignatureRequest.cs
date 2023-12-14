using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINSignatureRequest : DistINObject
    {
        public string DisplayText { get; set; } = string.Empty;
        public string RemoteAddress { get; set; } = string.Empty;
        public string Identity { get; set; } = string.Empty;
        public string Challenge { get; set; } = string.Empty;

        public List<string> RequiredAttributes { get; set; } = new List<string>();
        public List<string> PreferredAttributes { get; set; } = new List<string>();
    }
}
