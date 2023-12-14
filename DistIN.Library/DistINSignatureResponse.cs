using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DistIN
{
    public class DistINSignatureResponse : DistINObject
    {
        public string Identity { get; set; } = string.Empty;
        public string Signature { get; set; } = string.Empty;
        public List<string> PermittedAttributes { get; set; } = new List<string>();
    }
}
