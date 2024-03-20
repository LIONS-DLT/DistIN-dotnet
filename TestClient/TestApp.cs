using DistIN.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestClient
{
    internal class TestApp : IDisposable
    {

        public TestApp() 
        {
            DistINClient.SCHEME = "http://";
        }

        public void Run()
        {

        }
        public void Dispose()
        {
        }
    }
}
