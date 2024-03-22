// See https://aka.ms/new-console-template for more information
using TestClient;

Console.WriteLine("PROGRAM START.");
Console.WriteLine("-----------------------------------------------------------");

using (var app = new TestApp())
{
    try
    {
        app.Run();
    }
    catch(Exception ex)
    {
        Console.WriteLine("-----------------------------------------------------------");
        Console.WriteLine("ERROR:");
        Console.WriteLine(ex.ToString());
    }
}


Console.WriteLine("-----------------------------------------------------------");
Console.WriteLine("PROGRAM EXIT.");