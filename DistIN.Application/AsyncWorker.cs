namespace DistIN.Application
{
    public static class AsyncWorker
    {
        private static Thread? _thread = null;

        public static void Init()
        {
            _thread = new Thread(new ThreadStart(asyncThread));
            _thread.Start();
        }

        private static void asyncThread()
        {

        }
    }
}
