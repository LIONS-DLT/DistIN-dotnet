namespace DistIN.Application
{
    public static class LoginRequestCache
    {
        private static Dictionary<string, string> _cache = new Dictionary<string, string>();

        private static void cleanUp()
        {
            while (_cache.Count > 100)
                _cache.Remove(_cache.Keys.First());
        }

        public static string CreateChallange(string identity)
        {
            lock( _cache )
            {
                cleanUp();
                if (_cache.ContainsKey(identity))
                    _cache.Remove(identity);

                string challange = IDGenerator.GenerateRandomString(32);
                _cache.Add(identity, challange);
                return challange;
            }
        }

        public static string? GetChallange(string identity)
        {
            lock( _cache )
            {
                if (!_cache.ContainsKey(identity))
                    return null;
                string challange = _cache[identity];
                _cache.Remove(identity);
                return challange;
            }
        }
    }
}
