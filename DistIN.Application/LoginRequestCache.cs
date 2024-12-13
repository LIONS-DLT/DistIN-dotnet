namespace DistIN.Application
{
    public static class LoginRequestCache
    {
        private static List<string> _idsToRegister = new List<string>();
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

        public static void AddIdForRegistration(string identity)
        {
            lock (_idsToRegister)
            {
                if(!_idsToRegister.Contains(identity))
                    _idsToRegister.Add(identity);
            }
        }

        public static bool HasIdForRegistration(string identity)
        {
            lock (_idsToRegister)
            {
                return _idsToRegister.Contains(identity);
            }
        }
        public static void RemoveIdForRegistration(string identity)
        {
            lock (_idsToRegister)
            {
                if (_idsToRegister.Contains(identity))
                    _idsToRegister.Remove(identity);
            }
        }
    }
}
