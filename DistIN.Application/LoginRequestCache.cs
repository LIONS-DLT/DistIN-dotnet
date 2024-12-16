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

        public static string CreateChallange(string challangeId)
        {
            lock( _cache )
            {
                cleanUp();
                if (_cache.ContainsKey(challangeId))
                    _cache.Remove(challangeId);

                string challange = IDGenerator.GenerateRandomString(32);
                _cache.Add(challangeId, challange);
                return challange;
            }
        }

        public static string? GetChallange(string challangeId)
        {
            lock( _cache )
            {
                if (!_cache.ContainsKey(challangeId))
                    return null;
                string challange = _cache[challangeId];
                _cache.Remove(challangeId);
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
