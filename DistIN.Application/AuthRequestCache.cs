namespace DistIN.Application
{
    public static class AuthRequestCache
    {
        class AuthRequestCacheItem
        {
            public DistINSignatureRequest? Request { get; set; }
            public DistINSignatureResponse? Response { get; set; }
            public DateTime Timeout { get; set; } = DateTime.Now.AddMinutes(10);
        }

        private static Dictionary<string, AuthRequestCacheItem> _cache = new Dictionary<string, AuthRequestCacheItem>();

        private static void cleanUp()
        {
            foreach (var item in _cache.Where(x => x.Value.Timeout < DateTime.Now).ToList())
                _cache.Remove(item.Key);
        }

        public static void AddRequest(DistINSignatureRequest request, DateTime timeout)
        {
            lock( _cache )
            {
                cleanUp();
                _cache.Add(request.ID, new AuthRequestCacheItem()
                {
                    Request = request,
                    Timeout = timeout
                });
            }
        }

        public static List<DistINSignatureRequest> GetRequests(string identity)
        {
            List<DistINSignatureRequest> result = new List<DistINSignatureRequest>();

            lock(_cache )
            {
                foreach(var item in _cache.Values)
                {
                    if (item.Request != null && item.Request.Identity == identity)
                        result.Add(item.Request);
                }
            }
            return result;
        }

        public static bool AddResponse(DistINSignatureResponse response)
        {
            lock( _cache )
            {
                cleanUp();
                if (_cache.ContainsKey(response.ID))
                {
                    _cache[response.ID].Response = response;
                    return true;
                }
                else
                    return false;
            }
        }

        public static DistINSignatureResponse? GetAndRemoveResponse(string id)
        {
            DistINSignatureResponse? result = null;
            lock(_cache )
            {
                if(! _cache.ContainsKey(id))
                    return null;

                result = _cache[id].Response;
                if(result != null)
                    _cache.Remove(result.ID);
            }

            return result;
        }
    }
}
