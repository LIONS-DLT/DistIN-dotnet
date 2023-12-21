using System.Collections.Generic;

namespace DistIN.Application
{
    public class ObjectCache<T> where T : DistINObject
    {
        public int MaxCount {  get; private set; }

        private Dictionary<string, ObjectCacheItem<T>> cache = new Dictionary<string, ObjectCacheItem<T>>();
        public ObjectCache(int maxCount) 
        {
            this.MaxCount = maxCount;
        }

        public T? GetItem(string id, Func<T> getFromDatabaseAction)
        {
            T? result = null;
            lock (cache)
            {
                if (cache.ContainsKey(id))
                {
                    ObjectCacheItem<T> item = cache[id];
                    item.LastRequest = DateTime.Now;
                    result = item.Object;
                }
                else
                {
                    result = getFromDatabaseAction();
                    ObjectCacheItem<T> item = new ObjectCacheItem<T>(result);
                    item.LastRequest = DateTime.Now;
                    cache.Add(id, item);
                }

                if (this.cache.Count > this.MaxCount)
                {
                    int count = this.cache.Count - this.MaxCount;
                    var orderedList = cache.OrderBy(c => c.Value.LastRequest).ToList();
                    for(int i = 0; i < count; i++)
                    {
                        cache.Remove(orderedList[i].Key);
                    }
                }
            }
            return result;
        }
    }

    public class ObjectCacheItem<T> where T : DistINObject
    {
        public DateTime LastRequest { get; set; } = DateTime.Now;

        public T Object { get; private set; }

        public ObjectCacheItem(T obj) 
        { 
            this.Object = obj;
        }
    }
}
