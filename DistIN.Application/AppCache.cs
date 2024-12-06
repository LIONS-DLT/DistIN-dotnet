using DistIN.Client;

namespace DistIN.Application
{
    public static class AppCache
    {
        private static ObjectCache<DistINPublicKey> _publicKeys = new ObjectCache<DistINPublicKey>(1000);

        public static DistINPublicKey GetPublicKey(string identity)
        {
            return _publicKeys.GetItem(identity, () =>
            {
                string[] address = identity.Split('@');
                if (address[1] == AppConfig.Current.ServiceDomain)
                    return Database.PublicKeys.Where(string.Format("[Identity]='{0}'", identity.ToSqlSafeValue())).FirstOrDefault()!;
                else
                    return DistINClient.GetPublicKey(identity).Result!.Result!;
            })!;
        }
    }
}
