//using System.Data.SQLite;
using System.Data;
using System.Globalization;
using System.Reflection.Metadata;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using DistIN.DistAN;
using Microsoft.Data.Sqlite;
using DistIN.Application.DistNet;

namespace DistIN.Application
{
    public static class Database
    {
        //public static DatabaseEntitySet<DistINIdentity> Identities { get; private set; } = new DatabaseEntitySet<DistINIdentity>();
        public static DatabaseEntitySet<DistINAttribute> Attributes { get; private set; } = new DatabaseEntitySet<DistINAttribute>();
        public static DatabaseEntitySet<DistINAttributeSignature> AttributeSignatures { get; private set; } = new DatabaseEntitySet<DistINAttributeSignature>();
        public static DatabaseEntitySet<DistINAttributeSignatureReference> AttributeSignatureRefs { get; private set; } = new DatabaseEntitySet<DistINAttributeSignatureReference>();
        public static DatabaseEntitySet<DistINCredential> Credentials { get; private set; } = new DatabaseEntitySet<DistINCredential>();
        public static DatabaseEntitySet<DistINPublicKey> PublicKeys { get; private set; } = new DatabaseEntitySet<DistINPublicKey>();
        public static DatabaseEntitySet<AppToken> Tokens { get; private set; } = new DatabaseEntitySet<AppToken>();
        public static DatabaseEntitySet<OpenIDClient> OpenIDClients { get; private set; } = new DatabaseEntitySet<OpenIDClient>();
        public static DatabaseEntitySet<DistNetNode> DistNetNodes { get; private set; } = new DatabaseEntitySet<DistNetNode>();
        public static DatabaseEntitySet<AppLogEntry> AppLog { get; private set; } = new DatabaseEntitySet<AppLogEntry>();

        // DistAN Enities
        public static DatabaseEntitySet<DistANMessage> Messages { get; private set; } = new DatabaseEntitySet<DistANMessage>();

        public static string ConnectionString { get; private set; } = "";

        public static void Init(string filepath, Action seedAction)
        {
            ConnectionString = string.Format("Data Source={0}", filepath);
            if (!File.Exists(filepath))
            {
                //SqliteConnection.CreateFile(filepath);
                SQLitePCL.Batteries_V2.Init();
                SQLitePCL.raw.SetProvider(new SQLitePCL.SQLite3Provider_e_sqlite3());

                CreateTableForType<DistINIdentity>();
                CreateTableForType<DistINAttribute>();
                CreateTableForType<DistINAttributeSignature>();
                CreateTableForType<DistINAttributeSignatureReference>();
                CreateTableForType<DistINCredential>();
                CreateTableForType<DistINPublicKey>();
                CreateTableForType<AppToken>();
                CreateTableForType<OpenIDClient>();
                CreateTableForType<DistNetNode>();
                CreateTableForType<AppLogEntry>();
                // DistAN
                CreateTableForType<DistANMessage>();

                if (seedAction != null)
                    seedAction();
            }
        }

        private static object _threadSafeLockObj = new { };

        public static DataTable QuerySQL(string sql)
        {
            lock (_threadSafeLockObj)
            {
                try
                {
                    SqliteConnection con = new SqliteConnection(ConnectionString);
                    con.Open();

                    SqliteCommand adapter = new SqliteCommand(sql, con);
                    DataTable table = new DataTable();
                    table.Load(adapter.ExecuteReader());

                    con.Close();
                    return table;
                }
                catch (Exception ex)
                {
                    throw new Exception("Database Interface Error.", ex);
                }
            }
        }
        public static int ExecuteSQL(string sql)
        {
            lock (_threadSafeLockObj)
            {
                try
                {
                    SqliteConnection con = new SqliteConnection(ConnectionString);
                    con.Open();

                    SqliteCommand cmd = con.CreateCommand();
                    cmd.CommandText = sql;
                    int result = cmd.ExecuteNonQuery();

                    con.Close();
                    return result;
                }
                catch (Exception ex)
                {
                    throw new Exception("Database Interface Error.", ex);
                }
            }
        }

        public static void CreateTableForType<T>() where T : DistINObject
        {
            Type type = typeof(T);

            StringBuilder sql = new StringBuilder();
            sql.Append(string.Format("CREATE TABLE IF NOT EXISTS {0} (", type.Name));

            bool isFirst = true;
            foreach (var property in type.GetProperties())
            {
                PropertyNotInDatabaseAttribute? attribute = property.GetCustomAttribute<PropertyNotInDatabaseAttribute>(true);
                if (attribute == null)
                {
                    string dataType = "TEXT";
                    if (property.PropertyType.IsEnum || property.PropertyType == typeof(int) || property.PropertyType == typeof(long)
                        || property.PropertyType == typeof(DateTime) || property.PropertyType == typeof(bool))
                    {
                        dataType = "INTEGER";
                    }
                    else if (property.PropertyType == typeof(float) || property.PropertyType == typeof(double))
                    {
                        dataType = "REAL";
                    }

                    if (property.GetCustomAttribute<PropertyIsPrimaryKeyAttribute>(true) != null)
                        dataType += " PRIMARY KEY";

                    if (isFirst)
                        sql.Append(string.Format("{0} {1}", property.Name, dataType));
                    else
                        sql.Append(string.Format(",{0} {1}", property.Name, dataType));
                    isFirst = false;
                }
            }

            sql.Append(");");

            ExecuteSQL(sql.ToString());
        }

        public static T DeserializeFromDatarow<T>(DataRow row) where T : DistINObject
        {
            T obj = Activator.CreateInstance<T>();

            foreach (var property in obj.GetType().GetProperties())
            {
                PropertyNotInDatabaseAttribute? attribute = property.GetCustomAttribute<PropertyNotInDatabaseAttribute>(true);
                if (attribute == null)
                {
                    object rawValue = row[property.Name];

                    if (property.PropertyType.IsEnum)
                    {
                        property.SetValue(obj, (int)(long)rawValue);
                    }
                    else if (property.PropertyType == typeof(int))
                    {
                        property.SetValue(obj, (int)(long)rawValue);
                    }
                    else if (property.PropertyType == typeof(long))
                    {
                        property.SetValue(obj, (long)rawValue);
                    }
                    else if (property.PropertyType == typeof(DateTime))
                    {
                        property.SetValue(obj, new DateTime((long)rawValue));
                    }
                    else if (property.PropertyType == typeof(bool))
                    {
                        property.SetValue(obj, (bool)((long)rawValue > 0));
                    }
                    else if (property.PropertyType == typeof(double))
                    {
                        property.SetValue(obj, (double)rawValue);
                    }
                    else if (property.PropertyType == typeof(float))
                    {
                        property.SetValue(obj, (float)(double)rawValue);
                    }
                    else if (property.PropertyType == typeof(string))
                    {
                        property.SetValue(obj, rawValue as string);
                    }
                }
            }
            return obj;
        }

        public static bool Update<T>(T item) where T : DistINObject
        {
            Type type = typeof(T);

            StringBuilder sql = new StringBuilder();
            sql.Append(string.Format("UPDATE [{0}] SET ", type.Name));

            bool isFirst = true;
            foreach (var property in type.GetProperties())
            {
                PropertyNotInDatabaseAttribute? attribute = property.GetCustomAttribute<PropertyNotInDatabaseAttribute>(true);
                if (attribute == null)
                {
                    string value = "";

                    if (property.PropertyType.IsEnum)
                        value = ((int)property.GetValue(item)!).ToString();
                    else if (property.PropertyType == typeof(string))
                        value = string.Format("'{0}'", property.GetValue(item));
                    else if (property.PropertyType == typeof(bool))
                        value = string.Format("{0}", (bool)property.GetValue(item)! ? 1 : 0);
                    else if (property.PropertyType == typeof(DateTime))
                        value = string.Format("{0}", ((DateTime)property.GetValue(item)!).Ticks);
                    else
                        value = string.Format(CultureInfo.InvariantCulture, "{0}", property.GetValue(item));

                    if (isFirst)
                        sql.Append(string.Format("{0}={1}", property.Name, value));
                    else
                        sql.Append(string.Format(",{0}={1}", property.Name, value));
                    isFirst = false;
                }
            }

            sql.AppendLine(string.Format(" WHERE ID='{0}'", item.ID));

            return ExecuteSQL(sql.ToString()) > 0;
        }

        public static void Insert<T>(T item) where T : DistINObject
        {
            Type type = typeof(T);

            StringBuilder sql = new StringBuilder();
            sql.Append(string.Format("INSERT INTO [{0}] (", type.Name));

            bool isFirst = true;
            List<PropertyInfo> properties = new List<PropertyInfo>();
            foreach (var property in type.GetProperties())
            {
                PropertyNotInDatabaseAttribute? attribute = property.GetCustomAttribute<PropertyNotInDatabaseAttribute>(true);
                if (attribute == null)
                {
                    properties.Add(property);
                    if (isFirst)
                        sql.Append(string.Format("{0}", property.Name));
                    else
                        sql.Append(string.Format(",{0}", property.Name));
                    isFirst = false;
                }
            }
            sql.Append(") VALUES(");

            isFirst = true;
            foreach (var property in properties)
            {
                string value = "";

                if (property.PropertyType.IsEnum)
                    value = ((int)property.GetValue(item)!).ToString();
                else if (property.PropertyType == typeof(string))
                    value = string.Format("'{0}'", property.GetValue(item));
                else if (property.PropertyType == typeof(bool))
                    value = string.Format("{0}", (bool)property.GetValue(item)! ? 1 : 0);
                else if (property.PropertyType == typeof(DateTime))
                    value = string.Format("{0}", ((DateTime)property.GetValue(item)!).Ticks);
                else
                    value = string.Format(CultureInfo.InvariantCulture, "{0}", property.GetValue(item));

                if (isFirst)
                    sql.Append(string.Format("{0}", value));
                else
                    sql.Append(string.Format(",{0}", value));
                isFirst = false;
            }

            sql.AppendLine(string.Format(")", item.ID));

            ExecuteSQL(sql.ToString());
        }

        public static void InsertOrUpdate<T>(T item) where T : DistINObject
        {
            if (!Update<T>(item))
                Insert<T>(item);
        }

        public static List<T> QueryObjects<T>(string? where = null) where T : DistINObject
        {
            string sql = string.Format("SELECT * FROM [{0}]", typeof(T).Name);
            if (!string.IsNullOrEmpty(where))
                sql += " WHERE " + where;

            List<T> result = new List<T>();

            foreach (DataRow row in QuerySQL(sql).Rows)
            {
                result.Add(DeserializeFromDatarow<T>(row));
            }

            return result;
        }
        public static List<T> QueryObjectsSQL<T>(string sql) where T : DistINObject
        {
            List<T> result = new List<T>();

            foreach (DataRow row in QuerySQL(sql).Rows)
            {
                result.Add(DeserializeFromDatarow<T>(row));
            }

            return result;
        }
    }

    public class DatabaseEntitySet<T> where T : DistINObject
    {
        public void Insert(T item)
        {
            Database.Insert<T>(item);
        }
        public T? Find(string id)
        {
            if (!string.IsNullOrEmpty(id))
                return null;
            else
                id = id.ToSqlSafeValue();
            return Database.QueryObjects<T>(string.Format("ID='{0}'", id)).FirstOrDefault();
        }
        public List<T> All()
        {
            return Database.QueryObjects<T>();
        }
        public List<T> Where(string where)
        {
            return Database.QueryObjects<T>(where);
        }
        public void InsertOrUpdate(T item)
        {
            Database.InsertOrUpdate<T>(item);
        }
        public bool Update(T item)
        {
            return Database.Update<T>(item);
        }


        public bool Delete(string id)
        {
            if (!string.IsNullOrEmpty(id))
                return false;
            else
                id = id.ToSqlSafeValue();

            Type type = typeof(T);

            StringBuilder sql = new StringBuilder();
            sql.Append(string.Format("DELETE FROM [{0}] WHERE [ID]='{1}'", type.Name, id));

            return Database.ExecuteSQL(sql.ToString()) > 0;
        }
    }

}
