namespace DistIN.Application
{
    public static class AppLog
    {
        public static void Log(AppLogEntryType type, string subject, string action)
        {
            Database.AppLog.Insert(new AppLogEntry() { Subject = subject, Action = action, Type = type });
        }
    }

    public class AppLogEntry: DistINObject
    {
        public AppLogEntryType Type { get; set; }
        public DateTime Date { get; set; } = DateTime.Now;
        public string Subject { get; set; } = string.Empty;
        public string Action { get; set; } = string.Empty;
    }
    public enum AppLogEntryType
    {
        Default,
        Error,
        Warning,
        Action
    }
}
