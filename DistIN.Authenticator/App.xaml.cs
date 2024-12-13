using DistIN.Client;

namespace DistIN.Authenticator
{
    public partial class App : Application
    {
        public const int REQUEST_INTERVAL_MS = 2000;

        public App()
        {
            InitializeComponent();

            // MainPage = new AppShell();

            MainPage = new NavigationPage();
            MainPage.Navigation.PushAsync(new MainPage());
        }

        protected override void OnStart()
        {
            base.OnStart();

            DeviceDisplay.Current.KeepScreenOn = true;
        }

        public static object FindResource(string key)
        {
            if (App.Current.Resources.ContainsKey(key))
                return App.Current.Resources[key];

            foreach (var dict in App.Current.Resources.MergedDictionaries)
            {
                if (dict.Keys.Contains(key))
                    return dict[key];
            }
            return null;
        }
    }
}