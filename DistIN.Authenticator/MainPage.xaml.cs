namespace DistIN.Authenticator
{
    public partial class MainPage : ContentPage
    {
        private List<Button> buttons = new List<Button>();

        public MainPage()
        {
            InitializeComponent();
            loadList();
        }

        private void loadList()
        {
            foreach (Button button in buttons)
                layout.Remove(button);
            buttons.Clear();

            foreach (string id in IdentityMaterial.GetLocalIDs())
            {
                var btn = new Button()
                {
                    Text = id,
                    HorizontalOptions = LayoutOptions.Fill,
                    Style = App.FindResource("EntryButton") as Style
                };
                btn.Clicked += (object sender, EventArgs e) =>
                {
                    OnIdClicked(id);
                };
                layout.Add(btn);
            }
        }

        private void OnIdClicked(string id)
        {
            App.Current.MainPage.Navigation.PushModalAsync(new PasswordModal("Password:", (string pswd) =>
            {
                if (string.IsNullOrEmpty(pswd))
                    return;

                IdentityMaterial material = IdentityMaterial.Open(id, pswd);

                App.Current.MainPage.Navigation.PushAsync(new IdentityPage(material));
            }));
        }

        private void OnScanClicked(object sender, EventArgs e)
        {
            App.Current.MainPage.Navigation.PushModalAsync(new ScanQrModal((string content) =>
            {
                if (string.IsNullOrEmpty(content))
                    return;

                // create:id:challenge

                string[] parameters = content.Split('|');

                if (parameters[0] == "create") // create and register id
                {
                    string id = parameters[1];
                    string regId = parameters[2];
                    string regChallange = parameters[3];

                    App.Current.MainPage.Navigation.PushModalAsync(new PasswordModal(string.Format( "Password for '{0}':", id), (string pswd) =>
                    {
                        if (string.IsNullOrEmpty(pswd))
                            return;

                        App.Current.MainPage.Navigation.PushModalAsync(new PasswordModal("Repeat password:", (string pswd2) =>
                        {
                            if (pswd2 != pswd)
                                return;

                            IdentityMaterial material = IdentityMaterial.Create(id, DistINKeyAlgorithm.DILITHIUM, pswd);

                            bool success = DistIN.Client.DistINClient.Register(material.ID, regId, regChallange, material.KeyPair).Result;

                            if (success)
                                loadList();
                        }));
                    }));
                }
                else if (parameters[0] == "???") // ???
                {

                }

            }));
        }
    }
}