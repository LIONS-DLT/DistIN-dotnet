namespace DistIN.Authenticator;

public partial class EnterTextModal : ContentPage
{
    Action<string> _callback;
    public EnterTextModal(Action<string> callback)
    {
        _callback = callback;
        InitializeComponent();
    }

    private void OkClicked(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopModalAsync();
        _callback(textEntry.Text);
    }
    private void CancelClicked(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopModalAsync();
        _callback(null);
    }
}