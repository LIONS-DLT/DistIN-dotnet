namespace DistIN.Authenticator;

public partial class PasswordModal : ContentPage
{
    Action<string> _callback;
    public PasswordModal(string caption, Action<string> callback)
    {
        _callback = callback;
        InitializeComponent();
        label.Text = caption;
    }

    private void Button_Clicked(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopModalAsync();
        _callback(passwordEntry.Text);
    }

    private void Button_Clicked_1(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopModalAsync();
        _callback(null);
    }
}