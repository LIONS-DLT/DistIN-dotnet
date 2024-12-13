using DistIN.Client;

namespace DistIN.Authenticator;

public partial class IdentityPage : ContentPage
{
    private IdentityMaterial identity;
    private bool _listening = false;

    public IdentityPage(IdentityMaterial identityMaterial)
	{
        identity = identityMaterial;
		InitializeComponent();
        idLabel.Text = identity.ID;
	}

    protected override void OnAppearing()
    {
        base.OnAppearing();
        new Thread(new ThreadStart(listenThread)).Start();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();

        _listening = false;
    }

    private void listenThread()
    {
        _listening = DistINClient.Login(identity.ID, identity.KeyPair).Result;

        while (_listening)
        {
            Thread.Sleep(App.REQUEST_INTERVAL_MS);

            try
            {
                var signatureRequests = DistINClient.GetSignatureRequests().Result.Result.Requests;
                foreach(DistINSignatureRequest signatureRequest in signatureRequests)
                {
                    bool waiting = true;
                    onSignatureRequestRceived(signatureRequest, (bool accepted) =>
                    {
                        waiting = false;
                    });

                    while (waiting)
                        Thread.Sleep(500);
                }
            }
            catch
            {
                _listening = false;
            }
        }
    }

    private void onSignatureRequestRceived(DistINSignatureRequest signatureRequest, Action<bool> callback)
    {
        Dispatcher.Dispatch(() =>
        {
            App.Current.MainPage.Navigation.PushAsync(new SignPage(identity, signatureRequest, callback));
        });
    }

    private void Button_Clicked(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopToRootAsync();
    }
}