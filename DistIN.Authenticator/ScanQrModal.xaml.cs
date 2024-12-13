using System.Net.NetworkInformation;
using ZXing.Net.Maui;

namespace DistIN.Authenticator;

public partial class ScanQrModal : ContentPage
{
    Action<string> _callback;
    public ScanQrModal(Action<string> callback)
    {
        _callback = callback;
        InitializeComponent();
    }
    private void cameraBarcodeReaderView_BarcodesDetected(object sender, BarcodeDetectionEventArgs e)
    {
        if (e.Results.Length > 0)
        {
            //CameraBarcodeReaderView v;
            string content = e.Results[0].Value;
            Dispatcher.Dispatch(() =>
            {
                cameraBarcodeReaderView.IsEnabled = false;
                //DisplayAlert("Code", content, "OK");
                if (_callback != null)
                {
                    App.Current.MainPage.Navigation.PopModalAsync();
                    _callback(content);
                    _callback = null;
                }
            });
        }
    }

    private void Button_Clicked(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopModalAsync();
        _callback(null);
    }
}