using DistIN.Client;
using Microsoft.Maui.Storage;
using System.Text;

namespace DistIN.Authenticator;

public partial class SignPage : ContentPage
{
    private IdentityMaterial identity;
    private DistINSignatureRequest signatureRequest;
    private DistINSignatureResponse signatureResponse;
    private List<Button> boxes = new List<Button>();
    private Action<bool> _callback;

    public SignPage(IdentityMaterial identityMaterial, DistINSignatureRequest distINSignatureRequest, Action<bool> callback)
	{
        _callback = callback;
        identity = identityMaterial;
        signatureRequest = distINSignatureRequest;
        signatureResponse = new DistINSignatureResponse();
        signatureResponse.ID = signatureRequest.ID;
        signatureResponse.Identity = signatureRequest.Identity;

        InitializeComponent();

        foreach (Button box in boxes)
            layout.Remove(box);
        boxes.Clear();

        int insertIndex = 0;
        foreach (string attribute in signatureRequest.RequiredAttributes)
        {
            string name = attribute;
            addCheckButton(insertIndex, attribute, name);
            insertIndex++;
        }
        foreach (string attribute in signatureRequest.PreferredAttributes)
        {
            string name = attribute + " (optional)";
            addCheckButton(insertIndex, attribute, name);
            insertIndex++;
        }
    }

    private void addCheckButton(int insertIndex, string attribute, string name)
    {
        var box = new Button()
        {
            Text = "[ ] " + name,
            HorizontalOptions = LayoutOptions.Fill,
            Style = App.FindResource("EntryButton") as Style
        };
        box.Clicked += (object sender, EventArgs e) =>
        {
            if (signatureResponse.PermittedAttributes.Contains(attribute))
            {
                signatureResponse.PermittedAttributes.Remove(attribute);
                box.Text = "[ ] " + name;
            }
            else
            {
                signatureResponse.PermittedAttributes.Add(attribute);
                box.Text = "[X] " + name;
            }
        };
        layout.Insert(insertIndex, box);
    }


    private async void OnAcceptClick(object sender, EventArgs e)
    {
        signatureResponse.Signature = CryptHelper.SignData(identity.KeyPair, Encoding.UTF8.GetBytes(signatureRequest.Challenge));

        await DistINClient.PostSignatureResponse(signatureResponse);

        await App.Current.MainPage.Navigation.PopAsync();
        _callback(true);
    }
    private void OnDeclineClick(object sender, EventArgs e)
    {
        App.Current.MainPage.Navigation.PopAsync();
        _callback(false);
    }
}