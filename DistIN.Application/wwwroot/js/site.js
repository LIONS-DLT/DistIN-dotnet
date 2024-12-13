// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

function executeLogin(buttonId, inputId) {

    $(buttonId).prop("disabled", true);

    $.post('/Home/Login', { id: $(inputId).val() }, function (data) {

        $(buttonId).prop("disabled", false);

        if (data.success) {
            document.location.href = '/App/Index';
        }
        else {
            alert(data.reason);
        }
    });
}