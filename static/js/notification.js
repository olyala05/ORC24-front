
// Hata mesajlarını gösteren fonksiyon
function showErrorAlert(title, text = "") {
    toastr.options = {
        "closeButton": false,
        "debug": true,
        "newestOnTop": false,
        "progressBar": true,
        "positionClass": "toast-bottom-right",
        "preventDuplicates": true,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "3000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };

    toastr["error"](text, title);
}

// Başarı mesajlarını gösteren fonksiyon
function showSuccessAlert(title, text = "") {
    toastr.options = {
        "closeButton": false,
        "debug": true,
        "newestOnTop": false,
        "progressBar": true,
        "positionClass": "toast-bottom-right",
        "preventDuplicates": true,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "3000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };

    toastr["success"](text, title);
}

// Uyarı mesajlarını gösteren fonksiyon
function showWarningAlert(title, text = "") {

    toastr.options = {
        "closeButton": false,
        "debug": true,
        "newestOnTop": false,
        "progressBar": true,
        "positionClass": "toast-bottom-right",
        "preventDuplicates": true,
        "showDuration": "300",
        "hideDuration": "1000",
        "timeOut": "3000",
        "extendedTimeOut": "1000",
        "showEasing": "swing",
        "hideEasing": "linear",
        "showMethod": "fadeIn",
        "hideMethod": "fadeOut"
    };

    toastr["warning"](text, title);
}

// Yükleme ekranını gösteren yardımcı fonksiyon
function showLoading(message) {
    let loadingOverlay = document.createElement("div");
    loadingOverlay.id = "loading-overlay";
    loadingOverlay.className = "loading-overlay";
    loadingOverlay.innerHTML = `
    <div class="loading-box">
      <p> ${message} </p>
      <div class="loader"></div>
    </div>`;
    document.body.appendChild(loadingOverlay);
}

// Yükleme ekranını kaldırma
function hideLoading() {
    let loader = document.getElementById("loading-overlay");
    if (loader) loader.remove();
}