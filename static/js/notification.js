
// Hata mesajlarını gösteren fonksiyon
function showErrorAlert(title, text = "") {
  toastr.options = {
    closeButton: false,
    debug: false,
    newestOnTop: false,
    progressBar: true,
    positionClass: "toast-bottom-right",
    preventDuplicates: true,
    showDuration: "300",
    hideDuration: "1000",
    timeOut: "3000",
    extendedTimeOut: "1000",
    showEasing: "swing",
    hideEasing: "linear",
    showMethod: "fadeIn",
    hideMethod: "fadeOut",
    escapeHtml: false,
  };

  const customHTML = `
    <div style="display: flex; align-items: center; gap: 10px;">
      <span>
        <img src="${errorAlarmIconUrl}" alt="Error" width="32" height="32" />
      </span>
      <div>
        <div style="font-weight: bold; color: #0B1734;">${title}</div>
        <div style="color: #0B1734;">${text}</div>
      </div>
    </div>
  `;

  toastr.error(customHTML);
}

// Başarı mesajlarını gösteren fonksiyon
function showSuccessAlert(title, text = "") {
  toastr.options = {
    closeButton: false,
    debug: false,
    newestOnTop: false,
    progressBar: true,
    positionClass: "toast-bottom-right",
    preventDuplicates: true,
    showDuration: "300",
    hideDuration: "1000",
    timeOut: "3000",
    extendedTimeOut: "1000",
    showEasing: "swing",
    hideEasing: "linear",
    showMethod: "fadeIn",
    hideMethod: "fadeOut",
    escapeHtml: false,
  };

  const customHTML = `
    <div style="display: flex; align-items: center; gap: 10px;">
      <span>
        <img src="${successAlarmIconUrl}" alt="Success" width="32" height="32" />
      </span>
      <div>
        <div style="font-weight: bold; color: #0B1734;">${title}</div>
        <div style="color: #0B1734;">${text}</div>
      </div>
    </div>
  `;

  toastr.success(customHTML);
}

// Uyarı mesajlarını gösteren fonksiyon
function showWarningAlert(title, text = "") {
  toastr.options = {
    closeButton: false,
    debug: false,
    newestOnTop: false,
    progressBar: true,
    positionClass: "toast-bottom-right",
    preventDuplicates: true,
    showDuration: "300",
    hideDuration: "1000",
    timeOut: "3000",
    extendedTimeOut: "1000",
    showEasing: "swing",
    hideEasing: "linear",
    showMethod: "fadeIn",
    hideMethod: "fadeOut",
    escapeHtml: false,
  };

  const customHTML = `
    <div style="display: flex; align-items: center; gap: 10px;">
      <span>
        <img src="${alarmIconUrl}" alt="Alarm" width="32" height="32" />
      </span>
      <div>
        <div style="font-weight: bold; color: #0B1734;">${title}</div>
        <div style="color: #0B1734;">${text}</div>
      </div>
    </div>
  `;

  toastr.warning(customHTML);
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
