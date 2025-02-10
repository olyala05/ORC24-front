// Şifre göstermek için
document.addEventListener("DOMContentLoaded", function () {
    const togglePassword = document.getElementById("toggle-password");
    const passwordInput = document.getElementById("password-input");

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener("click", function () {
            // Şifreyi göster veya gizle
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                togglePassword.classList.add("active"); // Renk değişimi için
                togglePassword.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
            } else {
                passwordInput.type = "password";
                togglePassword.classList.remove("active");
                togglePassword.innerHTML = '<i class="fa-solid fa-eye"></i>';
            }
        });
    }
});

document.addEventListener("DOMContentLoaded", function () {
    const langButtons = document.querySelectorAll(".language-dropdown button");
    const langToggle = document.querySelector(".language-toggle");
    const languageDropdown = document.querySelector(".language-dropdown");
    const selectedLangText = document.getElementById("selected-lang");

    // Önceki seçili dili al ve UI güncelle
    const savedLang = localStorage.getItem("selectedLanguage");
    if (savedLang) {
        setLanguage(savedLang);
    } else {
        setLanguage("tr"); // Varsayılan dil TR
    }

    // Dil değiştirme işlemi
    langButtons.forEach(button => {
        button.addEventListener("click", function () {
            const selectedLang = this.getAttribute("data-lang");
            setLanguage(selectedLang);
            localStorage.setItem("selectedLanguage", selectedLang);
        });
    });

    function setLanguage(lang) {
        langButtons.forEach(btn => btn.classList.remove("active"));
        const activeBtn = document.querySelector(`.language-dropdown button[data-lang="${lang}"]`);
        if (activeBtn) activeBtn.classList.add("active");

        // Seçili dilin metnini güncelle
        const langMapping = {
            "tr": "TR",
            "en": "EN",
            "de": "DE"
        };
        selectedLangText.textContent = langMapping[lang] || "TR";

        // Dropdown'u kapat
        languageDropdown.style.display = "none";
    }

    // Dil menüsünü aç/kapat
    langToggle.addEventListener("click", function (event) {
        event.stopPropagation();
        languageDropdown.style.display = (languageDropdown.style.display === "flex") ? "none" : "flex";
    });

    // Dışarı tıklanınca menüyü kapat
    document.addEventListener("click", function (event) {
        if (!languageDropdown.contains(event.target) && !langToggle.contains(event.target)) {
            languageDropdown.style.display = "none";
        }
    });
});



setTimeout(function () {
    if (window.location.pathname === "/" || window.location.pathname === "/index.html") {
        window.location.href = loginURL;
    }
}, 5000);

