// Şifre göstermek için
document.addEventListener("DOMContentLoaded", function () {
    const togglePassword = document.getElementById("toggle-password");
    const passwordInput = document.getElementById("password-input");

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener("click", function () {
            // Şifreyi göster/gizle
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                togglePassword.innerHTML = '<i class="fa-solid fa-eye-slash"></i>';
            } else {
                passwordInput.type = "password";
                togglePassword.innerHTML = '<i class="fa-solid fa-eye"></i>';
            }
        });
    }
});

// Dil
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

// Simple Keyboard
document.addEventListener("DOMContentLoaded", function () {
    // Klavyeyi kontrol etmek için değişkenler
    const keyboardContainer = document.getElementById("keyboard-container");

    // SimpleKeyboard Başlat
    const Keyboard = new window.SimpleKeyboard.default({
        onChange: input => onInputChange(input),
        onKeyPress: button => onKeyPress(button),
        layout: {
            default: [
                "1 2 3 4 5 6 7 8 9 0 @ # $ % & * ( )",
                "q w e r t y u i o p {bksp}",
                "a s d f g h j k l ; : ' \"",
                "z x c v b n m , . / ? !",
                "{shift} {space} {enter}"
            ],
            shift: [
                "! @ # $ % ^ & * ( ) _ +",
                "Q W E R T Y U I O P {bksp}",
                "A S D F G H J K L ; : ' \"",
                "Z X C V B N M , . / ? !",
                "{shift} {space} {enter}"
            ]
        },
        theme: "hg-theme-default myTheme",
    });

    let activeInput = null;

    // Klavyeye Yazma Fonksiyonu
    function onInputChange(input) {
        if (activeInput) {
            activeInput.value = input;
        }
    }

    // Tuş Basılınca Çalışacak Fonksiyon
    function onKeyPress(button) {
        if (!activeInput) return;

        if (button === "{bksp}") {
            activeInput.value = activeInput.value.slice(0, -1);
        } else if (button === "{space}") {
            activeInput.value += " ";
        } else if (button === "{enter}") {
            activeInput.value += "\n";
        } else if (button === "{shift}") {
            Keyboard.setOptions({
                layoutName: Keyboard.options.layoutName === "default" ? "shift" : "default"
            });
        } else {
            activeInput.value += button;
        }
    }

    // Input Alanına Tıklanınca Klavyeyi Aç
    document.querySelectorAll("input").forEach(input => {
        input.addEventListener("focus", event => {
            activeInput = event.target;
            Keyboard.setOptions({ input: activeInput.value });

            // Klavyeyi aktif hale getir
            keyboardContainer.style.display = "block";  // Görünür yap
            setTimeout(() => {
                keyboardContainer.style.bottom = "0";  // Yavaşça yukarı çıkart
            }, 10);
        });
    });

    // Input dışında bir yere tıklanınca klavyeyi kapat
    document.addEventListener("click", function (event) {
        if (!event.target.closest("input") && !event.target.closest("#keyboard-container")) {
            keyboardContainer.style.bottom = "-100%";  // Klavyeyi aşağı kaydırarak gizle
            setTimeout(() => {
                keyboardContainer.style.display = "none"; // Tamamen kaldır
            }, 300);
            activeInput = null;
        }
    });
});
