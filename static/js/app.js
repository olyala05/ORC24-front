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

// Tarayıcı önerisini engeller
document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("input").forEach(input => {
        input.setAttribute("readonly", "readonly");
        input.setAttribute("autocomplete", "off"); 
        input.setAttribute("autocorrect", "off");
        input.setAttribute("spellcheck", "false");

        setTimeout(() => {
            input.removeAttribute("readonly");
        }, 100);
    });
});

// Simple Keyboard
document.addEventListener("DOMContentLoaded", function () {
    const keyboardContainer = document.getElementById("keyboard-container");
    const loginButton = document.querySelector(".login-btn");

    // Sadece login sayfasında çalışmasını sağla
    if (window.location.pathname === "/login") {
        document.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault(); // Formun otomatik gönderilmesini engelle
                if (loginButton) {
                    loginButton.click(); // Butona tıklamayı tetikle
                }
            }
        });
    }

    // SimpleKeyboard başlat
    const Keyboard = new window.SimpleKeyboard.default({
        onChange: input => onInputChange(input),
        onKeyPress: button => onKeyPress(button),
        layout: {
            default: [
                "1 2 3 4 5 6 7 8 9 0 @ # $ % & * ( ) {bksp}",
                "q w e r t y u i o p",
                "a s d f g h j k l ; :",
                "z x c v b n m , . / ? !",
                "{shift} {space} {enter}"
            ],
            shift: [
                "! @ # $ % ^ & * ( ) _ + {bksp}",
                "Q W E R T Y U I O P",
                "A S D F G H J K L ; :",
                "Z X C V B N M , . / ? !",
                "{shift} {space} {enter}"
            ]
        },
        theme: "hg-theme-default myTheme",
    });

    let activeInput = null;

    function onInputChange(input) {
        if (activeInput) {
            activeInput.value = input;
        }
    }

    function onKeyPress(button) {
        if (!activeInput) return;

        if (button === "{bksp}") {
            activeInput.value = activeInput.value.slice(0, -1);
        } else if (button === "{space}") {
            activeInput.value += " ";
        } else if (button === "{enter}") {
            if (loginButton) {
                loginButton.click(); // Sanal klavyede Enter basıldığında butonu tıklat
            }
        } else if (button === "{shift}") {
            Keyboard.setOptions({
                layoutName: Keyboard.options.layoutName === "default" ? "shift" : "default"
            });
        } else {
            activeInput.value += button;
        }
    }

    // Input alanına tıklanınca klavyeyi aç
    document.querySelectorAll("input").forEach(input => {
        input.addEventListener("focus", event => {
            activeInput = event.target;
            Keyboard.setOptions({ input: activeInput.value });

            keyboardContainer.style.display = "block";
            setTimeout(() => {
                keyboardContainer.style.bottom = "0";
            }, 10);
        });
    });

    // Input dışında bir yere tıklanınca klavyeyi kapat
    document.addEventListener("click", function (event) {
        if (!event.target.closest("input") && !event.target.closest("#keyboard-container")) {
            keyboardContainer.style.bottom = "-100%";
            setTimeout(() => {
                keyboardContainer.style.display = "none";
            }, 300);
            activeInput = null;
        }
    });
});

