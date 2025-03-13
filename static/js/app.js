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
    let Keyboard = new window.SimpleKeyboard.default({
      onChange: input => onInputChange(input),
      onKeyPress: button => onKeyPress(button),
    });
  
    let activeInput = null;
  
    function onInputChange(input) {
      if (activeInput) {
        activeInput.value = input;
      }
    }
  
    function onKeyPress(button) {
      if (button === "{bksp}") {
        if (activeInput) {
          activeInput.value = activeInput.value.slice(0, -1);
        }
      }
    }
  
    document.querySelectorAll("input").forEach(input => {
      input.addEventListener("focus", event => {
        activeInput = event.target;
        Keyboard.setOptions({
          input: event.target.value
        });
        document.getElementById("keyboard-container").style.display = "block"; // Klavyeyi aç
      });
    });
  
    // Klavyeyi kapatmak için tıklama dışı olayını ekleyelim
    document.addEventListener("click", function (event) {
      if (!event.target.closest("input") && !event.target.closest("#keyboard-container")) {
        document.getElementById("keyboard-container").style.display = "none"; // Klavyeyi gizle
      }
    });
  });
  