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

setTimeout(function () {
    const currentPath = window.location.pathname;
    if (currentPath === "/" || currentPath === "/index" || currentPath === "/index.html") {
        fetch("/auto-login", {
            method: "POST"
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.success) {
                    window.location.href = "/dashboard";
                } else {
                    console.error("Giriş başarısız:", data.message);
                }
            })
            .catch((err) => {
                console.error("API çağrısı hatası:", err);
            });
    }
}, 3000);


// Simple Keyboard
document.addEventListener("DOMContentLoaded", function () {
    const keyboardContainer = document.getElementById("keyboard-container");
    const loginButton = document.querySelector(".login-btn");

    // Sadece login sayfasında çalışmasını sağla
    if (window.location.pathname === "/login") {
        document.addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                if (loginButton) {
                    loginButton.click();
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
                "! @ # $ % ^ & * ( ) _ - + {bksp}",
                "Q W E R T Y U I O P",
                "A S D F G H J K L ; :",
                "Z X C V B N M , . / ? !",
                "{shift} {space} {enter}"
            ]
        },
        display: {
            '{enter}': '↵',
            '{bksp}': '⌫',
            '{shift}': '⇧',
            '{space}': 'Space'
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
                loginButton.click();
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
    // document.querySelectorAll("input").forEach(input => {
    //     input.addEventListener("focus", event => {
    //         const activeEl = document.activeElement;
    //         if (activeEl.closest(".language-switcher")) {
    //         return; 
    //         }

    //         activeInput = event.target;
    //         Keyboard.setInput(activeInput.value);
    //         keyboardContainer.style.display = "block";
    //         setTimeout(() => {
    //             keyboardContainer.style.bottom = "0";
    //         }, 10);
    //     });
    // });

    // Input alanına tıklanınca klavyeyi aç
    document.querySelectorAll("input").forEach(input => {
        input.addEventListener("focus", event => {
            const activeEl = document.activeElement;
            if (activeEl.closest(".language-switcher")) return;
    
            activeInput = event.target;
            Keyboard.setInput(activeInput.value);
            keyboardContainer.style.display = "block";
    
            // Boşluk bırak ki klavye alanı üzerine binmesin
            document.body.style.paddingBottom = "260px";
    
            setTimeout(() => {
                keyboardContainer.style.bottom = "0";
            }, 10);
    
            // GSM Number input için scrollIntoView
            const isGSMInput =
                activeInput.placeholder === "GSM Number" ||
                activeInput.placeholder === "{{ _('GSM Number') }}";
    
            if (isGSMInput) {
                setTimeout(() => {
                    activeInput.scrollIntoView({
                        behavior: "smooth",
                        block: "center"
                    });
                }, 200);
            }
        });
    });
    

    // // Input dışında bir yere tıklanınca klavyeyi kapat
    // document.addEventListener("click", function (event) {
    //     if (!event.target.closest("input") && !event.target.closest("#keyboard-container")) {
    //         keyboardContainer.style.bottom = "-100%";
    //         setTimeout(() => {
    //             keyboardContainer.style.display = "none";
    //         }, 300);
    //         activeInput = null;
    //     }
    // });
    document.addEventListener("click", function (event) {
        if (!event.target.closest("input") && !event.target.closest("#keyboard-container")) {
            keyboardContainer.style.bottom = "-100%";
            setTimeout(() => {
                keyboardContainer.style.display = "none";
            }, 300);
            activeInput = null;
            document.body.style.paddingBottom = "0px"; // 🔄 sıfırla
        }
    });
    
});

document.querySelectorAll(".language-switcher button").forEach(button => {
    button.addEventListener("mousedown", (e) => {
        e.preventDefault();
    });
});
keyboardContainer.style.display = "block";
document.body.style.paddingBottom = "260px";  // geçici boşluk

