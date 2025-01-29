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

