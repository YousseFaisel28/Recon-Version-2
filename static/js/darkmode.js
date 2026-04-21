const toggleBtn = document.getElementById("darkModeToggle");

function applyTheme(theme) {
    if (theme === "dark") {
        document.documentElement.classList.add("dark", "dark-mode");
        localStorage.setItem("theme", "dark");
    } else {
        document.documentElement.classList.remove("dark", "dark-mode");
        localStorage.setItem("theme", "light");
    }
}

// Initial application (though handled by layout.html inline script as well)
const savedTheme = localStorage.getItem("theme");
if (savedTheme) {
    applyTheme(savedTheme);
} else if (document.documentElement.classList.contains("dark")) {
    // Default to dark if no preference but class is present
    applyTheme("dark");
}

if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
        const isDark = document.documentElement.classList.contains("dark");
        applyTheme(isDark ? "light" : "dark");
    });
}