function loadPage(page) {
    const content = document.getElementById("content-area");

    // Built-in home page
    if (page === 'welcome') {
        content.innerHTML = `
            <h1 class="welcome-title">Welcome Admin</h1>
            <p class="sub-text">Choose an option from the left menu</p>
            <div class="center-icon">
              <img src="../assets/images/shield.png" class="shield-icon">
            </div>
        `;
        return;
    }

    // Load HTML from the same folder as Admin.html
    fetch(`${page}.html`)
    .then(r => r.text())
    .then(html => {
        content.style.opacity = 0;
        setTimeout(() => {
            content.innerHTML = html;
            content.style.opacity = 1;
        }, 200);
    });
}
