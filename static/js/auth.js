async function logout() {
    try {
        const response = await fetch('/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        // Always redirect and clear storage
        localStorage.clear();
        sessionStorage.clear();
        window.location.href = '/login';
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/login';
    }
}
