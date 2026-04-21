function animateCounter(id, target, speed = 50) {
    let element = document.getElementById(id);
    let count = 0;

    let update = setInterval(() => {
        count += Math.ceil(target / 60); // smooth animation
        if (count >= target) {
            count = target;
            clearInterval(update);
        }
        element.textContent = count.toLocaleString();
    }, speed);
}

window.onload = () => {
    animateCounter("visitors", 12482);
    animateCounter("rating", 4.9); 
    animateCounter("scans", 8341);
};
