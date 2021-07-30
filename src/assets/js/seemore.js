document.querySelectorAll(".see-more").forEach(e => {
    if (e.parentElement.parentElement.querySelector(".smarkdown").offsetHeight < 490) {
        e.parentElement.remove();
    } else {
        e.addEventListener("click", event => {
            event.preventDefault();
            e.parentElement.parentElement.style.maxHeight = "none";
            e.parentElement.remove();
        });
    }
});