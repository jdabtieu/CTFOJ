document.querySelectorAll(".see-more").forEach(e => {
    if (e.parentElement.parentElement.querySelector(".showdown").offsetHeight < 490) {
        e.parentElement.remove();
    } else {
        e.addEventListener("click", event => {
            event.preventDefault();
            e.parentElement.parentElement.style.maxHeight = "";
            e.parentElement.remove();
        });
    }
});