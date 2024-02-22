function seeMore() {
    document.querySelectorAll(".see-more").forEach(e => {
        if (e.parentElement.parentElement.offsetHeight < 599) {
            e.parentElement.remove();
        } else {
            e.addEventListener("click", event => {
                event.preventDefault();
                e.parentElement.parentElement.style.maxHeight = "none";
                e.parentElement.remove();
            });
        }
    });
};
