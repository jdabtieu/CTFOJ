$(".see-more").each(function() {
    if ($(this).parent().parent().find(".showdown").height() < 490) {
        $(this).parent().remove();
    }
});

$(".see-more").click(function(event) {
    event.preventDefault();
    event.target.parentElement.parentElement.style.maxHeight = "";
    event.target.parentElement.remove();
});