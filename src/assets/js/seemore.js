$(".see-more").each(function() {
    if ($(this).parent().parent().find(".showdown").height() < 490) {
        $(this).parent().remove();
    }
});

$(".see-more").click(function(event) {
    event.preventDefault();
    $(event.target).parent().parent().css("max-height", "");
    $(event.target).parent().remove()
});