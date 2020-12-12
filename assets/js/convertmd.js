var converter = new showdown.Converter()
$('.showdown').each(function() {
    var toConvert = $(this).find('textarea')[0].value;
    this.innerHTML = DOMPurify.sanitize(converter.makeHtml(toConvert));
})