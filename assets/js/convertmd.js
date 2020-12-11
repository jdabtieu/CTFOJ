var converter = new showdown.Converter()
$('.showdown').each(function() {
    this.innerHTML = converter.makeHtml($(this).find('textarea')[0].value);
})