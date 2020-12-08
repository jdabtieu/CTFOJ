var converter = new showdown.Converter()
$('.showdown').each(function() {
    this.innerHTML = converter.makeHtml(this.innerHTML.trim());
})