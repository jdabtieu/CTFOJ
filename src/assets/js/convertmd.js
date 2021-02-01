var converter = new showdown.Converter();
for (element of document.getElementsByClassName('showdown')) {
    var toConvert = element.getElementsByTagName('textarea')[0].value;
    element.innerHTML = DOMPurify.sanitize(converter.makeHtml(toConvert));
}