var converter = new showdown.Converter();
converter.setOption('openLinksInNewWindow', true);
converter.setOption('strikethrough', true);

function convertMD(toConvert) {
    return DOMPurify.sanitize(converter.makeHtml(toConvert), { ADD_ATTR: ['target'] });
}

for (element of document.getElementsByClassName('showdown')) {
    element.innerHTML = convertMD(element.getElementsByTagName('textarea')[0].value);
}
