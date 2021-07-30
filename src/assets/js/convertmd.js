var converter = new showdown.Converter();
converter.setOption('openLinksInNewWindow', true);
converter.setOption('strikethrough', true);

function convertMD(toConvert) {
    return DOMPurify.sanitize(converter.makeHtml(toConvert), { ADD_ATTR: ['target'] });
}

function inject(targetDiv, content, unhide) {
    let shadow = targetDiv.attachShadow({mode: "open"});
    let container = document.createElement("div");
    container.innerHTML = convertMD(content);
    shadow.appendChild(container);
    container.querySelectorAll("*").forEach(e => {
        if (window.getComputedStyle(e).position === "fixed") {
            e.style.setProperty("position", "unset", "important");
        }
    });
    if (unhide) {
        targetDiv.classList.remove("hidden");
    }
}

// Deprecated in favor of API + inject function
for (element of document.getElementsByClassName('showdown')) {
    element.innerHTML = convertMD(element.getElementsByTagName('textarea')[0].value);
}
