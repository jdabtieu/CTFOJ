var converter = new showdown.Converter();
converter.setOption('openLinksInNewWindow', true);
converter.setOption('strikethrough', true);

function addCSS(content) {
    let style = `
        <link rel="stylesheet"
              href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css"
              crossorigin="anonymous">
        <link href="/assets/css/style.css" rel="stylesheet">`;
    return style + content;
}
function convertMD(toConvert) {
    return DOMPurify.sanitize(converter.makeHtml(toConvert), { ADD_ATTR: ['target'] });
}

function _inject(shadow, content, editing) {
    let container = document.createElement("div");
    container.innerHTML = addCSS(convertMD(content));
    shadow.replaceChildren(container);
    container.querySelectorAll("*").forEach(e => {
        if (window.getComputedStyle(e).position === "fixed") {
            e.style.setProperty("position", "unset", "important");
        }
    });
}

function inject(targetDiv, content, unhide) {
    let shadow = targetDiv.attachShadow({mode: "open"});
    _inject(shadow, content);
    if (unhide) {
        targetDiv.classList.remove("hidden");
    }
}

function injectEditor(targetDiv, content) {
    _inject(targetDiv.shadowRoot, content);
}