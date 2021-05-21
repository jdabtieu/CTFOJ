const paginationDiv = document.querySelector("#pagination");

if (paginationDiv != null) {
    // get current & total pages
    var currentPage = new URL(window.location.href).searchParams.get("page");
    var totalPages = paginationDiv.getAttribute("data-pages");
    const displayedPages = 3;
    currentPage = currentPage ? parseInt(currentPage) : 1;
    totalPages = Math.max(1, totalPages);

    if (currentPage < 0 || currentPage > totalPages) {
        throw "Current page must be between 1 and the total pages";
    }

    // calculate left and right bounds
    var paginationBegin, paginationEnd;
    if (2 * displayedPages + 1 > totalPages) {
       paginationBegin = 1;
       paginationEnd = totalPages;
    } else {
        paginationBegin = currentPage - displayedPages;
        paginationEnd = currentPage + displayedPages
        if (paginationBegin <= 0) {
            let tmp = 1 - paginationBegin;
            paginationBegin += tmp;
            paginationEnd += tmp;
        } else if (paginationEnd > totalPages) {
            let tmp = paginationEnd - totalPages;
            paginationBegin -= tmp;
            paginationEnd -= tmp;
        }
    }

    // function to modify page parameter in URI
    function insertParam(value) {
        key = "page";

        // kvp looks like ['key1=value1', 'key2=value2', ...]
        var kvp = document.location.search.substr(1).split('&');
        let i = 0;

        for(; i < kvp.length; i++){
            if (kvp[i].startsWith('page=')) {
                let pair = kvp[i].split('=');
                pair[1] = value;
                kvp[i] = pair.join('=');
                break;
            }
        }

        if(i >= kvp.length){
            kvp[kvp.length] = ["page", value].join('=');
        }

        document.location.search = kvp.join('&');
    }

    // determine if we need to disable the First, Prev, Next, and Last buttons
    var disableFirst = (currentPage == 1 ? "disabled" : "");
    var disableLast = (currentPage == totalPages ? "disabled" : "");

    // create the pagination tree
    var e = document.createElement("ul");
    e.classList.add("pagination");
    e.innerHTML +=
        `<li class="page-item first ${disableFirst}"><a href="#" class="page-link">First</a></li>`;
    e.innerHTML +=
        `<li class="page-item prev ${disableFirst}"><a href="#" class="page-link">Prev</a></li>`;
    for (let i = paginationBegin; i < currentPage; i++) {
        e.innerHTML += `<li class="page-item"><a href="#" class="page-link">${i}</a></li>`;
    }
    e.innerHTML +=
        `<li class="page-item active"><a href="#" class="page-link">${currentPage}</a></li>`;
    for (let i = currentPage + 1; i <= paginationEnd; i++) {
        e.innerHTML += `<li class="page-item"><a href="#" class="page-link">${i}</a></li>`;
    }
    e.innerHTML +=
        `<li class="page-item next ${disableLast}"><a href="#" class="page-link">Next</a></li>`;
    e.innerHTML +=
        `<li class="page-item last ${disableLast}"><a href="#" class="page-link">Last</a></li>`;

    // and append the pagination tree to the DOM
    paginationDiv.append(e);

    // attach event listeners
    document.querySelectorAll(".page-item").forEach(e => {
        if (!e.classList.contains("active") && !e.classList.contains("disabled")) {
            e.addEventListener("click", function() {
                switch (this.innerText) {
                case "First":
                    insertParam("1");
                    break;
                case "Prev":
                    insertParam(currentPage - 1);
                    break;
                case "Next":
                    insertParam(currentPage + 1);
                    break;
                case "Last":
                    insertParam(totalPages);
                    break;
                default:
                    insertParam(this.innerText);
                }
            });
        }
    });
}