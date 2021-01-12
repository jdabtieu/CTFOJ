var page = new URL(window.location.href).searchParams.get("page");
$(() => $('#pagination').twbsPagination({
    totalPages: total_length,
    visiblePages: 7,
    startPage: page ? parseInt(page) : 1,
    initiateStartPageClick: false,
    onPageClick: function (event, page) {
        insertParam(page);
    }
}));

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