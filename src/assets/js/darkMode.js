let darkMode = false;

function toggleDark() {
    if (darkMode) disableDark();
    else enableDark();
    darkMode = !darkMode;
}


function enableDark() {
    document.body.classList.add("dark");
    $("input").addClass("dark");
    $("textarea").addClass("dark");
    $(".form-control").addClass("dark");
    $(".set-dark").addClass("dark");
    $(".card").addClass("dark");
    $("table").addClass("dark");
    $(".btn-primary").removeClass("dark");
}

function disableDark() {
    document.body.classList.remove("dark");
    $("input").removeClass("dark");
    $("textarea").removeClass("dark");
    $(".form-control").removeClass("dark");
    $(".set-dark").removeClass("dark");
    $("table").removeClass("dark");
    $(".card").removeClass("dark");
}