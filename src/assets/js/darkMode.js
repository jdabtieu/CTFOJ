function setCookie(name, val, exp) {
    var d = new Date();
    d.setTime(d.getTime() + (exp*24*60*60*1000)); // expiry in days
    var expires = "expires=" + d.toUTCString();
    document.cookie = name + "=" + val + ";" + expires + ";path=/";
}

function getCookie(name) {
    name += "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for(var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) == ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) == 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

if (getCookie("darkMode") == 1) {
    enableDark();
    document.querySelector(".dark-toggle").setAttribute("checked", "");
}

function toggleDark() {
    if (getCookie("darkMode") == 1) {
        disableDark();
        setCookie("darkMode", 0, 7);
    } else {
        enableDark();
        setCookie("darkMode", 1, 7);
    }
}


function enableDark() {
    document.body.classList.add("dark");
}
function disableDark() {
    document.body.classList.remove("dark");
}