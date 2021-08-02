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
    document.body.classList.add("dark");
    document.querySelector(".dark-toggle").setAttribute("checked", "");
}

document.querySelector(".dark-toggle").addEventListener("click", function() {
    document.body.classList.toggle("dark");
    setCookie("darkMode", getCookie("darkMode") == 1 ? 0 : 1, 7);
});
