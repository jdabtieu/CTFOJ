document.querySelectorAll(".dt").forEach(function (e) {
    var split = e.innerHTML.split(" ");
    var date_split = split[0].split("-");
    var final = date_split[1] + "/" + date_split[2] + "/" + date_split[0] + " " + split[1];
    var parsed = new Date(final + " UTC").toString().split(" ");
    e.innerHTML = parsed[1] + " " + parsed[2] + ", " + parsed[3] + " " + parsed[4];
});
