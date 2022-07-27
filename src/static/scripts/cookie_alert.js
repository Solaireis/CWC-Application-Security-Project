/* ---------------  Cookie alert Javascript --------------- */

// Cookie functions from w3schools
function set_cookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    // cookie attributes settings in javascript: 
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
    document.cookie = `${cname}=${cvalue}; expires=${d.toUTCString()}; Path=/; SameSite=lax; Secure`;
}

function get_cookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(";");
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) === " ") {
            c = c.substring(1);
        }
        if (c.indexOf(name) === 0) {
            return c.substring(name.length, c.length);
        }
    }
    return "";
}

document.addEventListener("DOMContentLoaded", function () {
    "use strict";

    let cookieAlert = document.querySelector(".cookiealert");
    let acceptCookies = document.querySelector(".acceptcookies");
    let importantAcknowledgement = new bootstrap.Modal(document.getElementById("importantModal"), {});
    let importantAcknowledgementBtn = document.getElementById("importantModalButton");

    if (!cookieAlert && !importantAcknowledgement) {
        return;
    }

    cookieAlert.offsetHeight; // Force browser to trigger reflow

    // Show the alert if we cant find the "accepted_cookies" cookie
    if (!get_cookie("accepted_cookies")) {
        cookieAlert.classList.add("show");
    }

    // Show the alert if we cant find the "risks_accepted" cookie
    if (!get_cookie("risks_accepted")) {
        importantAcknowledgement.show();
    }

    // When clicking on the agree button, create a 30 days
    // cookie to remember user's choice and close the banner/modal
    acceptCookies.addEventListener("click", function () {
        set_cookie("accepted_cookies", true, 30);
        cookieAlert.classList.remove("show");

        // dispatch the accept event
        window.dispatchEvent(new Event("cookieAlertAccept"));
    });

    importantAcknowledgementBtn.addEventListener("click", function () {
        set_cookie("risks_accepted", true, 30);

        // dispatch the accept event
        window.dispatchEvent(new Event("serviceAccepted"));
    });
});

/* ---------------  End of Edited Cookie warning alert Javascript --------------- */