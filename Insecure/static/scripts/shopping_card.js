function unavailable() {
    var unavailables = document.getElementsByClassName("unavailable");
    for (var unavailable = 0; unavailable < unavailables.length; unavailable++) {
        document.getElementsByClassName("unavailable")[unavailable].innerHTML += "*Unavailable*";
    }
}

window.onload = unavailable();

function removeCourse(courseID) {
    document.getElementById(courseID).submit();
    console.log(courseID);
}


//https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_form_submit


/*PayPal Buttons Responsiveness*/
function PayPalMove() {
    if (window.matchMedia("(max-width: 825px)").matches) {
        //Width of window reaches <= 825px
        //console.log("PayPalDown!");
        document.getElementsByClassName("col-4")[0].className = "not-col-4";
    }
    else {
        //Width of window reaches > 825px
        //console.log("PayPalReturn!");
        document.getElementsByClassName("not-col-4")[0].className = "col-4";
    }
}

moveCondition = window.matchMedia("(max-width: 825px)");
moveCondition.addListener(PayPalMove);

document.getElementById("paypal-container").onload = PayPalMove();

