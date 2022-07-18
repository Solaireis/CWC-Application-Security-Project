// Form elements
let flashMsg = document.getElementById("flashMsg");
let passForm = document.getElementById("passForm");
let passInput = document.getElementById("password");
let cfmPass = document.getElementById("cfmPassword");
let passError = document.getElementById("passwordError");
let passErrorMsg = document.getElementById("passwordErrorMsg");

// Password complexity requirement elements 
const numOfRegex = 6;
let strengthIndicator = document.getElementById("strengthIndicator");
let uppercase = document.getElementById("uppercase");
let lowercase = document.getElementById("lowercase");
let number = document.getElementById("number");
let specialChar = document.getElementById("specialChar");
let eightChar = document.getElementById("eightChar");
let twoRepeatChar = document.getElementById("twoRepeatChar");

// regex
const allowedChar = /^[A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]{1,}$/;
const twoRepeatCharRegex = /^(?!.*([A-Za-z\d!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^])\1{2}).+$/;
const eightCharRegex = /^.{8,}$/;
const specialCharRegex = /[!@#$&\\()\|\-\?`.+,/\"\' \[\]{}=<>;:~%*_^]+/;
const lowercaseRegex = /[a-z]+/;
const uppercaseRegex = /[A-Z]+/;
const numberRegex = /[\d]+/;

function checkPasswords() {
    var failed = false;
    var progressPercent = parseInt(strengthIndicator.style.width);
    if (progressPercent < (100 / numOfRegex) * 3) {
        if (passError.hidden) {
            passError.hidden = false;
        }
        passErrorMsg.innerHTML = "Entered password must at least match three requirements!";
        failed = true;
    }

    if (passInput.value !== cfmPass.value) {
        if (passError.hidden) {
            passError.hidden = false;
        }
        passErrorMsg.innerHTML = "Entered passwords do not match!";
        failed = true;
    }

    if (failed) {
        if (flashMsg) {
            flashMsg.remove();
        }
        return false;
    }

    return true;
}

if (passForm) {
    passForm.addEventListener("submit", function(e) {
        e.preventDefault();
        var successfulChecks = checkPasswords();
        if (successfulChecks) {
            passForm.submit();
        }
    });
}

passInput.addEventListener("input", function(e) {
    var pass = passInput.value;
    var strength = 0;

    // check if password contains at least one uppercase letter
    if (pass.match(uppercaseRegex)) {
        uppercase.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        uppercase.className = "far fa-times-circle text-danger";
    }

    // check if password contains at least one lowercase letter
    if (pass.match(lowercaseRegex)) {
        lowercase.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        lowercase.className = "far fa-times-circle text-danger";
    }

    // check if password contains at least one number
    if (pass.match(numberRegex)) {
        number.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        number.className = "far fa-times-circle text-danger";
    }

    // check if password contains at least one special character
    if (pass.match(specialCharRegex)) {
        specialChar.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        specialChar.className = "far fa-times-circle text-danger";
    }

    // check if password contains at least 8 characters
    if (pass.match(eightCharRegex)) {
        eightChar.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        eightChar.className = "far fa-times-circle text-danger";
    }

    // check if password does not contain more than 2 identical characters consecutively
    if (pass.match(twoRepeatCharRegex)) {
        twoRepeatChar.className = "far fa-check-circle text-success";
        strength++;
    }
    else {
        twoRepeatChar.className = "far fa-times-circle text-danger";
    }

    // Reflect the strength in the progress bar
    strengthIndicator.style.width = (strength / numOfRegex * 100) + "%";
    strengthIndicator.setAttribute("aria-valuenow", (strength / numOfRegex * 100));
});