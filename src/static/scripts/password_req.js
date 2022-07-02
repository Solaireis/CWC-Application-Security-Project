// Form elements
let flashMsg = document.getElementById("flashMsg");
let signupForm = document.getElementById("signupForm");
let passInput = document.getElementById("password");
let cfmPass = document.getElementById("cfm_password");
let passErrorOne = document.getElementById("passwordError1");
let passErrorTwo = document.getElementById("passwordError2");

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

signupForm.addEventListener("submit", function(e) {
    var failed = false;
    var progressPercent = strengthIndicator.style.width;
    if (progressPercent <= "0%") {
        e.preventDefault();
        passErrorOne.hidden = true;
        passErrorTwo.hidden = false;
        failed = true;
    }

    if (passInput.value !== cfmPass.value) {
        e.preventDefault();
        if (passErrorOne.hidden) {
            passErrorOne.hidden = false;
            passErrorTwo.hidden = true;
        }
        failed = true;
    }

    if (failed) {
        flashMsg.remove();
        return;
    }

    signupForm.submit();
});

passInput.addEventListener("keyup", function(e) {
    var pass = passInput.value;
    var strength = 0;

    if (pass.length > 0) {
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
    }
    else {
        uppercase.classList.remove("text-success");
        lowercase.classList.remove("text-success");
        number.classList.remove("text-success");
        specialChar.classList.remove("text-success");
        eightChar.classList.remove("text-success");
        twoRepeatChar.classList.remove("text-success");
    }
});