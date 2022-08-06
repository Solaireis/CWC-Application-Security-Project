/* --------------- START OF HAMBURGER MENU JAVASCRIPT --------------- */

let navBtn = document.getElementById("nav-icon");
let navBtnContent = document.getElementById("navbar-content");
let navBtnInput = document.getElementById("check");

function btnclick() {
    navBtnContent.className === "navbar-collapse collapse show" && navBtnInput.getAttribute("aria-expanded")
        ? navBtn.classList.remove("openTrue") : navBtn.classList.add("openTrue");
}

navBtn.addEventListener("click", btnclick);

/* --------------- END OF HAMBURGER MENU JAVASCRIPT --------------- */

/* --------------- Start of footer copyright year Javascript --------------- */

let footerCopright = document.getElementById("copyright_year").appendChild(document.createTextNode(new Date().getFullYear()));

/* --------------- End of footer copyright year Javascript --------------- */

/* --------------- Start of Go to top button Javascript --------------- */

var scrollToTopBtn = document.getElementById("topbutton");

window.onscroll = function(){
    scrollFunction();
};

function scrollFunction(){
    document.body.scrollTop > 20 || document.documentElement.scrollTop > 20 
        ? scrollToTopBtn.classList.add("show") : scrollToTopBtn.classList.remove("show");
}

scrollToTopBtn.addEventListener("click", scrollToTop);

var rootElement = document.documentElement;

function scrollToTop() {
    rootElement.scrollTo({
        top: 0, 
        behavior: "smooth" 
    });
}

/* --------------- End of Go to top button Javascript --------------- */

/* --------------- Start of Inactivity Modal Javascript --------------- */

// Code from https://stackoverflow.com/questions/667555/how-to-detect-idle-time-in-javascript
function idleLogout() {
    let timer; 
    const idleTimeLimit = 1 * 60 * 60 * 1000; // 1 hour
    window.onload = resetTimer;
    window.onmousemove = resetTimer;
    window.onmousedown = resetTimer;  // catches touchscreen presses as well      
    window.ontouchstart = resetTimer; // catches touchscreen swipes as well      
    window.ontouchmove = resetTimer;  // required by some devices 
    window.onclick = resetTimer;      // catches touchpad clicks as well
    window.onkeydown = resetTimer;   
    window.addEventListener("scroll", resetTimer, true);

    function showInactivityModal() {
        var inactivityModal = new bootstrap.Modal(inacitivityModalEl, {});
        inactivityModal.show();
    }

    function resetTimer() {
        clearTimeout(timer);
        timer = setTimeout(showInactivityModal, idleTimeLimit);  // time is in milliseconds
    }

    document.getElementById("inactivityModalButton").addEventListener("click", function() {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "", true); // sends a GET request to the same page
        xhr.send();
    });
}

let inacitivityModalEl = document.getElementById("inacitivityModal");
if (inacitivityModalEl) {
    idleLogout();
}

/* --------------- End of Inactivity Modal Javascript --------------- */