// For general usage such as on the user profile page
function copyToClipBoard(typeOfData) {
    var tooltipEl = document.getElementById('tooltipValue' + typeOfData);
    navigator.clipboard.writeText(tooltipEl.innerText);

    // Updating the tooltip to show the updated tooltip title
    tooltipEl.setAttribute("data-bs-original-title", "Copied to clipboard!");
    var tooltipInstance = bootstrap.Tooltip.getInstance(tooltipEl);
    tooltipInstance.show();
}
function tooltipMouseOut(typeOfData) {
    var tooltipEl = document.getElementById('tooltipValue' + typeOfData);
    tooltipEl.setAttribute("data-bs-original-title", "Copy to clipboard");
}

let emailCopy = document.getElementById("tooltipValueEmail");
if (emailCopy) {
    emailCopy.onclick = function() {
        copyToClipBoard("Email");
    };
    emailCopy.onmouseout = function() {
        tooltipMouseOut("Email");
    };
}
let usernameCopy = document.getElementById("tooltipValueUsername");
if (usernameCopy) {
    usernameCopy.onclick = function() {
        copyToClipBoard("Username");
    };
    usernameCopy.onmouseout = function() {
        tooltipMouseOut("Username");
    };
}