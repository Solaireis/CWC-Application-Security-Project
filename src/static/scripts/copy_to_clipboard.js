// For specific use cases on the user management page
function emailCopyToClipBoard(userID) {
    var copiedText = document.getElementById('emailTooltipValue' + userID);
    navigator.clipboard.writeText(copiedText.innerText);
    var tooltipEl = document.getElementById('userEmailTooltip' + userID);
    // using jquery to change the tooltip title so that the admin knows that they have copied
    $(tooltipEl).attr('title', 'Copied to clipboard!').tooltip('_fixTitle').tooltip('show')
}
function emailTooltipMouseOut(userID) {
    var tooltipEl = document.getElementById('userEmailTooltip' + userID);
    // using jquery to reset the tooltip title
    $(tooltipEl).attr('title', 'Copy to clipboard').tooltip('_fixTitle').tooltip('hide')
}
function usernameCopyToClipBoard(userID) {
    var copiedText = document.getElementById('usernameTooltipValue' + userID);
    navigator.clipboard.writeText(copiedText.innerText);
    var tooltipEl = document.getElementById('usernameTooltip' + userID);
    // using jquery to change the tooltip title so that the admin knows that they have copied
    $(tooltipEl).attr('title', 'Copied to clipboard!').tooltip('_fixTitle').tooltip('show')
}
function usernameTooltipMouseOut(userID) {
    var tooltipEl = document.getElementById('usernameTooltip' + userID);
    // using jquery to reset the tooltip title
    $(tooltipEl).attr('title', 'Copy to clipboard').tooltip('_fixTitle').tooltip('hide')
}
function userIDCopyToClipBoard(userID) {
    var copiedText = document.getElementById('userIDTooltipValue' + userID);
    navigator.clipboard.writeText(copiedText.innerText);
    var tooltipEl = document.getElementById('userIDTooltip' + userID);
    // using jquery to change the tooltip title so that the admin knows that they have copied
    $(tooltipEl).attr('title', 'Copied to clipboard!').tooltip('_fixTitle').tooltip('show')
}
function userIDTooltipMouseOut(userID) {
    var tooltipEl = document.getElementById('userIDTooltip' + userID);
    // using jquery to reset the tooltip title
    $(tooltipEl).attr('title', 'Copy to clipboard').tooltip('_fixTitle').tooltip('hide')
}





// For general usage such as on the user profile page
function copyToClipBoard(typeOfData) {
    var copiedText = document.getElementById('tooltipValue' + typeOfData);
    navigator.clipboard.writeText(copiedText.innerText);
    var tooltipEl = document.getElementById('tooltipElement' + typeOfData);
    // using jquery to change the tooltip title so that the admin knows that they have copied
    $(tooltipEl).attr('title', 'Copied to clipboard!').tooltip('_fixTitle').tooltip('show')
}
function tooltipMouseOut(typeOfData) {
    var tooltipEl = document.getElementById('tooltipElement' + typeOfData);
    // using jquery to reset the tooltip title
    $(tooltipEl).attr('title', 'Copy to clipboard').tooltip('_fixTitle').tooltip('hide')
}





//For enquiry messages which are gigantic and contain very a lot of unescaped characters
function copyEnquiryToClipBoard(enquiryNumber) {
    var copiedText = document.getElementById('tooltipEnquiryValue' + enquiryNumber).innerText;
    navigator.clipboard.writeText(copiedText);
    var copyButton = document.getElementById('copyEnquiryToClipboardButton' + enquiryNumber);
    copyButton.innerText = "Copied to Clipboard!";
}

function openEnquiryModal(enquiryNumber) {
    var copyButton = document.getElementById('copyEnquiryToClipboardButton' + enquiryNumber);
    copyButton.innerText = "Copy to Clipboard";
}


function ticketIDCopyToClipBoard(ticketID) {
    var copiedText = document.getElementById('ticketIDTooltipValue' + ticketID);
    navigator.clipboard.writeText(copiedText.innerText);
    var tooltipEl = document.getElementById('ticketIDTooltip' + ticketID);
    // using jquery to change the tooltip title so that the admin knows that they have copied
    $(tooltipEl).attr('title', 'Copied to clipboard!').tooltip('_fixTitle').tooltip('show')
}
function ticketIDTooltipMouseOut(ticketID) {
    var tooltipEl = document.getElementById('ticketIDTooltip' + ticketID);
    // using jquery to reset the tooltip title
    $(tooltipEl).attr('title', 'Copy to clipboard').tooltip('_fixTitle').tooltip('hide')
}

