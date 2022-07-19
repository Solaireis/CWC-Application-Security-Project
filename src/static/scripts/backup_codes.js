const downloadCodes = document.getElementById("downloadCodes");
const activeBackupCodes = document.querySelectorAll("span.backupCodeActive");
const usedBackupCodes = document.querySelectorAll("span.backupCodeUsed");

downloadCodes.addEventListener("click", function() {
    // Construct a string to hold the backup codes.
    var backupCodesText = "";
    for (var i = 0; i < activeBackupCodes.length; i++) {
        backupCodesText += activeBackupCodes[i].innerText + "\n";
    }
    for (var i = 0; i < usedBackupCodes.length; i++) {
        backupCodesText += usedBackupCodes[i].innerText + " (Used)\n";
    }

    // Create a link to download the backup codes (client-side).
    var backupCodesBlob = new Blob([backupCodesText], {type: "text/plain;charset=utf-8"});
    var backupCodesURL = URL.createObjectURL(backupCodesBlob);
    var backupCodesLink = document.createElement("a");
    backupCodesLink.href = backupCodesURL;
    backupCodesLink.download = "backup_codes.txt";
    backupCodesLink.click();
});

// Get the HTML content for formatting it into a new HTML page for printing
const backupCodesHTML = document.getElementById("backupCodesTable");
const backupCodesTitle = document.getElementById("backupCodesTitle");
const backupCodesDesc = document.getElementById("backupCodesDesc");
const backupCodesImpt = document.getElementById("backupCodesImpt");
document.getElementById("printCodes").addEventListener("click", function() {
    // open a new tab with the html content of the backup codes for the user to print
    var myWindow = window.open("", "PRINT", "width=800,height=600");

    // Write the html head content to the new tab
    myWindow.document.write("<html><head><title>Print Backup Codes</title>");
    myWindow.document.write('<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous"></head><body class="p-5">');

    // Write the html body content
    myWindow.document.write(`<h1>${backupCodesTitle.innerText}</h1>`);
    myWindow.document.write(`<p>${backupCodesDesc.innerText}</p>`);
    myWindow.document.write(`<p>${backupCodesImpt.innerText}</p>`);
    myWindow.document.write(backupCodesHTML.innerHTML);

    // Finished writing the html body content
    myWindow.document.write("</body></html>");
    myWindow.document.close();

    // Focus on the new tab 
    // and prompt the print window
    myWindow.focus();
    myWindow.print();
});