let downloadCodes = document.getElementById("downloadCodes");
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

document.addEventListener("DOMContentLoaded", function() {
    const pdfDoc = new jspdf();
    let printCodes = document.getElementById("printCodes");

    var backUpCodesHTML = document.getElementById("userForm");
    printCodes.addEventListener("click", function() {
        pdfDoc.fromHTML(backUpCodesHTML, 15, 15, {
            'width': 170,
            'elementHandlers': specialElementHandlers
        });
        pdfDoc.output("dataurlnewwindow");
    });
});