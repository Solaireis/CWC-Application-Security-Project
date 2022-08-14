// for editing teacher's bio
function editBioNow() {
    document.getElementById("originalTextarea").setAttribute("hidden", null);
    document.getElementById("editedTextarea").removeAttribute("hidden");
}
function cancelBio() {
    document.getElementById("originalTextarea").removeAttribute("hidden");
    document.getElementById("editedTextarea").setAttribute("hidden", null);
}

document.addEventListener("DOMContentLoaded", function() {
    let editProfileButton = document.getElementById("editProfileButton");
    let imageForm = document.getElementById("imageForm");
    editProfileButton.addEventListener("click", function() {
        imageForm.classList.toggle("d-none");
    });
});

function redirectUser() {
    location.reload();
}

document.getElementById("submitPfp").addEventListener("click", function(event){
    event.preventDefault()
    file = document.getElementById("myFile").files[0];
    form = document.getElementById("myFile").form
    var reader = new FileReader();
    reader.onload = function(e) {
        var hash = CryptoJS.SHA512(CryptoJS.lib.WordArray.create(e.target.result));
        const fileHash = hash.toString(CryptoJS.enc.Hex);
        var xhr = new XMLHttpRequest();
        var formData = new FormData(form);    
        xhr.open("POST", "/upload-profile-picture", true); // sends a GET request to the same page
        formData.append("fileHash", fileHash);
        xhr.send(formData);
    };
    reader.readAsArrayBuffer(file);
    setInterval(redirectUser, 1500);
});



