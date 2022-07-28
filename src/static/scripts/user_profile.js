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

// Dropzone.js for segmenting data payload to chunks of data
// Useful resources:
// https://stackoverflow.com/questions/46728205/dropzone-submit-button-on-upload/46732882
// https://docs.dropzone.dev/

Dropzone.options.dropper = {
    url: "/upload-profile-picture", // Determines where to reroute after submission
    chunking: true, // Enable chunking
    forceChunking: true, // Force chunking to happen
    chunkSize: 50000000, // Size of each chunk in bytes (Need to clarify this, default:50mb)
    retryChunks: true, // Retry chunk uploads
    retryChunksLimit: 3, // Number of times to retry chunk uploads (third times the charm)
    maxFilesize: 5000, // Maximum size of each file in MB (current: 5GB)
    paramName: "profilePic", // The name of the uploaded file
    maxFiles: 1, // Number of files allowed to be uploaded
    acceptedFiles: ".png, .jfif, .jpg, .jpeg", //allowed file extensions 
    addRemoveLinks: true, // ability to remove
    autoProcessQueue: true, // whether to automatically process the queue after adding a file (set to false jic)
    init: function() {
        // var fileHash;
        // HASH IS CORRECT :D, now need send across
        this.on("addedfile", function(file) {
            var reader = new FileReader();
            var xhr = new XMLHttpRequest();
            reader.onload = function(event) {
                var hash = CryptoJS.SHA512(CryptoJS.lib.WordArray.create(event.target.result));
                const fileHash = hash.toString(CryptoJS.enc.Hex);
                xhr.open("POST", "", true); // sends a GET request to the same page
                xhr.setRequestHeader("Content-Type", "application/json");
                const jsonData = {
                    hash: fileHash
                }
                xhr.send(JSON.stringify(jsonData));
            };
            reader.readAsArrayBuffer(file);
        });

        this.on("removedfile", function(file) {
            console.log("File " + file.name + " removed");
        });
        
        // comment this out when testing hash
        this.on("success", function (file) {
            function redirectUser() {
                location.reload();
            }
            setInterval(redirectUser, 1500);
        });
    }
};