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
    maxFiles: 1,
    paramName: 'profileImage',
    acceptedFiles: ".jpeg,.jpg,.png",
    chunking: true,
    forceChunking: true,
    url: '/user_profile',
    maxFilesize: 50, // megabytes
    chunkSize: 1000000, // bytes
    retryChunks: true,
    retryChunksLimit: 3,
    autoProcessQueue: false,
    init: function() {
        let userProfileImageDropzone = this;
        
        // when the user uploads more than one image, this function will remove the old user profile image and replaces it with the new user profile image that was added by the user
        userProfileImageDropzone.on("addedfile", function() {
            document.querySelector(".dz-progress").classList.add("d-none");
            if (userProfileImageDropzone.files[1] == null) return;
            userProfileImageDropzone.removeFile(userProfileImageDropzone.files[0]);
        });

        // tells dropzone to upload the image data to the web server when the user clicks on the upload button
        document.getElementById('submit-button').addEventListener("click", function (e) {
            e.preventDefault();
            userProfileImageDropzone.processQueue();
        });

        // sending the chunks of data when user clicks on the upload button
        userProfileImageDropzone.on('sending', function(file, xhr, formData) {
            /* Append inputs to FormData */
            document.querySelector(".dz-progress").classList.remove("d-none");
            formData.append("profileImage", document.getElementById('dropper').value);
        });
        
        // when the user profile image has been successfully uploaded, refresh the page after 1.5 seconds
        userProfileImageDropzone.on("success", function () {
            function redirectUser() {
                location.reload();
            }
            setInterval(redirectUser, 1500);
        });
    }
};