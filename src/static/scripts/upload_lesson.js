document.addEventListener("DOMContentLoaded", function() {
    let editProfileButton = document.getElementById("editProfileButton");
    let imageForm = document.getElementById("imageForm");
    editProfileButton.addEventListener("click", function() {
        imageForm.classList.toggle("d-none");
    });
});

function readURL(input) {
    if (input.files && input.files[0]) {
        var reader = new FileReader();

        reader.onload = function (e) {
            document.getElementById("thumbnail").setAttribute("src", e.target.result);
        };

        reader.readAsDataURL(input.files[0]);
    };
};

//Dropzone for lesson video
Dropzone.options.dropper = {
    maxFiles: 1,
    paramName: 'lessonVideo',
    acceptedFiles: ".mp4, .mov, .avi",
    chunking: true,
    forceChunking: true,
    url: "/upload_lesson",
    maxFilesize: 10000, // megabytes
    chunkSize: 1000000, // bytes
    retryChunks: true,
    retryChunksLimit: 3,
    autoProcessQueue: true,
    autoQueue: false, // Make sure the files aren't queued until manually added
    previewsContainer: "#previews", // Define the container to display the previews
    clickable: ".fileinput-button", // Define the element that should be used as click trigger to select files.

    init: function() {
        let lessonVideoDropzone = this;
        // when the user uploads more than one video, this function will remove the old video and replace it with the new lesson video that was added by the user
        lesonVideoDropzone.on("addedfile", function() {
            document.querySelector(".dz-progress").classList.add("d-none");
            if (lesonVideoDropzone.files[1] == null) return;
            lesonVideoDropzone.removeFile(userProfileImageDropzone.files[0]);
        });

        // tells dropzone to upload the video data to the web server when the user clicks on the upload button
        document.getElementById("submit-button").addEventListener("click", function (e) {
            e.preventDefault();
            lesonVideoDropzone.processQueue();
        });

        // sending the chunks of data when user clicks on the upload button
        lesonVideoDropzone.on("sending", function(file, xhr, formData) {
            /* Append inputs to FormData */
            document.querySelector(".dz-progress").classList.remove("d-none");
            formData.append("lessonVideo", document.getElementById('dropper').value);
        });
        
        // when the user profile image has been successfully uploaded, refresh the page after 1.5 seconds
        lesonVideoDropzone.on("success", function () {
            function redirectUser() {
                location.reload();
            }
            setInterval(redirectUser, 1500);
        });
        
        /* Start of Progress bar */
        // Update the total progress bar
        lessonVideoDropzone.on("totaluploadprogress", function(progress) {
            document.querySelector("#total-progress .progress-bar").style.width = progress + "%";
        });
        
        lessonVideoDropzone.on("sending", function(file) {
            // Show the total progress bar when upload starts
            document.querySelector("#total-progress").style.opacity = "1";
            // And disable the start button
            file.previewElement.querySelector(".start").setAttribute("disabled", "disabled");
        });
        
        // Hide the total progress bar when nothing's uploading anymore
        lessonVideoDropzone.on("queuecomplete", function(progress) {
            document.querySelector("#total-progress").style.opacity = "0";
        });
        /* End of Progress bar */
    }
};