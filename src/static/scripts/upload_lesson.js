$(document).ready(function(){
    $("#editProfileButton").click(function(){
        $("#imageForm").toggle();
    });
})
// ;$(document).ready(function(){
//     $("#editProfileButton").click(function(){
//         $("#imageForm").toggle();
//     });
// });

// Dropzone.js for segmenting data payload to chunks of data
// Useful resources:
// https://stackoverflow.com/questions/46728205/dropzone-submit-button-on-upload/46732882
// https://docs.dropzone.dev/

//Dropzone for lesson thumbnail
// Dropzone.options.dropper = {
//     maxFiles: 1,
//     paramName: 'lessonThumbnail',
//     acceptedFiles: ".jpeg,.jpg,.png",
//     chunking: true,
//     forceChunking: true,
//     url: '/upload_lesson',
//     maxFilesize: 50, // megabytes
//     chunkSize: 1000000, // bytes
//     retryChunks: true,
//     retryChunksLimit: 3,
//     autoProcessQueue: false,

//     init: function() {
//         let lessonThumbnailDropzone = this;
        
//         // when the user uploads more than one image, this function will remove the old lesson thumbnail and replace it with the new lesson thumbnail that was added by the user
//        lessonThumbnailDropzone.on("addedfile", function() {
//             $(".dz-progress").hide();
//             if (lessonThumbnailDropzone.files[1] == null) return;
//            lessonThumbnailDropzone.removeFile(userProfileImageDropzone.files[0]);
//         });

//         // tells dropzone to upload the image data to the web server when the user clicks on the upload button
//         document.getElementById('submit-button').addEventListener("click", function (e) {
//             e.preventDefault();
//            lessonThumbnailDropzone.processQueue();
//         });

//         // sending the chunks of data when user clicks on the upload button
//        lessonThumbnailDropzone.on('sending', function(file, xhr, formData) {
//             /* Append inputs to FormData */
//             $(".dz-progress").show();
//             formData.append("lessonThumbnail", document.getElementById('dropper').value);
//         });
        
//         // when the user profile image has been successfully uploaded, refresh the page after 1.5 seconds
//        lessonThumbnailDropzone.on("success", function () {
//             function redirectUser() {
//                 location.reload();
//             }
//             setInterval(redirectUser, 1500);
//         });
//     }
// };

function readURL(input) {
            if (input.files && input.files[0]) {
                var reader = new FileReader();

                reader.onload = function (e) {
                    $('#thumbnail')
                        .attr('src', e.target.result);
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
    url: '/upload_lesson',
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
            $(".dz-progress").hide();
            if (lesonVideoDropzone.files[1] == null) return;
           lesonVideoDropzone.removeFile(userProfileImageDropzone.files[0]);
        });

        // tells dropzone to upload the video data to the web server when the user clicks on the upload button
        document.getElementById('submit-button').addEventListener("click", function (e) {
            e.preventDefault();
           lesonVideoDropzone.processQueue();
        });

        // sending the chunks of data when user clicks on the upload button
        lesonVideoDropzone.on('sending', function(file, xhr, formData) {
            /* Append inputs to FormData */
            $(".dz-progress").show();
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


//     init: function() {
//         let lessonVideoDropzone = this;
        
//         // when the user uploads more than one video, this function will remove the old lesson video and replace it with the new lesson video that was added by the user
//        lessonVideoDropzone.on("addedfile", function() {
//             $(".dz-progress").hide();
//             if (lessonVideoDropzone.files[1] == null) return;
//            lessonVideoDropzone.removeFile(lessonVideoDropzone.files[0]);
//         });

//         // this tells dropzone to upload the video data to the web server when the user clicks on the upload button
//         document.getElementById('submit-button').addEventListener("click", function (e) {
//             e.preventDefault();
//            lessonVideoDropzone.processQueue();
//         });

//         // sending the chunks of data when user clicks on the upload button
//        lessonVideoDropzone.on('sending', function(file, xhr, formData) {
//             /* Append inputs to FormData */
//             $(".dz-progress").show();
//             formData.append("lessonVideo", document.getElementById('dropper').value);
//         });
        
//         // when the lesson video has been successfully uploaded, refresh the page after 1.5 seconds
//        lessonVideoDropzone.on("success", function () {
//             function redirectUser() {
//                 location.reload();
//             }
//             setInterval(redirectUser, 1500);
//         });
        
        

//         
//     }
// };

//  var lessonVideoDropzone = new Dropzone(document.getElementById("formDropZone", {
//     // options here
//  });

// // Update the total progress bar
// lessonVideoDropzone.on("totaluploadprogress", function(progress) {
//    // add code to edit bootstrap 5 progress
// });
