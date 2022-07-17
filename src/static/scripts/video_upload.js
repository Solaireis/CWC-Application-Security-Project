// For Dropzone
// https://github.com/dropzone/dropzone/blob/main/src/options.js

Dropzone.options.dropper = {
    url: "/create-course", // Determines where to reroute after submission
    chunking: true, // Enable chunking
    forceChunking: true, // Force chunking to happen
    chunkSize: 2000000, // Size of each chunk in bytes (Need to clarify this, default:2mb)
    retryChunks: true, // Retry chunk uploads
    retryChunksLimit: 3, // Number of times to retry chunk uploads (third times the charm)
    maxFilesize: 10000, // Maximum size of each file in MB (current: 10GB)
    paramName: "videoUpload", // The name of the uploaded file
    maxFiles: 1, // Number of files allowed to be uploaded
    acceptedFiles: ".mp4, .mov, .wmv, .avi, .webm", //allowed file extensions (clarify with waffles)
    autoProcessQueue: false, // whether to automatically process the queue after adding a file (set to false jic)
    init: function() {
        //function will remove older video if one is already uploaded
        this.on("addedfile", function() {
            document.querySelector(".dz-progress").classList.add("d-none");
            if (this.files[1] == null) 
                return;
            this.removeFile(this.files[0]);
        });
    }
};

// For video upload

var input = document.getElementById( 'upload' );
var infoArea = document.getElementById( 'file-upload-filename' );

input.addEventListener( 'change', showFileName );

function showFileName( event ) {

// the change event gives us the input it occurred in 
var input = event.srcElement;

// the input has an array of files in the `files` property, each one has a name that you can use. We're just using the name here.
var fileName = input.files[0].name;

// use fileName however fits your app best, i.e. add it into a div
infoArea.textContent = 'File name: ' + fileName;
}