// For Dropzone
// https://github.com/dropzone/dropzone/blob/main/src/options.js

Dropzone.options.dropper = {
    url: "/upload-video", // Determines where to reroute after submission
    chunking: true, // Enable chunking
    forceChunking: true, // Force chunking to happen
    chunkSize: 50000000, // Size of each chunk in bytes (Need to clarify this, default:50mb)
    retryChunks: true, // Retry chunk uploads
    retryChunksLimit: 3, // Number of times to retry chunk uploads (third times the charm)
    maxFilesize: 500, // Maximum size of each file in MB (current: 500mb)
    paramName: "videoUpload", // The name of the uploaded file
    maxFiles: 1, // Number of files allowed to be uploaded
    acceptedFiles: ".mp4, .mov, .wmv, .avi, .webm", //allowed file extensions (clarify with waffles)
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
        

        // Testing something
        // this.on("queuecomplete", function(file) {
        //     var xhr = new XMLHttpRequest();
        //     xhr.open("POST", "/upload-video", true); // sends a GET request to the same page
        //     xhr.setRequestHeader("Content-Type", "application/json");
        //     const jsonData = {
        //         hash: fileHash
        //     }
        //     xhr.send(JSON.stringify(jsonData));
        // });

        // comment this out when testing hash
        this.on("success", function (file) {
            window.location = "/draft-course-video-list";
        });
    }
};
