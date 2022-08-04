// For Dropzone
// https://github.com/dropzone/dropzone/blob/main/src/options.js

function getClientPayload() {
    fetch(url).then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }
        return JSON.parse(response.text());
    })
}

Dropzone.autoDiscover = false;
var myDropzone = new Dropzone("#dropper", {
    url: "#",
    maxFilesize: 5120, // MB
    acceptedFiles: 'video/*',
    /*accept: function(file) {
        this.awsOptions = uploadCreds;
        this.options.url = this.awsOptions.uploadLink;
    },*/
    init: function() {
        this.options.url = uploadCredentials['uploadLink'],
        this.url = '#/sdfjsldf'

        this.on("sending", function(file, xhr, formData) {
            uploadCredentials = getClientPayload()
            formData.append("x-amz-credential", uploadCredentials['x-amz-credential']);
            formData.append("x-amz-algorithm", uploadCredentials['x-amz-algorithm']);
            formData.append("x-amz-date ", uploadCredentials['x-amz-date']);
            formData.append("x-amz-signature", uploadCredentials['x-amz-signature']);
            formData.append("key", uploadCredentials['key']);
            formData.append("policy", uploadCredentials['policy']);
            formData.append("success_action_status", 201);
            formData.append("success_action_redirect", "");
        });
        this.on("success", function (file) {
            window.location = uploadCredentials['successUrl'];
        });
    }
}
);

/*
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

*/