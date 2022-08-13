// For Dropzone
// https://github.com/dropzone/dropzone/blob/main/src/options.js

var clientPayload = null;
// function getClientPayload() {
//     console.log("Getting payload")
    // fetch(document.getElementById("dropzone-client").innerText).then((response) => {
    //     if (!response.ok) {
    //         throw new Error(`HTTP error: ${response.status}`);
    //     }
    //     clientPayload = response.json();
    //     console.log("Payload acquired");
    //     console.log(JSON.parse(clientPayload));
    //     return response.json().uploadLink;
// })};

function getClientPayload() {
    console.log("Getting payload")
    fetch(document.getElementById("dropzone-client").innerHTML)
    .then((response) => response.json())
    .then((uploadCreds) => {
        clientPayload = uploadCreds;
        myDropzone.options.url = clientPayload.uploadLink;
        console.log("Payload acquired");
        console.log(clientPayload);
        myDropzone.processQueue();
    });
};

Dropzone.autoDiscover = false;
var myDropzone = new Dropzone("#dropper", {
    url: "#",
    maxFilesize: 5120, // MB
    acceptedFiles: 'video/*',
    autoProcessQueue: false,
    // accept: function(file) {
    //     console.log("File Accepted");
    //     this.options.url = getClientPayload();
    //     console.log(this.options.url);
    // },
    init: function() {
        console.log("Initialising");
        this.url = '#/sdfjsldf';

        this.on("addedfile", async function() {
            console.log("File Accepted");
            if (clientPayload == null) {
                getClientPayload();
                myDropzone.processQueue();
            }
            else {
                console.log("Payload exists");
                myDropzone.processQueue();
            }
            console.log(this.options.url);
        });

        this.on("sending", async function(file, xhr, formData) {
            while (clientPayload == null) {
                console.log("Waiting");
                await new Promise(r => setTimeout(r, 500));
            };
            console.log("Sending");
            console.log(clientPayload);
            formData.append("x-amz-credential", clientPayload['x-amz-credential']);
            formData.append("x-amz-algorithm", clientPayload['x-amz-algorithm']);
            formData.append("x-amz-date ", clientPayload['x-amz-date']);
            formData.append("x-amz-signature", clientPayload['x-amz-signature']);
            formData.append("key", clientPayload.key);
            formData.append("policy", clientPayload.policy);
            formData.append("success_action_status", 201);
            formData.append("success_action_redirect", "");
        });

        this.on("success", function (file) {
            window.location = clientPayload['successUrl'];
        });
    }
});


// function getClientPayload() {
//     fetch(document.getElementById("dropzone-client").innerHTML)
//     .then((response) => {
//         if (!response.ok) {
//             throw new Error(`HTTP error: ${response.status}`);
//         }
//         console.log(response.text())
//         return JSON.parse(response.text());
// })};

// var clientPayload = null
// Dropzone.autoDiscover = false;
// var myDropzone = new Dropzone("#dropper", {
//     url: "#",
//     maxFilesize: 5120, // MB
//     acceptedFiles: 'video/*',

//     accept: function(file, done) {
//         fetch(document.getElementById("dropzone-client").innerHTML)
//         .then((response) => response.json())
//         .then((uploadCreds) => {
//             console.log("Hello")
//             this.awsOptions = uploadCreds;
//             this.options.url = this.awsOptions.uploadLink;
//             clientPayload = uploadCreds
//             console.log(uploadCreds)
//         });
//     },
//         // await clientPayload({}, () => {
//         //     console.log(uploadCreds)
//             // this.awsOptions = uploadCreds;
//             // console.log("Hello")
//             // this.options.url = this.awsOptions.uploadLink;
//             // done();
//         // })
//     // },

//     init: function() {

//         this.url = "#/sdfjsldf";
//         // this.options.url = clientPayload.uploadLink;
//         // while (clientPayload == null) {
//         //     console.log(clientPayload)
//         //     await new Promise(r => setTimeout(r, 1000));
//         //   };

//         // this.on("addedfile", function() {
//         //     fetch(document.getElementById("dropzone-client").innerHTML)
//         //         .then(function (response) {
//         //             return response.json();
//         //         }).then(function (text) {
//         //             clientPayload = text;
//         //     });
//         // });

//         this.on("sending", function(file, xhr, formData) {
//             // clientPayload = getClientPayload()
//             // console.log(getClientPayload())
//             // while (clientPayload == null) {
//             //     console.log(clientPayload);
//             //     await new Promise(r => setTimeout(r, 5000));
//             // }
//             formData.append("x-amz-credential", clientPayload.x-amz-credential);
//             formData.append("x-amz-algorithm", clientPayload.x-amz-algorithm);
//             formData.append("x-amz-date ", clientPayload.x-amz-date);
//             formData.append("x-amz-signature", clientPayload.x-amz-signature);
//             formData.append("key", clientPayload.key);
//             formData.append("policy", clientPayload.policy);
//             formData.append("success_action_status", 201);
//             formData.append("success_action_redirect", "");
//             console.log(formData);
//         });

//         this.on("success", function (file) {
//             window.location = clientPayload.successUrl;
//         });
//     }
// });

// // function clientPayload(payloadUrl) {
// //     fetch(payloadUrl)
// //         .then(function (response) {
// //             return response.json();
// //         }).then(function (text) {
// //             window.alert(text);
// //             return text, text.uploadLink;
// //             //document.write(JSON.stringify(this.awsOptions));
// //             // this.options.url = this.awsOptions.uploadLink;
// //         });
// // }


// // Dropzone.options.dropper = {
// //     url: "/upload-video", // Determines where to reroute after submission
// //     chunking: true, // Enable chunking
// //     forceChunking: true, // Force chunking to happen
// //     chunkSize: 50000000, // Size of each chunk in bytes (Need to clarify this, default:50mb)
// //     retryChunks: true, // Retry chunk uploads
// //     retryChunksLimit: 3, // Number of times to retry chunk uploads (third times the charm)
// //     maxFilesize: 500, // Maximum size of each file in MB (current: 500mb)
// //     paramName: "videoUpload", // The name of the uploaded file
// //     maxFiles: 1, // Number of files allowed to be uploaded
// //     acceptedFiles: ".mp4, .mov, .wmv, .avi, .webm", //allowed file extensions (clarify with waffles)
// //     addRemoveLinks: true, // ability to remove
// //     autoProcessQueue: true, // whether to automatically process the queue after adding a file (set to false jic)
// //     init: function() {
// //         // var fileHash;
// //         // HASH IS CORRECT :D, now need send across
// //         this.on("addedfile", function(file) {
// //             var reader = new FileReader();
// //             var xhr = new XMLHttpRequest();
// //             reader.onload = function(event) {
// //                 var hash = CryptoJS.SHA512(CryptoJS.lib.WordArray.create(event.target.result));
// //                 const fileHash = hash.toString(CryptoJS.enc.Hex);
// //                 xhr.open("POST", "", true); // sends a GET request to the same page
// //                 xhr.setRequestHeader("Content-Type", "application/json");
// //                 const jsonData = {
// //                     hash: fileHash
// //                 }
// //                 xhr.send(JSON.stringify(jsonData));
// //             };
// //             reader.readAsArrayBuffer(file);
// //         });

// //         this.on("removedfile", function(file) {
// //             console.log("File " + file.name + " removed");
// //         });
        

//         // Testing something
//         // this.on("queuecomplete", function(file) {
//         //     var xhr = new XMLHttpRequest();
//         //     xhr.open("POST", "/upload-video", true); // sends a GET request to the same page
//         //     xhr.setRequestHeader("Content-Type", "application/json");
//         //     const jsonData = {
//         //         hash: fileHash
//         //     }
//         //     xhr.send(JSON.stringify(jsonData));
//         // });

//         // comment this out when testing hash
// //         this.on("success", function (file) {
// //             window.location = "/draft-course-video-list";
// //         });
// //     }
// // };