// For Dropzone
// https://github.com/dropzone/dropzone/blob/main/src/options.js

var clientPayload = null;

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