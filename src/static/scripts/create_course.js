// Dropzone.js for segmenting data payload to chunks of data
Dropzone.options.courseThumbnail = {
    maxFiles: 1,
    paramName: 'courseThumbnail',
    acceptedFiles: ".jpeg,.jpg,.png",
    chunking: true,
    forceChunking: true,
    url: '/create_course/{{ teacherUID }}',
    maxFilesize: 50, // megabytes
    chunkSize: 1000000, // bytes
    retryChunks: true,
    retryChunksLimit: 3,
    autoProcessQueue: false,
    init: function() {
        let myDropzone = this;
        
        myDropzone.on("addedfile", function() {
            document.querySelector(".dz-progress").classList.add("d-none");
            if (myDropzone.files[1] == null) return;
            myDropzone.removeFile(myDropzone.files[0]);
        });

        document.getElementById('submit-button').addEventListener("click", function (e) {
            e.preventDefault();
            myDropzone.processQueue();
        });

        myDropzone.on("success", function () {
            function redirectUser() {
                location.reload();
            }
            setInterval(redirectUser, 1500);
        });

        myDropzone.on('sending', function(file, xhr, formData) {
            /* Append inputs to FormData */
            document.querySelector(".dz-progress").classList.remove("d-none");
            formData.append("courseThumbnail", document.getElementById('courseThumbnail').value);
        });
    }
};

function readURL(input) {
    if (input.files && input.files[0]) {
        var reader = new FileReader();

        reader.onload = function (e) {
            document.getElementById("thumbnail").setAttribute("src", e.target.result);
        };

        reader.readAsDataURL(input.files[0]);
    }
}