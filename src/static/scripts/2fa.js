let secretToken = document.getElementById("secretToken");
secretToken.addEventListener("click", function() {
    navigator.clipboard.writeText(secretToken.innerText);
});

let secretTokenBtn = document.getElementById("secretTokenBtn");
let secretTokenDiv = document.getElementById("secretTokenDiv");
secretTokenBtn.addEventListener("click", function() {
    if (secretTokenDiv.classList.contains("d-none")) {
        secretTokenBtn.innerText = "Hide Setup Key"
        secretTokenDiv.classList.remove("d-none");
    }
    else {
        secretTokenBtn.innerText = "View Setup Key"
        secretTokenDiv.classList.add("d-none");
    }
});