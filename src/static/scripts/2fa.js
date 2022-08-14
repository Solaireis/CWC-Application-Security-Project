let secretToken = document.getElementById("secretToken");
secretToken.addEventListener("click", function() {
    navigator.clipboard.writeText(secretToken.innerText);
});