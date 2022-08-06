if (window.location.hostname !== "coursefinity.social") {
    currentUrl = new URL(window.location.href);
    currentUrl.protocol = "https";
    currentUrl.hostname = "coursefinity.social";
    currentUrl.port = "443";
    window.location.href = currentUrl.href;
}