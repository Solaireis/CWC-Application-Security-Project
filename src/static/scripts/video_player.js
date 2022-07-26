var player = videojs('video-player', {
    playbackRates: [0.5, 1, 1.5, 2],
    aspectRatio: "16:9",
    fluid: true,          //The video player
    responsive: true,     //The video controls
    autoplay: true,       //Or attempts to
    controls: true,
    preload: "auto",
  });

function add_source(videoPath) {
    player.ready(function() {
        player.src({
        type: 'application/dash+xml',
        //type: 'application/x-mpegurl',
        //type: 'application/vnd.apple.mpegurl',
        src: videoPath
        //src: 'https://bitdash-a.akamaihd.net/content/MI201109210084_1/m3u8s-fmp4/f08e80da-bf1d-4e3d-8899-f0f6155f6efa.m3u8'
        //src: 'https://storage.googleapis.com/shaka-demo-assets/angel-one/dash.mpd'
        });
    });
};