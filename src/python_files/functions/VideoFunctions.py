# import third party libraries
import requests
from flask import request as flaskRequest
from time import time

# import local python files
from .NormalFunctions import generate_id, write_log_entry
from python_files.classes.Constants import SECRET_CONSTANTS

# import python standard libraries
from typing import Union, Optional
from pathlib import Path
from urllib3 import PoolManager
import json

""" Get Video Data """

def get_video(videoID:str) -> Optional[dict]:
    """
    Creates an OTP and playback info for a video.
    Supply to a VdoCipher video player.

    Args:
    - videoID, stored in MySQL video_path (str)

    Returns:
    - {"otp": ..., "playbackInfo": ...} (dict) -> Video Ready
    - {"message": ...} (dict) -> Video not ready
    """
    # Get course data
    data = json.loads(requests.post(
        url=f"https://dev.vdocipher.com/api/videos/{videoID}/otp",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        data=json.dumps({
            "ttl": 300,  # Time to live
            "whitelisthref": flaskRequest.headers["Host"],    # Whitelist sites
        })
    ).text)
    write_log_entry(
        logMessage=f"Deserialisation : Get Video",
        severity="NOTICE"
    )
    # Course cannot be acquired for reasons
    if data.get("message") is not None:
        # E.g. {'message': 'Video not found'}
        write_log_entry(
            logMessage={
                "VdoCipher Video Check Error": data["message"],
                "videoID": videoID
                },
            severity="ERROR"
        )
        print(data.get("message"))
        return None

    return data

def get_video_thumbnail(videoID:str) -> tuple:
    """
    Get thumbnail for a video, for display purposes.

    Args:
    - videoID, stored in MySQL video_path (str)

    Returns:
    - (thumbnailLink, ...) (tuple)
    """
    data = requests.get(
        url=f"https://dev.vdocipher.com/api/meta/{videoID}",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Accept": "application/json"
        }
    )

    if data.get("message") is not None:
    # E.g. {'message': 'Video not found'}
        write_log_entry(
            logMessage={
                "VdoCipher Get Thumbnail Error": data["message"],
                "videoID": videoID
                },
            severity="WARNING"
        )
        print(data.get("message"))
        return None
    return tuple(thumbnail.get("url") for thumbnail in json.loads(data.text).get("posters"))

def check_video(videoID:str) -> Optional[dict]:
    """
    Get data on the video, e.g. thumbnails, status, etc.
    Possible statuses (so far):
    ┌──────────────────┬──────────────────┬───────────────────────────────────────────────────────┐
    │ API Format       │ Webpage Format   │ Notes                                                 │
    ├──────────────────┼──────────────────┼───────────────────────────────────────────────────────┤
    │ PRE-Upload       │ VERIFYING UPLOAD │ Nothing uploaded, but credentials asked for           │
    │ Queued           │ Processing       │ v1                                                    │
    │ Processing       │ Processing       │ v2                                                    │
    │ ready            │ READY            │ Playable                                              │
    │ Encoding error   │ Encoding error   │ gif files (image with frames, but not a proper video) │
    │ Not a media file │ Not a media file │ other files                                           │
    └──────────────────┴──────────────────┴───────────────────────────────────────────────────────┘

    Args:
    - videoID, stored in MySQL video_path (str)

    Returns:
    - data (dict)
    """
    data = json.loads(requests.get(
        url=f"https://dev.vdocipher.com/api/videos/{videoID}",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Accept": "application/json"
        }
    ).text)

    write_log_entry(
        logMessage=f"Deserialisation : Check Video",
        severity="NOTICE"
    )
    if data.get("message") is not None:
    # E.g. {'message': 'Video not found'}
        write_log_entry(
            logMessage={
                "VdoCipher Video Check Error": data["message"],
                "videoID": videoID
                },
            severity="WARNING"
        )
        print(data.get("message"))
        return None
    return data #.get("status")

# Testing
# check_video("68c9b84e24c841498cc772e9760cc659")

def check_video_list(tagName:Optional[str]=None) -> Union[int, tuple, None]:
    """
    Gets a list of videoIDs given a tag, up to 40 at a time.
    Leave empty to get all videos.

    Args:
    - tagName (str)

    Returns:
    - count (int)
    - videoData (dict)
    """
    data = json.loads(requests.get(
        url="https://dev.vdocipher.com/api/videos",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Accept": "application/json"
        },
        params={"tags": tagName}
    ).text)
    write_log_entry(
        logMessage=f"Deserialisation : Video List",
        severity="NOTICE"
    )

    if data["count"] > 0:
        return data["count"], data["rows"]
    else:
        return 0, {} # Empty dictionary

""" End of Get Video Data """

""" Video Upload/Edit """

def update_video_thumbnail(videoID:str, thumbnailFilePath:Union[str,Path]) -> Optional[list]:
    """
    Updates the video thumbnail of a video, given its video ID
    Returns the types of thumbnails created (such as different dimensions)

    Args:
    - videoID, stored in MySQL video_path (str)
    - thumbnailFilePath (str|Path)

    Returns:
    - data, based on dimensions (list)
    [{
        "id": ...,
        "format": ...,
        "video_height": ...,
        "video_width": ...,
        "time": ...,
        "size": ...
    }, {...}, ...]
    """
    filename = Path(thumbnailFilePath).name
    if isinstance(thumbnailFilePath, Path):
        thumbnailFilePath = str(thumbnailFilePath)

    boundary = f"----WebKitFormBoundary{generate_id()}"
    try:
        data = json.loads(requests.post(
            url=f"https://dev.vdocipher.com/api/videos/{videoID}/files",
            headers={
                "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json"
            },
            data=f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: image/webp\r\n\r\n{PoolManager().request('GET', thumbnailFilePath).data.decode('latin-1')}\r\n--{boundary}--",
            timeout=(2, 5)  # If file cannot be processed, server refuses to respond
                            # until 504-Gateway Timeout Error (which takes forever)
        ).text)
        write_log_entry(
            logMessage=f"Deserialisation : Update Video Thumbnail",
            severity="NOTICE"
        )
    except requests.ReadTimeout:
        return None

    if isinstance(data, dict) and data.get("message") is not None:
        # E.g.
        # {"message":"Bad formatting of Authorization header"}
        # {"message":"Internal server error: jtngxq0pptokpbxaa4hgi"}
        write_log_entry(
            logMessage={"VdoCipher Thumbnail Update Error": data["message"]},
            severity="ERROR"
        )
        print(data.get("message"))
        return None

    return data
# print(update_video_thumbnail("c452cdeec4ca45578454849fd0794862", r"https://storage.googleapis.com/coursefinity/course-thumbnails/a7f9a72762b842ad987cb5449a7f6d7e86c08ef1b5d04cfd9a56a8a1313a966d.webp"))

def delete_video(videoIDs:Union[tuple, list, str]) -> int:
    """
    Deletes video(s), given 1 or more video IDs. Returns number of videos deleted.

    Args:
    - videoID (str)
    - videoID (tuple, list)
    - thumbnailFilePath (str, Path)
    Either str, or tuple/list

    Returns:
    - count (int)
    """
    if isinstance(videoIDs, tuple) or isinstance(videoIDs, list):
        videoIDs = ", ".join(videoIDs)

    data = json.loads(requests.delete(
        url="https://dev.vdocipher.com/api/videos",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        params={"videos": videoIDs}
    ).text)
    write_log_entry(
        logMessage=f"Deserialisation : Delete Video",
        severity="NOTICE"
    )
    # {'code': 200, 'message': 'Successfully deleted 0 videos'}
    return data["message"]

def add_video_tag(videoID:str, tagName:str) -> str:
    """
    Adds a set of tags to a video.

    Args:
    - videoID (str)
    - tagName (dict)

    Returns:
    - status (str) E.g. Done
    """

    if not isinstance(tagName, str):
        raise Exception("Tags must be a string!")

    data = json.loads(requests.post(
        url="https://dev.vdocipher.com/api/videos/tags",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        data=json.dumps({
            "videos": [videoID],
            "tags": [tagName]
        })
    ).text)
    write_log_entry(
        logMessage=f"Deserialisation : Add Video Tag",
        severity="NOTICE"
    )

    return data.get("message")

def edit_video_tag(videoID:str, tagName:Optional[str]=None) -> Optional[dict]:
    """
    Replace tags in a video. Leave empty to remove tags.

    Args:
    - videoID (str)
    - tagName (str)

    Returns:
    - status (str) E.g. Done
    """

    if tagName is not None and not isinstance(tagName, str):
        raise Exception("Tag must be a string!")

    data = json.loads(requests.put(
        url="https://dev.vdocipher.com/api/videos/tags",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        data=json.dumps({
            "videos": [videoID],
            "tags": [tagName] if tagName is not None else []
        })
    ).text)
    write_log_entry(
        logMessage=f"Deserialisation : Edit Video Tag",
        severity="NOTICE"
    )

    return data.get("message")

def delete_unuploaded_video() -> None:
    """
    Videos are tagged "PRE-Upload" when 'get_upload_credentials()' is called.
    Tag is removed once upload is complete.

    Function checks for videos with tag "PRE-Upload" (to a maximum of 40), and deletes them.
    """
    count, videos = check_video_list("PRE-Upload")
    if count != 0:
        videoIDs = tuple(row["id"] for row in videos if time() - row["upload_time"] > 86400)
        if videoIDs: # There are videos to be deleted.
            delete_video(videoIDs)

    if count == 40:
        try:
            delete_unuploaded_video()
        except RecursionError:
            # Check userID of most tagged videos?
            write_log_entry(
                logMessage="Extreme amount of unuploaded videos. Please perform manual checking of vdocipher website.",
                severity="WARNING"
            )

""" End of Video Upload/Edit """
