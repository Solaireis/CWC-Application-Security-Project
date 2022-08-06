# import third party libraries
import requests
from flask import request as flaskRequest

# import local python files
from .NormalFunctions import generate_id
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

    Inputs:
    - videoID, stored in MySQL video_path (str)

    Outputs:
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
    )
    .text)
    print(data)

    # Course cannot be acquired for reasons
    if data.get("message") is not None:
    # E.g. # {'message': 'You have reached the trial limit of 4 videos. Either remove the previously uploaded
    # videos or subscribe to our premium plans to unlock the video limit.'}
        print(data.get("message"))
        #TODO: Log error
        return None

    return data

# Currently not in use due to ability to set video thumbnails not existing.
def get_video_thumbnail(videoID:str) -> tuple:
    """
    Get thumbnail for a video, for display purposes.

    Inputs:
    - videoID, stored in MySQL video_path (str)

    Outputs:
    - (thumbnailLink, ...) (tuple)
    """
    data = requests.get(
        url=f"https://dev.vdocipher.com/api/meta/{videoID}",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Accept": "application/json"
        }
    )
    return tuple(thumbnail.get("url") for thumbnail in json.loads(data.text).get("posters"))

def check_video(videoID:str) -> Optional[dict]:
    """
    Get data on the video, e.g. thumbnails, status, etc.
    Possible statuses:
    - PRE-Upload (VERIFYING UPLOAD)
    - Queued (Processing)
    - Ready (READY)
    - Encoding error (Encoding error) -> gif files (image with frames, but not a proper video)
    - Not a media file (Not a media file) -> other files

    Inputs:
    - videoID, stored in MySQL video_path (str)

    Outputs:
    - data (dict)
    """
    data = json.loads(requests.get(
        url=f"https://dev.vdocipher.com/api/videos/{videoID}",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Accept": "application/json"
        }
    )
    .text)
    if data.get("message") is not None:
    # E.g. {'message': 'Video not found'}
        print(data.get("message"))
        #TODO: Log error
        return None
    print(data)
    return data #.get("status")

# Testing
# check_video("68c9b84e24c841498cc772e9760cc659")

""" End of Get Video Data """

""" Video Upload/Edit """

def update_video_thumbnail(videoID:str, thumbnailFilePath:Union[str,Path]) -> Optional[list]:
    """
    Updates the video thumbnail of a video, given its video ID
    Returns the types of thumbnails created (such as different dimensions)

    Inputs:
    - videoID, stored in MySQL video_path (str)
    - thumbnailFilePath (str|Path)

    Outputs:
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
            timeout=(2, 5) # If file cannot be processed, server refuses to respond
                             # until 504-Gateway Timeout Error (which takes forever)
        )
        .text)
    except requests.ReadTimeout:
        return None

    if isinstance(data, dict) and data.get("message") is not None:
        """
        E.g.
        {"message":"Bad formatting of Authorization header"}
        {"message":"Internal server error: jtngxq0pptokpbxaa4hgi"}
        """
        print(data.get("message"))
        #TODO: Log error
        return None

    return data
# print(update_video_thumbnail("c452cdeec4ca45578454849fd0794862", r"https://storage.googleapis.com/coursefinity/course-thumbnails/a7f9a72762b842ad987cb5449a7f6d7e86c08ef1b5d04cfd9a56a8a1313a966d.webp"))

def delete_video(videoIDs:Union[tuple, str]) -> Optional[dict]:
    """
    {'code': 200, 'message': 'Successfully deleted <num> videos'}
    """
    if isinstance(videoIDs, tuple):
        videoIDs = ", ".join(videoIDs)

    data = json.loads(requests.delete(
        url="https://dev.vdocipher.com/api/videos",
        headers={
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        params={
            "videos": videoIDs
        }
    )
    .text)
    print(videoIDs)
    print(data)

""" End of Video Upload/Edit """