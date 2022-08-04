from time import strftime
from requests import get, post, put
from datetime import datetime
from flask import request, url_for
from json import loads, dumps
from typing import Union, Optional
from pathlib import Path
from urllib3 import PoolManager

from .NormalFunctions import generate_id, JWTExpiryProperties
from .SQLFunctions import generate_limited_usage_jwt_token
from python_files.classes.Constants import SECRET_CONSTANTS

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
    # Check if course exists
    videoData = check_video(videoID)
    if videoData is None:
        return None
    elif videoData["status"] != "ready":
        return {"message": videoData["status"]}

    # Get course data
    data = loads(post(
        url = f"https://dev.vdocipher.com/api/videos/{videoID}/otp",
        headers = {
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            'Content-Type': "application/json",
            'Accept': "application/json"
        },
        data = dumps({
        "ttl": 300,  # Time to live
        "whitelisthref": request.headers["Host"],    # Whitelist sites
        })
    )
    .text)

    # Course cannot be acquired for reasons
    if data.get("message") is not None: 
    # E.g. # {'message': 'You have reached the trial limit of 4 videos. Either remove the previously uploaded \n        videos or subscribe to our premium plans to unlock the video limit.'}
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
    data = get(
        url = f"https://dev.vdocipher.com/api/meta/{videoID}",
        headers = {
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            'Accept': "application/json"
        }
    )
    return tuple(thumbnail.get("url") for thumbnail in loads(data.text).get("posters"))

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
    data = loads(get(
        url = f"https://dev.vdocipher.com/api/videos/{videoID}",
        headers = {
            "Authorization": f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            'Accept': "application/json"
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
# check_video("146ad54bd1804f1a9d19ac3f197ba8e2")

""" End of Get Video Data """

""" Video Upload/Edit """
# ERROR: Currently, the server in charge of this appears to be 
# suffering severe internal server error, which is always fun.
def update_video_thumbnail(videoID:str, thumbnailFilePath:Union[str,Path]) -> Optional[dict]:
    """
    Updates the video thumbnail of a video, given its video ID

    Inputs:
    - videoID, stored in MySQL video_path (str)
    - thumbnailFilePath (str|Path)

    Outputs:
    data (dict, probably)
    """
    if isinstance(thumbnailFilePath, Path):
        thumbnailFilePath = str(thumbnailFilePath)

    data = loads(post(
        url = f"https://dev.vdocipher.com/api/videos/{videoID}/files",
        headers = {
            'Authorization': f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}",
            'Content-Type': "multipart/form-data",
            'Accept': "application/json"
        },
        files = {'file': PoolManager().request("GET", thumbnailFilePath).data}
    )
    .text)

    if data.get("message") is not None: 
        """
        E.g. 
        {"message":"Bad formatting of Authorization header"}
        {"message":"Internal server error: jtngxq0pptokpbxaa4hgi"}
        """
        print(data.get("message"))
        #TODO: Log error
        return None

    return data

def get_upload_credentials(courseID:str, teacherID:str) -> Optional[dict]:
    """
    Send a request to VdoCipher to prepare to receive a video.
    Returns the proper credentials to connect with VdoCipher to receive said video.
    Passed to Dropzone as an API call.

    Uses input values derived from a JWT.
    Creates another JWT with videoID, to be passed to server when upload successful (for MySQL).

    Inputs:
    - courseID (str)
    - teacherID (str)

    Outputs (dict):
    {
        'clientPayload': {
            'policy': ... (str),
            'key': ... (str), 
            'x-amz-signature': ... (str), 
            'x-amz-algorithm': ... (str), 
            'x-amz-date': ... (str), 
            'x-amz-credential': ... (str), 
            'uploadLink': ... (str), 
            'successUrl': ... (str)
    }
    """
    data = loads(put(
        url = "https://dev.vdocipher.com/api/videos",
        headers = {
            'Authorization': f"Apisecret {SECRET_CONSTANTS.VDOCIPHER_SECRET}"
        },
        params = {
            "title": f"Course {courseID}", 
            "folderId": "root"
        }
    )
    .text)

    if data.get("message") is not None: # E.g. {'message': 'You have reached the trial limit of 4 videos. Either remove the previously uploaded \n        videos or subscribe to our premium plans to unlock the video limit.'}
        print(data.get("message"))
        #TODO: Log error
        return None
    
    payload = data["clientPayload"]

    expiryInfo = JWTExpiryProperties(activeDuration=300)
    jwtToken = generate_limited_usage_jwt_token(
        payload = {
            "teacherID": teacherID,
            "courseID": courseID,
            "videoPath": data["videoId"],
            "dateCreated":  datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, 
        expiryInfo=expiryInfo,
        limit = 1
    )

    payload["successUrl"] = url_for("teacherBP.uploadSuccess", jwtToken = jwtToken)
    print(payload)

    return payload

""" End of Video Upload/Edit """