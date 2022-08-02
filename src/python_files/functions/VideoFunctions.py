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

def get_video_thumbnail(videoID:str) -> tuple:
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

    return data #.get("status")

""" End of Get Video Data """


""" Video Upload/Edit """

# ERROR: Currently, the server in charge of this appears to be 
# suffering severe internal server error, which is always fun.
def update_video_thumbnail(videoID:str, thumbnailFilePath:Union[str,Path]):
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

def get_upload_credentials(teacherID:str) -> Optional[dict]:
    """
    {
        'clientPayload': {
            'policy': 'eyJleHBpcmF0aW9uIjoiMjAyMi0wOC0wMlQwODoyMjo0Mi43NTJaIiwiY29uZGl0aW9ucyI6W3siYnVja2V0IjoidmRvLWFwLXNvdXRoZWFzdCJ9LHsia2V5Ijoib3JpZy9jMVIwN2hHSjdyRUo1In0seyJ4LWFtei1jcmVkZW50aWFsIjoiQUtJQUoyUzJMQldLR04zVzMzR1EvMjAyMjA4MDEvYXAtc291dGhlYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1hbGdvcml0aG0iOiJBV1M0LUhNQUMtU0hBMjU2In0seyJ4LWFtei1kYXRlIjoiMjAyMjA4MDFUMDAwMDAwWiJ9LFsic3RhcnRzLXdpdGgiLCIkc3VjY2Vzc19hY3Rpb25fc3RhdHVzIiwiIl0sWyJzdGFydHMtd2l0aCIsIiRzdWNjZXNzX2FjdGlvbl9yZWRpcmVjdCIsIiJdXX0=', 
            'key': 'orig/c1R07hGJ7rEJ5', 
            'x-amz-signature': '1333a36a1f91777ffb88b336aa430a5bcfbe89f32855800dc863a8b9874e3e1f', 
            'x-amz-algorithm': 'AWS4-HMAC-SHA256', 
            'x-amz-date': '20220801T000000Z', 
            'x-amz-credential': 'AKIAJ2S2LBWKGN3W33GQ/20220801/ap-southeast-1/s3/aws4_request', 
            'uploadLink': 'https://vdo-ap-southeast.s3-accelerate.amazonaws.com'
        }, 
        'videoId': 'c64f0cdfff0d4632a610bb53973e6d24'
    }
    """

    courseID = generate_id()
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