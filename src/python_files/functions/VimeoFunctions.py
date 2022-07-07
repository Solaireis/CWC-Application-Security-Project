# import third-party libraries
import vimeo
from vimeo.exceptions import VideoUploadFailure
from vimeo.auth import GrantFailed
from requests import JSONDecodeError, get
from flask import request
from typing import Union

# import local python libraries
from python_files.classes.Constants import CONSTANTS

vimeoClient = vimeo.VimeoClient(
    key = CONSTANTS.VIMEO_CLIENT_ID,
    secret = CONSTANTS.VIMEO_CLIENT_SECRET,
    token = CONSTANTS.VIMEO_ACCESS_TOKEN
)


def vimeo_upload(videoFilePath:str, videoName:str, videoDescription:str, thumbnailFilePath:str=None) -> None:
    """
    Uploads a Vimeo video to Vimeo server.
    Free accounts get 10 uploads daily.

    Inputs:
    - videoFilePath (str): Path to video
    - videoName (str): Name of video (stored in SQL)
    - videoDescription: Description of video (stored in SQL)
    - thumbnailFilePath (str): Either course thumbnail, or a submitted video thumbnail?

    Outputs:
    - None

    """
    try:
        videoURI = vimeoClient.upload(videoFilePath, data = {
            'name': videoName,
            'description': videoDescription,
        })

    except VideoUploadFailure as error:
        print(error)
    except GrantFailed as error:    # Free account allows only 10 uploads per day :money_with_wings:
        print(error)

    vimeoClient.patch(videoURI, data={
        'privacy': {'view': 'nobody'},
        })

    vimeoClient.put(videoURI + f"/privacy/domains/{request.headers['Host']}")
    vimeoClient.patch(videoURI, data={
        'privacy': {'embed': 'whitelist'},
        })

    if thumbnailFilePath is not None:
        vimeoClient.upload_picture(videoURI, thumbnailFilePath, activate=True)

    videoID = videoURI.split('/')[-1]
    return videoID

def get_vimeo_video(videoID:str, data:bool=False) -> Union[dict, str, None]:
    """
    Get a Vimeo video iframe
    Inputs:
    videoID (str): videoID of the video iframe to get
    data (bool): If True, returns additional data (e.g. title, description, etc)
    
    Outputs:
    videoData (dict): iframe of corresponding video (if data = True)
    videoData (str): iframe of corresponding video with optional additional data (if data = False)
    
    """
    videoData = get(
        url = 'https://vimeo.com/api/oembed.json',
        params = {
            'url': f"https://vimeo.com/{videoID}",
            'responsive': True,
            'pip': True,
            'playsinline': True,
        }
    )

    try:
        if data:
            return videoData.json()
        else:
            return videoData.json()["html"]
    except JSONDecodeError:
        print("Error, response cannot be recorded. Generally, this is a 404 response, but it may be something else.")
        # TODO: Log response status code if not in 200 range.
        return None
    

if __name__ == "__main__":
    # videoData = vimeo_upload(r"C:\Users\wrenp\Downloads\the_fuck.mp4")
    # videoID = videoData['link'].split('/')[-1]
    # print(videoData)
    # videoData = get_vimeo_video(726279222)
    # print(videoData)
    pass


"""
def authorise_vimeo(redirectUrl:str) -> str:
    vimeo_authorization_url = vimeoClient.auth_url(
        ['private'],           #SCOPES
        redirectUrl,           #REDIRECT_URL
        'Not a JWT'            #STATE
    )

    return vimeo_authorization_url

def get_vimeo_data(code:str) -> tuple:
    try:
        token, user, scope = vimeoClient.exchange_code(code, url_for('userBP.vimeoTesting', _external = True))
        print(token)
        print(user)
        print(scope)
        return token, user, scope
    except GrantFailed as error:
        print(error)
        return None, None, None
"""