from os import environ
from pathlib import Path
from datetime import datetime, timezone
from time import time
from json import loads, dumps
import requests
from inspect import getframeinfo, stack
from re import sub

def get_splunk_token(eventCollectorName: str = 'Logging') -> str:
    """
    Retrieves the Splunk token from Splunk server. 
    Since the token is different for every implementation, it cannot be hardcoded.
    
    Returns:
    - The Splunk token.
    """

    response = requests.get(url = 'https://localhost:8089/services/data/inputs/http', 
                            auth = ('coursefinity', environ.get("EMAIL_PASS")), 
                            params = {'output_mode': 'json'}, 
                            verify = False
                           )
    # print(response.content)

    response = loads(response.content)['entry']

    for respond in response:
        if sub('http://|https://', "", respond['name']) == eventCollectorName:
            token = respond['content']['token']

    return token


def log_event(levelname: str, details: str, userID: str, IP: str, eventCollectorIndex: str = 'main') -> None:
    """Logs an event to the log file.

    Parameters:
    - levelname   'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    - details     Additional notes for log.

    Returns:
    - None
    """

    # Input Validation
    levelname = levelname.upper()
    if levelname not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        raise Exception("Level must be 'DEBUG', 'INFO', 'WARNING', 'ERROR' or 'CRITICAL'.")
    
    logPath = Path(__file__).parent.parent.joinpath('logs')

    # Get line number, module when this function was called, through stacking function frames
    lineNo = getframeinfo(stack()[1][0]).lineno
    module = Path(getframeinfo(stack()[1][0]).filename).stem

    # creates a folder for logs and dc if the folder alrd exists
    logPath.mkdir(parents=True, exist_ok=True)

    # Get date as log name
    utcTime = datetime.now(timezone.utc).astimezone()
    readableDate = utcTime.strftime('%Y-%m-%d')
    readableTime = utcTime.strftime('%H:%M:%S')

    filename = logPath.joinpath(f'{readableDate}.log')

    # Log event to file    
    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableTime} [{levelname}] line {lineNo}, in {module}: {details}\n")
        # userID?

    # Log event to database: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    response = requests.post(url = 'http://127.0.0.1:8088/services/collector/event',

                             headers = {
                                        'Authorization': f"Splunk {get_splunk_token()}",
                                        "X-Splunk-Request-Channel": '8cfb8d79-4d19-4841-a868-18867be0eae6', # Static UUID value
                                        "Content-Type": "application/json",
                                       },

                             data = dumps({'index' : eventCollectorIndex,
                                           'source' : module,
                                           'time'  : time(),
                                           'event' : {'userID'  : userID,
                                                      'IP'      : IP,
                                                      'line'    : lineNo,
                                                      'details' : details
                                                     }
                                          })
                       )
    ackID = loads(response.content)['ackId']

    return ackID
   
if __name__ == '__main__':
    log_event('INFO', 'This is to inform you that this is a debug messge.', None, None)

