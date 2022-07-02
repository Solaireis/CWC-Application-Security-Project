# import python standard libraries
from json import loads, dumps
from requests import get, post
from os import environ
from re import sub
from pathlib import Path
from inspect import stack, getframeinfo
from datetime import datetime, timezone
from time import time

def get_splunk_token(eventCollectorName: str = 'Logging') -> str:
    """
    Retrieves the Splunk token from Splunk server. 
    Since the token is different for every implementation, it cannot be hardcoded.
    
    Returns:
    - The Splunk token.
    """

    response = get(
                    url = 'https://localhost:8089/services/data/inputs/http',
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
        # IP?

    # Log event to Splunk

    data = dumps({'index' : eventCollectorIndex,
                  'source' : module,
                  'time'  : time(),
                  'event' : {'levelName' : levelname,
                             'userID'  : userID,
                             'IP'      : IP,
                             'line'    : lineNo,
                             'details' : details
                            }
                })

    splunk_log(data)

def splunk_log_integrity_check(ackID):

    eventCollectorName = 'CourseFinity Logging'

    # Get event collector token (differs per implementation)
    response = get(url = 'https://localhost:8089/services/data/inputs/http', 
                   auth = ('coursefinity', get("EMAIL_PASS")), 
                   params = {'output_mode': 'json'}, 
                   verify = False
                  )
    # print(response.content)

    response = loads(response.content)['entry']

    for respond in response:
        if sub('http://|https://', "", respond['name']) == eventCollectorName:
            token = respond['content']['token']

    response = post(url = 'http://127.0.0.1:8088/services/collector/ack',

                        params = {
                                  'channel': '8cfb8d79-4d19-4841-a868-18867be0eae6' # Same UUID as in LogExample.py, NormalFunction.py
                                 },

                        headers = {
                                   'Authorization': f'Splunk {token}',
                                   'Content-Type': 'application/x-www-form-urlencoded',
                                  },

                        data = dumps({
                                      'acks' : [ackID]
                                    })
                       )
    return loads(response.content)["acks"][str(ackID)]

def splunk_log(data: str, attempts: int = 5) -> bool:
    # Log event to database: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    
    response = post(url = 'http://127.0.0.1:8088/services/collector/event',

                        headers = {
                                   'Authorization': f"Splunk {get_splunk_token()}",
                                   "X-Splunk-Request-Channel": '8cfb8d79-4d19-4841-a868-18867be0eae6', # Static UUID value
                                   "Content-Type": "application/json",
                                  },

                        data = data
                       )
    # print(data)
    print(response.content)
    ackID = loads(response.content)['ackId']
    
    # Check if the event was logged successfully
    while not splunk_log_integrity_check(ackID):
        attempts -= 1
        if attempts == 0:
            splunk_fail_log()
            temp_splunk_backup(data)
            
            break

def temp_splunk_backup(data):
    # creates a folder for logs and dc if the folder alrd exists
    bakPath = Path(__file__).parent.parent.joinpath('logs')
    bakPath.mkdir(parents=True, exist_ok=True)

    filename = bakPath.joinpath('splunk_backup.bak')
    # print(data)
    
    with open(filename, 'a') as backup:
        backup.write(f"{data}\n")

def splunk_fail_log():
    logPath = Path(__file__).parent.parent.joinpath('logs')

    # Get line number, module when this function was called, through stacking function frames
    lineNo = getframeinfo(stack()[3][0]).lineno
    module = Path(getframeinfo(stack()[3][0]).filename).stem

    # creates a folder for logs and dc if the folder alrd exists
    logPath.mkdir(parents=True, exist_ok=True)

    # Get date as log name
    utcTime = datetime.now(timezone.utc).astimezone()
    readableDate = utcTime.strftime('%Y-%m-%d')
    readableTime = utcTime.strftime('%H:%M:%S')

    filename = logPath.joinpath('splunk_failure.log')

    levelname = 'WARNING'

    # Log event to file    
    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableDate} {readableTime} [{levelname}] line {lineNo}, in {module}: Splunk Server Logging Failure\n")

def splunk_log_retry():

    # creates a folder for logs and dc if the folder alrd exists
    logPath = Path(__file__).parent.parent.joinpath('logs')
    logPath.mkdir(parents=True, exist_ok=True)

    fileName = logPath.joinpath('splunk_backup.bak')
    with open(fileName, 'r+') as backup:
        lines = backup.readlines()

        if lines == []: # No need to query if nothing to query
            return

        data = "".join((line[:-1] for line in lines)) # Tuple faster
        
        response = post(url = 'http://127.0.0.1:8088/services/collector', 
                            headers = {
                                       'Authorization': f'Splunk {get_splunk_token()}',
                                      }, 
                            params = {
                                      'channel': '8cfb8d79-4d19-4841-a868-18867be0eae6' # Same UUID as in LogExample.py, NormalFunction.py
                                     },
                            data = data
                           )

        print(response.content)
        ackID = loads(response.content)['ackId']

        if splunk_log_integrity_check(ackID):
            backup.truncate(0)  # Delete all temporary lines
        