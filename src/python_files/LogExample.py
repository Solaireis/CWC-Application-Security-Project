from pathlib import Path
from datetime import datetime, timezone
from json import dumps
import requests
from inspect import getframeinfo, stack

def log_event(levelname, message):
    """Logs an event to the log file.

    Parameters:
    - levelname   'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
    - message     Additional notes for log.

    Returns:
    - None
    """
    
    logPath = Path(__file__).parent.parent.joinpath('databases', 'logs')

    # Get line number, module when this function was called, through stacking function frames
    lineNo = getframeinfo(stack()[1][0]).lineno
    module = Path(getframeinfo(stack()[1][0]).filename).stem

    # creates a folder for logs and dc if the folder alrd exists
    logPath.mkdir(parents=True, exist_ok=True)

    # Get date as log name
    time = datetime.now(timezone.utc).astimezone()
    readableDate = time.strftime('%Y-%m-%d')
    readableTime = time.strftime('%H:%M:%S')

    filename = logPath.joinpath(f'{readableDate}.log')


    # Log event to file    
    levelname = levelname.upper()
    if levelname not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        raise Exception("Level must be 'DEBUG', 'INFO', 'WARNING', 'ERROR' or 'CRITICAL'.")

    with open(filename, 'a') as log:
        # Based on logging module format
        log.write(f"{readableTime} [{levelname}] line {lineNo}, in {module}: {message}\n")

    # Log event to database
    data = dumps({'asctime' : readableTime,
                'levelname' : levelname,
                'module' : module,
                'message' : message})

if __name__ == '__main__':
    log_event('WARNING', 'This is a warning.')

