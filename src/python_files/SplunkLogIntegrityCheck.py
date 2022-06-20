from requests import get, post
from json import loads, dumps
from os import environ
from re import sub

def splunk_log_integrity_check(ackID):

    eventCollectorName = 'Logging'

    # Get event collector token (differs per implementation)
    response = get(url = 'https://localhost:8089/services/data/inputs/http', 
                   auth = ('coursefinity', environ.get("EMAIL_PASS")), 
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
    print(loads(response.content)["acks"][str(ackID)])

if __name__ == "__main__":
    splunk_log_integrity_check(5)