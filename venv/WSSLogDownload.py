import argparse
import configparser
import datetime
import glob
import gzip
import io
import logging
import logging.handlers
import os
import re
import shutil
import socket
import sys
import zipfile
from datetime import date
from zipfile import BadZipFile

import requests
from dateutil.relativedelta import relativedelta

#########################################################################################
# Define and parse config file.
#########################################################################################
cfile = "./Include/WSSLogDownload.conf"
config = configparser.ConfigParser()
config.read(cfile)

#########################################################################################
# Read timeframe argument, init start and end stamps, and calculate start time.
#########################################################################################
parser = argparse.ArgumentParser()
parser.add_argument("time", help="Values: prev-hour, prev-day, prev-week, prev-month")
args = parser.parse_args()
sTime = 0
eTime = 0
eDateTime = datetime.datetime.now()
sDateTime = eDateTime
eTime = int(eDateTime.timestamp())
sDateTime = sDateTime.replace(minute=0)
sDateTime = sDateTime.replace(second=0)
if args.time == "prev-hour" or args.time == "":
    sTime = int(sDateTime.timestamp())
elif args.time == "prev-month":
    sDateTime = sDateTime - relativedelta(months=1)
    sTime = int(sDateTime.timestamp())
elif args.time == "prev-week":
    sDateTime = sDateTime - relativedelta(days=7)
    sTime = int(sDateTime.timestamp())
elif args.time == "prev-day":
    sDateTime = sDateTime - relativedelta(days=1)
    sTime = int(sDateTime.timestamp())
#########################################################################################
# Add 3 zeros for epoch milliseconds.
#########################################################################################
sTime = sTime * 1000
eTime = eTime * 1000

#########################################################################################
# Setup logger for syslog support.
#########################################################################################
my_logger = logging.getLogger('MyLogger')
logging.raiseExceptions = False
my_logger.setLevel(logging.INFO)
sock_type = socket.SOCK_STREAM if str.lower(config['system']['syslog_protocol']) == "tcp" else socket.SOCK_DGRAM
handler = logging.handlers.SysLogHandler(address = (config['system']['syslog_server'],int(config['system']['syslog_port'])), socktype=sock_type)
my_logger.addHandler(handler) if config['system']['syslog'] else False

#########################################################################################
# Init status, ensure user and pass are in config.
#########################################################################################
status = ""
if config['portal']['username'] and config['portal']['password']:
    while status != "done":
        #########################################################################################
        # If a token exists in config, tack in onto url.
        #########################################################################################
        if config['tracking']['token']:
            url = "https://portal.threatpulse.com/reportpod/logs/sync?startDate=" + str(sTime) + "&endDate=0&token=" \
                  + config['tracking']['token']
        else:
            #########################################################################################
            # Otherwise define url without token.
            #########################################################################################
            url = "https://portal.threatpulse.com/reportpod/logs/sync?startDate=" + str(sTime) + "&endDate=0&token=none"
        print("URL: " + url) if config['system']['debug'] else False
        #########################################################################################
        # Add auth headers.
        #########################################################################################
        headers = {'X-APIUsername':config['portal']['username'], 'X-APIPassword':config['portal']['password']}
        #########################################################################################
        # Check for proxy config, add proxy dictionary and disable cert checking if so.
        #########################################################################################
        if config['proxy']['enableproxy'] != "0":
            proxies = {
                "https": config['proxy']['proxyaddress'] + ":" + config['proxy']['proxyport'],
            }
            r = requests.get(url, headers=headers, proxies=proxies, stream=True, verify=False)
        #########################################################################################
        # If no proxy in config, leave cert checking enabled.
        #########################################################################################
        else:
            r = requests.get(url, headers=headers, stream=True)
        print("Headers: " + str(r.headers)) if config['system']['debug'] else False
        print("Status Code: " + str(r.status_code)) if config['system']['debug'] else False
        #########################################################################################
        # If response from WSS is good (200), start processing returned data.
        #########################################################################################
        if r.status_code == 200:
            m = re.search('attachment; filename="(.*)"', r.headers['Content-Disposition'])
            fName = 'LogTemp/' + m.group(1)
            with open(fName,'wb+') as f:
                for chunk in r.iter_content(chunk_size=102400000):
                    if chunk:
                        tempStr = str(chunk)
                        m = re.search('X-sync-token: (.*)\\\\r\\\\nX-sync-status: (.*)\\\\r\\\\n\'',tempStr)
                        f.write(chunk)
                        if m:
                            config.set('tracking','token', m.group(1))
                            status = m.group(2)
                            print("Token:" + m.group(1)) if config['system']['debug'] else False
                            print("Status:" + m.group(2)) if config['system']['debug'] else False
            try:
                with zipfile.ZipFile(fName, "r") as z:
                    z.extractall(config['system']['archivelogdir'])
                    if int(config['system']['syslog']) > 0 or str.lower(config['system']['syslog']) == "yes":
                        z.extractall(config['system']['templogdir'])
                        for filename in os.listdir(config['system']['templogdir']):
                            #print("Filename:" + filename) if config['system']['debug'] else False
                            if filename.endswith(".gz"):
                                tfile = config['system']['templogdir'] + "/" + filename
                                with gzip.open(tfile, 'r') as f:
                                    for line in f:
                                        my_logger.info(line)
            except BadZipFile:
                print("Was a bad zip file") if config['system']['debug'] else False
            files = glob.glob(os.path.join(config['system']['templogdir'], "*"))
            for f in files:
                os.remove(f)
        #########################################################################################
        # If response from WSS is wait (429), chill for a bit then proceed.
        #########################################################################################
        elif r.status_code == 429:
            #########################################################################################
            # Need to stub in rest of code for sleeping
            #########################################################################################
            print("Need to sleep for a bit, super tired.")


#if status == "done":
#    config['tracking']['token'] = ''
#    with open(cfile, 'w') as cf:
#        config.write(cf)

my_logger.info('WSS Log Download Complete!')
