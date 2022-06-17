#!/usr/bin/env python

import argparse
import configparser
import requests
import time
import json
import logging
from datetime import datetime
from os import path, makedirs
from urllib.parse import quote_plus


# Defaults
SCRIPT_HOME = path.dirname(path.abspath( __file__ ))
CONFIG_FILEPATH = path.join(SCRIPT_HOME, "config.ini")
VTI_URL = "https://www.virustotal.com/api/v3/intelligence/search"

DEFAULT_LIMIT        = 300
DEFAULT_MAX_REQUESTS = 1000
DEFAULT_RETRY_DELAY  = 12*3600

DEFAULT_SORT_ORDER   = "last_submission_date+"
DEFAULT_OUTPUT       = "output"
DEFAULT_LOG          = "log/vt-search.log"
DEFAULT_OUTPUT_DIR   = path.join(SCRIPT_HOME, DEFAULT_OUTPUT)
DEFAULT_LOGPATH      = path.join(SCRIPT_HOME, DEFAULT_LOG)


class Query:

    def __init__(self, query_url, apikey, max_requests=DEFAULT_MAX_REQUESTS, retry_delay=DEFAULT_RETRY_DELAY, outdir=None, logpath=None):
        
        self.url = query_url
        self.headers = {'x-apikey' : apikey}
        self.max_requests = max_requests
        self.retry_delay = retry_delay 
        self.tries = 0
        
        # Set up output directory
        self.outdir = outdir if outdir else DEFAULT_OUTPUT_DIR
        makedirs(self.outdir, exist_ok=True)
        
        # Set up logger
        self.logpath = logpath if logpath else DEFAULT_LOGPATH
        makedirs(path.dirname(self.logpath), exist_ok=True)
        logging.basicConfig(level=logging.INFO, format='[%(levelname)5s] %(message)s',
                            handlers=[logging.FileHandler(self.logpath), logging.StreamHandler()])
        self.logger=logging.getLogger()
        
    def write_results(self, json_results):
        name = datetime.now().strftime("%Y-%m-%d_%H:%M:%S.%f")
        fpath = path.join(self.outdir, name + ".json")
        
        with open(fpath, 'w') as outfile:
            json.dump(json_results.get("data", []), outfile)
        
        self.logger.info("Wrote file {} with {} entries".format(fpath, len(json_results.get("data", []))))
        
    def fetch_results(self):
        
        self.logger.info("================================================")
        self.logger.info("Start query at: {}".format(datetime.now().strftime("%Y-%m-%d_%H:%M:%S")))
        self.logger.info("Query url: {}".format(self.url))
        
        j = {}
        while self.url is not None and self.tries < self.max_requests:            
            try:
                # Make request
                self.tries += 1
                r = requests.get(self.url, headers=self.headers)
                j = r.json()
                
                # Log total hits
                if self.tries == 1:
                    self.logger.info("Total_hits: {}".format(j.get("meta", {}).get("total_hits")))
                
                # Write output
                assert(j.get("data"))
                self.write_results(j)
                
                # Update next url
                self.url = j.get("links", {}).get("next")
                self.logger.info("Next url: {}".format(self.url))
            
            except Exception as e:
                if j.get("error"):
                    error = j.get("error")
                    self.logger.error("Received an error: {}".format(error) )
                    if error.get("message", "") == "Quota exceeded" and self.retry_delay >= 0:
                        # Reset tries and try again later
                        self.tries = 0
                        time.sleep(self.retry_delay)
                    else:
                        break
                else:
                    last_response = str(j)[:400] if j else "None"
                    self.logger.error("Hit an exception: {} Last response: {} Next url: {}".format(e, last_response, self.url))
                    break

def main():
    
    # Parse arguments
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-q", "--query", type=str,
                        help="Virustotal search query string.\n" \
                             "Example: \"comment_author:thor ls:2022-04-01+ ls:2022-04-10-\"\n"\
                             "For a list of modifiers, see:\n"\
                             "https://support.virustotal.com/hc/en-us/articles/360001385897-File-search-modifiers")
    parser.add_argument("-u", "--url", type=str,
                        help="Full query URL. Takes precedence over -q option.\n" \
                             "Allows the user to directly continue unfinished queries that have a cursor parameter.")   
    parser.add_argument("-l", "--limit", type=int, default=DEFAULT_LIMIT,
                        help="Number of results returned per response (defaults to maximum of {})".format(DEFAULT_LIMIT))
    parser.add_argument("-s", "--sort-order", type=str, default=DEFAULT_SORT_ORDER,
                        help="Order in which results are sorted (defaults to '{}').\n"\
                             "Use <order>+ and <order>- for ascending and descending order respectively.\n" \
                             "Allowed orders: ['first_submission_date', 'last_submission_date', " \
                             "'positives', 'times_submitted', 'size', 'unique_sources']".format(DEFAULT_SORT_ORDER))
    parser.add_argument("-m", "--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                        help="Maximum number of requests to try (defaults to daily API quota of {})".format(DEFAULT_MAX_REQUESTS))
    parser.add_argument("-r", "--retry-delay", type=int, default=DEFAULT_RETRY_DELAY,
                        help="Retry delay in seconds when quota is exceeded (defaults to {}).\n" \
                             "Set to less than zero to terminate instead of retrying. ".format(DEFAULT_RETRY_DELAY))
    parser.add_argument("-o", "--outdir", type=str, default=DEFAULT_OUTPUT_DIR,
                        help="Output location (defaults to ./{})".format(DEFAULT_OUTPUT))
    parser.add_argument("--logpath", type=str, default=DEFAULT_LOGPATH,
                        help="Log location (defaults to ./{})".format(DEFAULT_LOG))
    args = parser.parse_args()
    
    # Read config.ini
    config = configparser.ConfigParser()
    try:
        config.read(CONFIG_FILEPATH)
    except:
        print("Cannot read config from {}!".format(CONFIG_FILEPATH))
        return
        
    vt_apikey = config.get("VTI", "apikey", fallback=None)
    if vt_apikey is None: 
        print("{}:\nPlease fill in 'apikey' with a Virustotal Enterprise apikey.".format(CONFIG_FILEPATH))
        return
    
    # Formulate query url
    if args.url:
        if args.url.startswith(VTI_URL):
            query_url = args.url
        else:
            print("Invalid URL: {}".format(args.url))
            return
    else:
        query_url = "{}?query={}&limit={}&order={}".format(VTI_URL, quote_plus(args.query), args.limit, args.sort_order)
    
    # Submit query and collect results
    q = Query(query_url, vt_apikey, max_requests=args.max_requests, retry_delay=args.retry_delay, outdir=args.outdir, logpath=args.logpath)
    q.fetch_results()
    

if __name__ == "__main__":
    main()
