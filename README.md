# VT Search

## Description
A lightweight Python3 tool for fetching VirusTotal Intelligence Search results programmatically.  
This tool wraps the multiple requests needed to fetch anything exceeding 300 results.  
Currently, the tool only fetches sample metadata and does not download the actual samples (to do?).  
Output is written to JSON files in ./output.  

Reference: <https://developers.virustotal.com/reference/intelligence-search>

## Configuration
You will need a VirusTotal Enterprise API key.  
Add this to config.ini before using the script! 

## Example usage

You can provide a query string, using the same syntax as the VirusTotal Intelligence web interface 
(refer [here](https://support.virustotal.com/hc/en-us/articles/360001385897-File-search-modifiers) for search modifiers). 

```
# Find samples with comments by user "tines_bot", last submitted between 2022-04-01 and 2022-04-10
./vt_search.py -q "comment_author:tines_bot ls:2022-04-01T00:00:00+ ls:2022-04-10T00:00:00-"

# Find samples submitted from BR, last submitted between 2022-04-01 and 2022-04-10
./vt_search.py -q "submitter:BR ls:2022-04-01+ ls:2022-04-10-"
```

Or you can directly provide a query URL, e.g. from an unfinished query recorded in the logs:
```
./vt_search.py -u "https://www.virustotal.com/api/v3/intelligence/search?cursor=<cursor>&query=submitter%3ABR+ls%3A2022-04-01%2B+ls%3A2022-04-10-&limit=300&order=last_submission_date+"
```

Check the help for more options:
```
./vt_search.py -h

usage: vt_search.py [-h] [-q QUERY] [-u URL] [-l LIMIT] [-s SORT_ORDER] [-m MAX_REQUESTS] [-r RETRY_DELAY] [-o OUTDIR]
                    [--logpath LOGPATH]

options:
  -h, --help            show this help message and exit
  -q QUERY, --query QUERY
                        Virustotal search query string.
                        Example: "comment_author:thor ls:2022-04-01+ ls:2022-04-10-"
                        For a list of modifiers, see:
                        https://support.virustotal.com/hc/en-us/articles/360001385897-File-search-modifiers
  -u URL, --url URL     Full query URL. Takes precedence over -q option.
                        Allows the user to directly continue unfinished queries that have a cursor parameter.
  -l LIMIT, --limit LIMIT
                        Number of results returned per response (defaults to maximum of 300)
  -s SORT_ORDER, --sort-order SORT_ORDER
                        Order in which results are sorted (defaults to 'last_submission_date+').
                        Use <order>+ and <order>- for ascending and descending order respectively.
                        Allowed orders: ['first_submission_date', 'last_submission_date', 'positives', 'times_submitted', 'size', 'unique_sources']
  -m MAX_REQUESTS, --max-requests MAX_REQUESTS
                        Maximum number of requests to try (defaults to daily API quota of 1000)
  -r RETRY_DELAY, --retry-delay RETRY_DELAY
                        Retry delay in seconds when quota is exceeded (defaults to 43200).
                        Set to less than zero to terminate instead of retrying.
  -o OUTDIR, --outdir OUTDIR
                        Output location (defaults to ./output)
  --logpath LOGPATH     Log location (defaults to ./log/vt-search.log)

```

## Notes
* VirusTotal only returns results within the last 90 days.
* Search tends to terminate early if the date range is too large, e.g. 1 month.
