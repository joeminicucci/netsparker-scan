# Netsparker Scanner
This script is meant to be used to fire a Netsparker scan and periodically poll its progress. 
When completed, it reports back to the user depending on a defined severity threshold.
If the script fails due to severity threshold, it will return an error code of 2, otherwise it will return 1 for general failures. 
The script operates under the following assumptions:
  - A website object  has already been created for the target CI server.
  - A scan profile has already been created for the target website object.
  - The user has an API UserID and Password.
  
```
usage: ns_scan.py [-h] --ns-userid USERID --ns-password PASSWORD --ns-uri URI
                  --scan-name PROFILENAME --website-name WEBNAME
                  [--poll-interval POLLINTERVAL]
                  [--severity-threshold SEVTHRESHOLD]
```
```
Start a scan in Netsparker and continuously poll for a success or failure
state, subsequently succeed or fail based on a severity threshold.

  -h, --help            show this help message and exit
  --ns-userid USERID, -u USERID
                        The NS API User ID
  --ns-password PASSWORD, -p PASSWORD
                        The NS API Password
  --ns-uri URI, -n URI  The NS API domain/root API endpoint uri.
  --scan-name PROFILENAME, -s PROFILENAME
                        The NS Scan profile name to scan the website with.
                        Case Sensitive.
  --website-name WEBNAME, -w WEBNAME
                        The NS Website name. Case Sensitive.
(OPTIONAL)  --poll-interval POLLINTERVAL, -i POLLINTERVAL
                        The rate at which to poll the API for scan results, in
                        seconds.
(OPTIONAL)  --severity-threshold SEVTHRESHOLD, -t SEVTHRESHOLD
                        The severity at which to fail a scan. 0=info, 1=low,
                        2=med, 3=high, 4=critical
```
## Example 1
**Firing a basic scan**:
`ns_scan.py -u 82gf84hs949fhse934shef9w349hefsh -p SAIxI93Xkwos90whXoqjrt+923uH= -n netsparkercloud.com/api/1.0 -s Profile1 -w Website1`
## Example 2
**Setting a custom Poll Interval**
```ns_scan.py -u 82gf84hs949fhse934shef9w349hefsh -p SAIxI93Xkwos90whXoqjrt+923uH= -n netsparkercloud.com/api/1.0 -s Profile1 -w Website1 -i 7 -t 2```
