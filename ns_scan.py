from requests import get, auth, post
import sys
import argparse
import re
import json
import time

# https://stackoverflow.com/a/7160778
uriRegex = re.compile(
	r'^(?:http|ftp)s?://'  # http:// or https://
	r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
	r'localhost|'  # localhost...
	r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
	r'(?::\d+)?'  # optional port
	r'(?:/?|[/?]\S+)$', re.IGNORECASE)
def parseAndValidateNsApiUrl(uri):
	uri = "https://" + uri
	if not uri.endswith('/'):
		uri += '/'

	sys.stdout.write("[INFO] Validating URI..\n")
	if re.match(uriRegex, uri) is None:
		sys.stderr.write("[ERROR] Netsparker API root endpoint provided was not a valid URI.\n")
		sys.exit(1)

	return uri


def pullScanProfileJsonByName(profileName, url, userId, passwordToken):
	scanProfileEndpoint = url + "scanprofiles/get"
	getScanProfileHeaders = {"Accept": "application/json"}
	getScanProfileAuth = auth.HTTPBasicAuth(userId, passwordToken)
	getScanProfileParams = "name=%s" % profileName

	sys.stdout.write("[API] Pulling Scan Profile..\n")
	getScanProfileResponse = get(url=scanProfileEndpoint, params=getScanProfileParams, headers=getScanProfileHeaders, auth=getScanProfileAuth)
	if getScanProfileResponse.status_code is not 200:
		sys.stderr.write(
			"[ERROR] Retrieval of scan profile by name returned a status code of %s indicating: %s\n"
			% (getScanProfileResponse.status_code, getScanProfileResponse.text))
		sys.exit(1)
	return getScanProfileResponse.text


def checkForWebsiteName(websiteName, url, userId, passwordToken):
	websiteNameEndpoint = url + "websites/get"
	getWebsiteNameHeaders = {"Accept": "application/json"}
	getWebsiteNameAuth = auth.HTTPBasicAuth(userId, passwordToken)
	getWebsiteNameParams = "query=%s" % websiteName

	sys.stdout.write("[API] Checking Website Name..\n")
	getWebsiteNameResponse = get(url=websiteNameEndpoint, params=getWebsiteNameParams, headers=getWebsiteNameHeaders, auth=getWebsiteNameAuth)
	if getWebsiteNameResponse.status_code is not 200:
		sys.stderr.write(
			"[ERROR] Retrieval of website by name returned a status code of %s indicating: %s\n"
			% (getWebsiteNameResponse.status_code, getWebsiteNameResponse.text))
		sys.exit(1)
	rootUrl = json.loads(getWebsiteNameResponse.text)["RootUrl"]
	if rootUrl is None or not rootUrl:
		sys.stderr.write(
			"[ERROR] Retrieval of website Root URL from NS API endpoint %s profile failed.\n" % websiteNameEndpoint)
		sys.exit(1)
	return rootUrl

def postNewScanByProfile(profileName, url, targetUri, userId, passwordToken):
	# /api/1.0/scans/newwithprofile
	# {
	# 	"ProfileName": "string",
	# 	"TargetUri": "string"
	# }
	newScanPostEndpoint = url + "scans/newwithprofile"
	postScanHeaders = {"Accept": "application/json", "Content-Type": "application/json"}
	postScanAuth = auth.HTTPBasicAuth(userId, passwordToken)
	postScanPayload = json.dumps({"ProfileName": profileName, "TargetUri": targetUri})

	sys.stdout.write("[API] Beginning Scan..\n")
	# try:
	postScanResponse = post(url=newScanPostEndpoint, data=postScanPayload, headers=postScanHeaders, auth=postScanAuth, verify=True)
	if postScanResponse.status_code is not 201:
		sys.stderr.write(
			"[ERROR] Creation of scan failed with a status code of %s indicating: %s\n"
			% (postScanResponse.status_code, postScanResponse.text))
		sys.exit(1)
	# except urllib3.exceptions.InsecureRequestWarning as e:
	# 	sys.stdout.write(
	# 		'[WARNING] Using a self signed SSL certificate to connect to %s'
	# 		% targetUri
	# 	)

	scanConfirmationPayload = json.loads(postScanResponse.text)
	scanId = scanConfirmationPayload["Id"]
	initiatedAt = scanConfirmationPayload["InitiatedAt"]
	websiteName = scanConfirmationPayload["WebsiteName"]
	websiteUrl = scanConfirmationPayload["WebsiteUrl"]
	maxDuration = scanConfirmationPayload["MaxScanDuration"]

	sys.stdout.write("[INFO] Scan %s initiated at %s against website %s at %s with a max duration of %s hours.\n"
	                 % (scanId, initiatedAt, websiteName, websiteUrl, maxDuration))
	return scanId

poll=True
def pollRunningScan(scanId, url, userId, passwordToken, pollInterval, sevThreshold):
	# /api/1.0/scans/detail/{id}

	getScanEndpoint = url + "scans/detail/%s" % scanId
	getScanHeaders = {"Accept": "application/json"}
	getScanAuth = auth.HTTPBasicAuth(userId, passwordToken)

	getRunningScanResponse = get(url=getScanEndpoint, headers=getScanHeaders, auth=getScanAuth)
	if getRunningScanResponse.status_code is not 200:
		sys.stderr.write(
			"[ERROR] Retrieval of scan by id returned a status code of %s indicating: %s\n"
			% (getRunningScanResponse.status_code, getRunningScanResponse.text))
		sys.exit(1)
	#Poll scan  /api/1.0/scans/detail/{id}
	getRunningScanPayload = json.loads(getRunningScanResponse.text)
	##WebsiteName #InitiatedAt #WebsiteUrl #Id #FailureReason #FailureReasonDescription #FailureReasonString #IsCompleted #Percentage
	if getRunningScanPayload["IsCompleted"] is True:
		if getRunningScanPayload['FailureReason']:
			sys.stderr.write('[ERROR] Scan finished with errors: %s\n%s\n'
			                 % (getRunningScanPayload['FailureReasonDescription'], getRunningScanPayload['FailureReasonString']))
			return 1
		if getRunningScanPayload['State'] != 'Complete':
			sys.stderr.write('[ERROR] Scan finished with an non-completion state of %s.\n' % getRunningScanPayload['State'])
			return 1

		if handleErrorThresholds(getRunningScanPayload, sevThreshold):
			return 2

		successUrl = url.replace('/api/1.0','') + 'scans/report/' + scanId
		sys.stdout.write('[SUCCESS] Scan finished successfully. View report at %s\n' % successUrl)
		return 0

	#Netsparker will sometimes give erroneous percentages that backtrack from previous polls!
	sys.stdout.write('[API] Scan %s is %s%% complete..\r'
	                 % (scanId, getRunningScanPayload['Percentage']))
	sys.stdout.flush()

	time.sleep(pollInterval)
	return pollRunningScan(scanId, url, userId, passwordToken, pollInterval, sevThreshold)

def handleErrorThresholds(getRunningScanPayload, sevThreshold):
	if sevThreshold is 0 and (getRunningScanPayload['VulnerabilityInfoCount'] > 0
							  or getRunningScanPayload['VulnerabilityLowCount'] > 0
							  or getRunningScanPayload['VulnerabilityMediumCount'] > 0
							  or getRunningScanPayload['VulnerabilityHighCount'] > 0
							  or getRunningScanPayload['VulnerabilityCriticalCount'] > 0):
		sys.stdout.write('[WARNING] Vulnerabilities Detected at level INFO or above')
		return True

	if sevThreshold is 1 and (getRunningScanPayload['VulnerabilityLowCount'] > 0
							  or getRunningScanPayload['VulnerabilityMediumCount'] > 0
							  or getRunningScanPayload['VulnerabilityHighCount'] > 0
							  or getRunningScanPayload['VulnerabilityCriticalCount'] > 0):
		sys.stdout.write('[WARNING] Vulnerabilities Detected at level LOW or above')
		return True

	if sevThreshold is 2 and (getRunningScanPayload['VulnerabilityMediumCount'] > 0
							  or getRunningScanPayload['VulnerabilityHighCount'] > 0
							  or getRunningScanPayload['VulnerabilityCriticalCount'] > 0):
		sys.stdout.write('[WARNING] Vulnerabilities Detected at level MEDIUM or above')
		return True

	if sevThreshold is 3 and (getRunningScanPayload['VulnerabilityHighCount'] > 0
							  or getRunningScanPayload['VulnerabilityCriticalCount'] > 0):
		sys.stdout.write('[WARNING] Vulnerabilities Detected at level HIGH or above')
		return True

	if sevThreshold is 4 and getRunningScanPayload['VulnerabilityCriticalCount'] > 0:
		sys.stdout.write('[WARNING] Vulnerabilities Detected at level CRITICAL')
		return True

	return False

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Start a scan in Netsparker and continuously poll for a success or failure state, subsequently succeed or fail based on a severity threshold.')
	parser.add_argument('--ns-userid', '-u', type=str, required=True,
	                    help='The NS API User ID', dest='userId')
	parser.add_argument('--ns-password', '-p', type=str, required=True,
	                    help='The NS API Password', dest='password')
	parser.add_argument('--ns-uri', '-n', type=str, required=True,
	                    help='The NS API domain/root API endpoint uri.', dest='uri')
	parser.add_argument('--scan-name', '-s', type=str, required=True,
	                    help='The NS Scan profile name to scan the website with.\nCase Sensitive.', dest='profileName')
	parser.add_argument('--website-name', '-w', type=str, required=True,
	                    help='The NS Website name.\nCase Sensitive.', dest='webName')
	parser.add_argument('--poll-interval', '-i', type=float, required=False, default=300,
	                    help='The rate at which to poll the API for scan results, in seconds.', dest='pollInterval')
	parser.add_argument('--severity-threshold', '-t', type=int, required=False, default=3,
	                    help='The severity at which to fail a scan. 0=info, 1=low, 2=med, 3=high, 4=critical', dest='sevThreshold')

	options = parser.parse_args()
	if options.sevThreshold < 0 or options.sevThreshold > 4:
		sys.stderr.write('[ERROR] Invalid severity threshold value.\n')
		parser.print_usage()
		sys.exit(1)

	url = parseAndValidateNsApiUrl(options.uri)
	pullScanProfileJsonByName(options.profileName, url, options.userId, options.password)
	webUri = checkForWebsiteName(options.webName, url, options.userId, options.password)
	scanId = postNewScanByProfile(options.profileName, url, webUri, options.userId, options.password)
	sys.exit(pollRunningScan(scanId, url, options.userId, options.password, options.pollInterval, options.sevThreshold))
