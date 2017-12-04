#!/usr/bin/python

from __future__ import print_function
import datetime
import redis, sys, re, json, urllib, urllib2, logging
from flask import Flask, request, jsonify
import conf as cfg

# Load configurations
apiKey = cfg.virusTotal['ApiKey'];
apiUrl = cfg.virusTotal['ApiUrl'];
defaultTestHash = cfg.virusTotal['testHash'];
redis_db = redis.StrictRedis(host=cfg.redis['host'], port=cfg.redis['port'], db=0)


# Testing connectiviry to the Redis Server
try:
	redis_db.ping()
except Exception as ex:
	exit('Failed to connect to redis, terminating.\r\nErr:%s' % ex)


app = Flask(__name__)
	
@app.route('/<path:path>')
def catch_all(path):
	return returnJsonResponse('{"success": "0", "error":"path not found: %s" }' % path, 404)
	

@app.route("/api/db/clearall")
def clearAllCacheFromRedis():
	try:
		redis_db.flushall()
		return returnJsonResponse('{ "success": "1", "msg":"Redis Cache Clear" }', 200)
	except Exception as ex:
		return returnJsonResponse('{ "success": "0", "msg":"Redis error %s" }' % ex, 400)



@app.route("/api/db/check")
def checkRedisStatus():
	try:
		redis_db.ping()
		return returnJsonResponse('{ "success": "1", "msg":"Redis is up" }', 200)
	except Exception as ex:
		return returnJsonResponse('{ "success": "0", "msg":Redis is down", "err":"%s" }' % ex, 400)



@app.route("/api/db/benchmark/<hash>")
def getRedisBenchmarkResult(hash):
	if not isValidMd5String(hash):
		hash = defaultTestHash
	
	startTime = datetime.datetime.now()
	vtResult = redis_db.get(hash)
	endTime = datetime.datetime.now()
	timeSpan = (endTime - startTime).microseconds
	
	if vtResult is None:
		return returnJsonResponse('{ "hashInRedis":"0", "TimeSpan":%s }' % ( timeSpan ), 200)
	else:
		return returnJsonResponse('{ "hashInRedis":"1", "TimeSpan":%s }' % ( timeSpan ), 200)



@app.route("/api/vt/hash/<hash>")
def getHashResult(hash):
	radisIsUp = True
	if not isValidMd5String(hash):
		#return json.dumps({'success':'0', 'error': 'Invalid MD5 String'})
		return returnJsonResponse('{ "success": "0", "error":Invalid MD5 String" }', 400)
	
	#Check hash in Redis DB
	try:
		vtResult = redis_db.get(hash)
	except:
		vtResult = None
		radisIsUp = False
		
		
	if vtResult is None:
		#get results from VT and update redis
		vtReport = getVirusTotalReport(apiUrl, apiKey, hash)
		#print('vtReport Dump: ' + json.dumps(vtReport), file=sys.stderr)
		
		# get a boolean value if the file is clean or not
		isClean = isHashCleanByVirusTotal(vtReport)
		
		# Update the result in Redis
		radisIsUp = setNewHashInRadis(hash, isClean)
		
		return returnJsonResponse('{"success": "1", "md5":"%s", "isClean":%s, "fromRedis":"0", "radisUp":%r }' % (hash, isClean, radisIsUp), 200)
	else:
		return returnJsonResponse('{"success": "1", "md5":"%s", "isClean":%s, "fromRedis":"1", "radisUp":%r }' % (hash, vtResult,radisIsUp), 200)



@app.route("/api/vt/benchmark/")
def getVirusTotalDefaultBenchmarkResult():
	hash = defaultTestHash
	return getVirusTotalBenchmarkResult(hash)
	


@app.route("/api/vt/benchmark/<hash>")
def getVirusTotalBenchmarkResult(hash):
	if not isValidMd5String(hash):
		hash = defaultTestHash

	startTime = datetime.datetime.now()
	vtReport = getVirusTotalReport(apiUrl, apiKey, hash)
	endTime = datetime.datetime.now()
	timeSpan = (endTime - startTime).microseconds
	return returnJsonResponse('{ "VirusTotalResonseCode": %s, "TimeSpan":%s }' % ( timeSpan, vtReport['response_code'] ), 400)
		
		

# Update the result in Redis
def setNewHashInRadis(hashToInsert, isHashClean):	
	try:
		redis_db.set(hashToInsert, isHashClean)
	except:
		return False
	
	return True


		
# Get VirusTotal Report via request to the API
def getVirusTotalReport(apiUrl, apiKey, md5):
	data = urllib.urlencode({'resource':md5, 'apikey':apiKey, 'allinfo':'0'}  )
	reply = urllib2.urlopen( apiUrl, data )
	return json.loads( reply.read() )

	
# Md5 validation Function
def isValidMd5String(checkval):
	if len(checkval) != 32:
		return 0

	if re.match(r"([A-Fa-f0-9]{32})", checkval) == None:
		return 0

	return 1


#parse VT result and check if clean
def isHashCleanByVirusTotal(it):
	if it['response_code'] == 0:
		return 2
	
	if it['positives'] == 0:
		return 1;
	
	return 0;

	
# Format a JSON respone with the mime type and httpCode	
def returnJsonResponse(jsonDict, httpCode):
	resp = jsonify(jsonDict)
	resp.status_code = httpCode
	resp.mimetype="application/json"
	return resp



if __name__ == '__main__':
    app.run(
		threaded=True,
		debug=cfg.api['isDebug'],
		host=cfg.api['bindAddr'],
		port=cfg.api['bindPort']
	)
