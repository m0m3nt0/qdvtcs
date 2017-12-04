#!/usr/bin/env python
import preprocessing

redis = {'host': '192.168.0.101',
         'port': 6379}

api = {	'isDebug': True,
		    'bindAddr': '127.0.0.1',
        'bindPort': 5000 }

virusTotal = { 	'ApiKey':'YOUR_VIRUS_TOTAL_API_KEY',
                'ApiUrl':'https://www.virustotal.com/vtapi/v2/file/report',
				        'testHash':'0b5576ad9063a91f95c5eaab70099a32' }
