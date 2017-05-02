#!/usr/bin/env python

import os
import sys
import time
import json
import hmac
import base64
import docker
import hashlib
import datetime
import requests

#config
try:
	stats_writer = os.environ['DOCKER-STATS-WRITER']
except Exception as e:
	stats_writer = 'oms'

try:
	docker_version = os.environ['DOCKER-VERSION']
except Exception as e:
	docker_version = '1.21'

if(stats_writer == 'oms'):
	try:
		customer_id = os.environ['CUSTOMER-ID']
		shared_key  = os.environ['CUSTOMER-KEY']
	except Exception as e:
		print(e)
		sys.exit(1)
else:
	customer_id = ''
	shared_key  = ''

# The log type is the name of the event that is being submitted


#creating client
docker_url     = 'unix://var/run/docker.sock'
docker_client  = docker.DockerClient(base_url=docker_url, version=docker_version)

old_stats      = {}

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash).encode('utf-8')  
    decoded_key = base64.b64decode(shared_key)
    hmac_str = hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    encoded_hash = base64.b64encode(hmac_str)
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, time_str):
    method   = 'POST'
    resource = '/api/logs'
    log_type = 'dockerstats'
    content_type = 'application/json'
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, time_str, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': time_str
    }

    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code > 299):
        print "Response code: {}".format(response.status_code)

def calculate_cpu_percentage(oldStats, stats):
	cpuPercent       = 0.0
	old_cpu_usage    = 0.0
	old_system_usage = 0.0
	if(oldStats):
		old_cpu_usage    = oldStats['cpu_stats']['cpu_usage']['total_usage']
		old_system_usage = oldStats['cpu_stats']['system_cpu_usage']

	cpuDelta    = stats['cpu_stats']['cpu_usage']['total_usage'] - old_cpu_usage
	systemDelta = stats['cpu_stats']['system_cpu_usage'] - old_system_usage
	if(systemDelta > 0.0 and cpuDelta > 0.0):
		cpuPercent = (cpuDelta * len(stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100.0) / systemDelta
	
	return cpuPercent

def collect_stats():	
	try:
		#get containers
		containers = docker_client.containers.list()

		#cleanup old stats
		container_names = []
		for container in containers:
			container_names.append(container.name)
		for container in old_stats.keys():
			if(container not in container_names):
				del old_stats[container]

		for container in containers:
			inspect_time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
			docker_stats = container.stats(stream=False, decode=True)
			cpuPercent   = 0.0
			if(container.name in old_stats):
				cpuPercent = calculate_cpu_percentage(old_stats[container.name], docker_stats)
				stats_obj = {
					'computer_name': computer_name,
					'container': container.name,
					'cpu_usage': cpuPercent,
					'mem_usage': docker_stats['memory_stats']['usage']
				}
				if(stats_writer == 'oms'):
					post_data(customer_id, shared_key, json.dumps(stats_obj), inspect_time)
				else:
					stats_obj['time'] = inspect_time
					print(stats_obj)
			old_stats[container.name] = docker_stats
	except Exception as e:
		print(e)
		sys.exit(1)

file = open("/etc/hostname", "r")
computer_name = str.strip(file.read())

while True:
	collect_stats()
	time.sleep(60)
