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
	stats_writer = os.environ['DOCKER_STATS_WRITER']
except Exception as e:
	stats_writer = 'loggly'

try:
	docker_version = os.environ['DOCKER_VERSION']
except Exception as e:
	docker_version = '1.21'

try:
	installation_id = os.environ['INSTALLATION_ID']
except Exception as e:
	installation_id = 'installation-id'

# The log type is the name of the event that is being submitted


#creating client
docker_url     = 'unix://var/run/docker.sock'
docker_client  = docker.DockerClient(base_url=docker_url, version=docker_version)

old_stats      = {}

# Build and send a request to the POST API
def post_data(body):
    content_type = 'text/plain'
    uri = os.environ['LOGGLY_URL']

    headers = {
        'content-type': content_type
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
					'time': inspect_time,
					'log_type': 'dockerstats',
					'computer_name': computer_name,
					'image': container.image.attrs['RepoTags'][0],
					'container': container.name,
					'installation_id': installation_id,
					'cpu_usage': cpuPercent,
					'mem_usage': docker_stats['memory_stats']['usage']
				}
				post_data(json.dumps(stats_obj))
			old_stats[container.name] = docker_stats
	except Exception as e:
		print(e)
		sys.exit(1)

file = open("/etc/hostname", "r")
computer_name = str.strip(file.read())

while True:
	collect_stats()
	time.sleep(60)
