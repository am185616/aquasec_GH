from flask import Flask, jsonify, request
from flask_restful import reqparse, abort, Api, Resource
from kubernetes.client.rest import ApiException
from kubernetes import client, config
import requests, base64
import os, re, json

import urllib.request
url = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
req = urllib.request.Request(url)
req.add_header("Metadata-Flavor", "Google")
project_id = urllib.request.urlopen(req).read().decode()


app = Flask(__name__)

githubAPI = 'https://api.github.com/repos/ncr-bsp/'
githubToken = os.getenv('GITHUB_TOKEN')


@app.route('/bundlename/<application>/<commitHash>', methods=['GET'])
def get_bundle_name(application,commitHash):
    namespace = request.headers.get('namespace')
    r = requests.get(githubAPI+application+'/statuses/'+commitHash, headers = {"Authorization": "token "+githubToken,"Content-Type": "application/json" })
    #Get the HTTP Response Code
    r.status_code
    #Get HTTP Response Body
    r.text

    if r.status_code == 200:
        response_content = "Succcess"
        for git_status in r.json():
            if git_status['context'] == "api_launch":
                api_launch_bundle_name = git_status['description']
                config.load_incluster_config()
                # config.load_kube_config()
                api_instance = client.CoreV1Api()
                message_bytes = api_launch_bundle_name.encode('ascii')
                base64_bytes = base64.b64encode(message_bytes)
                base64_message = base64_bytes.decode('ascii')

                try:
                    secret = client.V1Secret()
                    secret.metadata = client.V1ObjectMeta(name=application+"-"+commitHash)
                    secret.type = "Opaque"
                    secret.data = {
                        "API_LAUNCH_BUNDLE_NAME": base64_message
                    }

                    print(api_instance.create_namespaced_secret(namespace, secret))

                except ApiException as e:
                # Status appears to be a string.
                    if e.status == 409:
                      print("Github token has already been installed")
                    else:
                      raise
    else:
        response_content = "Failure"
        print("Status of request: " + r.text)

    return jsonify(response_content)

@app.route('/statuschange', methods=['POST'])
def add_entry():
    request_json                = request.json
    name                        = request.json['name']
    namespace                   = request.json['namespace']
    request_metadadata_json     = request.json['metadata']
    application                 = request_metadadata_json.get('application')
    commitHash                  = request_metadadata_json.get('hash')
    type                        = request_metadadata_json.get('type')
    label_selector              = request_metadadata_json.get('label_selector')
    container                   = request_metadadata_json.get('container')
    state = ''
    description = ''
    if type == "deployment":
        if request_json.get('phase') == "Succeeded":
            state = "success"
            description = "Application was deployed successfully to "+ project_id +" project"
        elif request_json.get('phase') == "Failed":
            state = "failure"
            description = "Application failed to deploy to "+ project_id +" project"
        statusBody = '{"state": "'+state+'",  "description": "'+description+'", "context": "'+project_id+' '+type+'"}'
    elif type == "api_launch":
        if request_json.get('phase') == "Succeeded":
            state = "success"
            config.load_incluster_config()
            try:
                api_instance = client.CoreV1Api()
                pods = api_instance.list_namespaced_pod(namespace=namespace,label_selector=label_selector)
                for pod_name in pods.items:
                    print(pod_name.metadata.name)
                    if container:
                        api_response = api_instance.read_namespaced_pod_log(name=pod_name.metadata.name, namespace=namespace, container=container)
                    else:
                        api_response = api_instance.read_namespaced_pod_log(name=pod_name.metadata.name, namespace=namespace)
                    reference_json = re.findall('^Response result: {"version":.+', api_response, re.MULTILINE)[0].removeprefix('Response result: ')
                    description = json.loads(reference_json)['reference']
            except ApiException as e:
                print('Found exception in reading the logs')
        elif request_json.get('phase') == "Failed":
            state = "failure"
            description = "API Launch Failed"
        statusBody = '{"state": "'+state+'",  "description": "'+description+'", "context": "'+type+'"}'
    

    print(statusBody)
    print("Sending a " + state + " request to GitHub for " + application + " application: ")

    r = requests.post(githubAPI+application+'/statuses/'+commitHash,data = statusBody, headers = {"Authorization": "token "+githubToken,"Content-Type": "application/json" })
    #Get the HTTP Response Code
    r.status_code
    #Get HTTP Response Body
    r.text

    if r.status_code == 201:
        response_content = "Succcess"
    else:
        response_content = "Failure"
        print("Status of request: " + r.text)

    return jsonify(response_content)

if __name__ == '__main__':
    app.run(debug=True)
