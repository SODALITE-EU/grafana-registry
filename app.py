import os

from flask import Flask, request
from requests import post
from requests.auth import HTTPBasicAuth as basicAuth
from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(loader=PackageLoader("app"), autoescape=select_autoescape())
app = Flask(__name__)
dashboard_urls = {}
dashboard_uids = {}
dashboard_ids = {}
gf_endpoint = 'localhost:3000'
gf_admin_user = 'admin'
gf_admin_pw = 'admin'


@app.route('/create_dashboards', methods=['POST'])
def create_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    for template_file in os.listdir('templates'):
        dashboard_type = os.path.splitext(template_file)
        template = env.get_template(template_file)

        # Create of the dashboard with a dummy dashboard uid
        dashboard = template.render(deployment_label=deployment_label,
                                    dashboard_url="/")
        r = post(gf_endpoint + '/api/dashboards/db',
                 auth=basicAuth(gf_admin_user, gf_admin_pw),
                 json=dashboard)
        r_json = r.json()
        dashboard_uid = r_json['uid']
        dashboard_url = r_json['url']
        dashboard_id = str(r_json['id'])
        dashboard_urls[deployment_label] = {dashboard_type: dashboard_url}
        dashboard_uids[deployment_label] = {dashboard_type: dashboard_uid}
        dashboard_ids[deployment_label] = {dashboard_type: dashboard_id}

        # Update the dashboard to include the dashboard url in the links
        dashboard = template.render(deployment_label=deployment_label,
                                    dashboard_url=dashboard_url)
        post(gf_endpoint + '/api/dashboards/db',
             auth=basicAuth(gf_admin_user, gf_admin_pw),
             json=dashboard)

        # Set the permissions
        post(gf_endpoint + '/api/dashboards/id/'+dashboard_id+'/permissions',
             auth=basicAuth(gf_admin_user, gf_admin_pw),
             json={"userId": userId, "permission": 1})

    return 200


@app.route('/delete_dashboards', methods=['POST'])
def delete_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    for dashboard in dashboard_uids[deployment_label]:
        post(gf_endpoint + '/api/dashboards/uid/' + dashboard_uids[deployment_label][dashboard],
             auth=basicAuth(gf_admin_user, gf_admin_pw))

    dashboard_urls.pop(deployment_label)
    dashboard_uids.pop(deployment_label)
    dashboard_ids.pop(deployment_label)

    return 200


@app.route('/get_dashboards', methods=['POST'])
def get_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    return dashboard_urls[deployment_label], 200
