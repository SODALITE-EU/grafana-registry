from base64 import b64encode
from os import path, listdir, getenv
from flask import Flask, request
from requests import post, delete, Session, adapters
from requests.auth import HTTPBasicAuth as basicAuth
from jinja2 import Environment, PackageLoader
from json import loads
import logging

env = Environment(loader=PackageLoader("app"), autoescape=False)
app = Flask(__name__)
dashboard_urls = {}
dashboard_uids = {}
dashboard_ids = {}
gf_endpoint = 'localhost:'+getenv("GF_PORT", "")
gf_admin_user = getenv("GF_ADMIN_USER", "admin")
gf_admin_pw = getenv("GF_ADMIN_PW", "")
oidc_client_id = getenv("OIDC_CLIENT_ID", "sodalite-ide")
oidc_client_secret = getenv("OIDC_CLIENT_SECRET", "")
oidc_introspection_endpoint = getenv("OIDC_INTROSPECTION_ENDPOINT", "")


@app.route('/create_dashboards', methods=['POST'])
def create_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    dashboard_urls[deployment_label] = {}
    dashboard_uids[deployment_label] = {}
    dashboard_ids[deployment_label] = {}

    for template_file in listdir(path.dirname(path.abspath(__file__))+'/templates'):
        dashboard_type = path.splitext(path.splitext(template_file)[0])[0]
        template = env.get_template(template_file)

        # Create of the dashboard with a dummy dashboard uid
        dashboard = template.render(deployment_label=deployment_label,
                                    dashboard_url="/",
                                    dashboard_uid="null")
        r = post('http://' + gf_endpoint + '/api/dashboards/db',
                 auth=basicAuth(gf_admin_user, gf_admin_pw),
                 json=loads(dashboard))
        r_json = r.json()
        dashboard_uid = r_json['uid']
        dashboard_url = r_json['url']
        dashboard_id = str(r_json['id'])
        dashboard_urls[deployment_label][dashboard_type] = dashboard_url
        dashboard_uids[deployment_label][dashboard_type] = dashboard_uid
        dashboard_ids[deployment_label][dashboard_type] = dashboard_id

        # Update the dashboard to include the dashboard url in the links
        dashboard = template.render(deployment_label=deployment_label,
                                    dashboard_url=dashboard_url,
                                    dashboard_uid='"' + dashboard_uid + '"')
        r = post('http://' + gf_endpoint + '/api/dashboards/db',
                 auth=basicAuth(gf_admin_user, gf_admin_pw),
                 json=loads(dashboard))

        # Set the permissions
        r = post('http://' + gf_endpoint + '/api/dashboards/id/' + dashboard_id + '/permissions',
                 auth=basicAuth(gf_admin_user, gf_admin_pw),
                 json={"items":[{"userId": userId, "permission": 1}]})

    return "Dashboards added", 200


@app.route('/delete_dashboards', methods=['POST'])
def delete_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    for dashboard in dashboard_uids[deployment_label]:
        r = delete('http://' + gf_endpoint + '/api/dashboards/uid/' + dashboard_uids[deployment_label][dashboard],
                   auth=basicAuth(gf_admin_user, gf_admin_pw))
        if r.status_code != 200:
            return "Could not delete the dashboard " + dashboard + ": " + str(r.content), r.status_code

    dashboard_urls.pop(deployment_label)
    dashboard_uids.pop(deployment_label)
    dashboard_ids.pop(deployment_label)

    return "Dashboards deleted", 200


@app.route('/get_dashboards', methods=['POST'])
def get_dashboards():
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    return dashboard_urls[deployment_label], 200


def token_info(access_token) -> dict:
    session = Session()
    adapter = adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
    for protocol in ['http:', 'https:']:
        session.mount(protocol, adapter)
    req = {'token': access_token}
    headers = {'Content-type': 'application/x-www-form-urlencoded'}
    if not oidc_introspection_endpoint:
        return {}

    basic_auth_string = '{0}:{1}'.format(oidc_client_id, oidc_client_secret)
    basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
    headers['Authorization'] = 'Basic {0}'.format(b64encode(basic_auth_bytes).decode('utf-8'))
    try:
        token_request = post(oidc_introspection_endpoint, data=req, headers=headers)
        if not token_request.ok:
            return {}
        json = token_request.json
        if "active" in json and json["active"] is False:
            return {}
        return json
    except Exception as e:
        logging.error(str(e))
        return {}
