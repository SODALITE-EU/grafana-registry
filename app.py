from base64 import b64encode
from os import path, listdir, getenv
from flask import Flask, request
from requests import post, delete, get, Session, adapters
from requests.auth import HTTPBasicAuth as basicAuth
from jinja2 import Environment, PackageLoader
from json import loads
import logging

env = Environment(loader=PackageLoader("app"), autoescape=False)
app = Flask(__name__)
dashboard_urls = {}
dashboard_uids = {}
dashboard_ids = {}
user_ids = {}
gf_endpoint = 'localhost:' + getenv("GF_PORT", "")
gf_admin_user = getenv("GF_ADMIN_USER", "admin")
gf_admin_pw = getenv("GF_ADMIN_PW", "")
oidc_client_id = getenv("OIDC_CLIENT_ID", "sodalite-ide")
oidc_client_secret = getenv("OIDC_CLIENT_SECRET", "")
oidc_introspection_endpoint = getenv("OIDC_INTROSPECTION_ENDPOINT", "")

session = Session()
adapter = adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
for protocol in ['http:', 'https:']:
    session.mount(protocol, adapter)


@app.route('/dashboards', methods=['POST'])
def create_dashboards():
    user_info = token_info(request.authorization)
    if not user_info:
        return "Access not authorized", 401

    user_email = user_info['email']
    user_name = user_info['name']
    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    if not check_user_deployment_availability(user_email, deployment_label):
        return "Deployment label already belongs to a different user", 403

    if user_email not in dashboard_uids:
        dashboard_urls[user_email] = {}
        dashboard_uids[user_email] = {}
        dashboard_ids[user_email] = {}
        user_id = get_user_id(user_email, user_name)
        if user_id is None:
            return "Could not register user in Grafana", 500
        else:
            user_ids[user_email] = user_id

    dashboard_urls[user_email][deployment_label] = {}
    dashboard_uids[user_email][deployment_label] = {}
    dashboard_ids[user_email][deployment_label] = {}

    for template_file in listdir(path.dirname(path.abspath(__file__)) + '/templates'):
        dashboard_type = path.splitext(path.splitext(template_file)[0])[0]
        template = env.get_template(template_file)

        # Create of the dashboard with a dummy dashboard uid and no url in the links
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
        dashboard_urls[user_email][deployment_label][dashboard_type] = dashboard_url
        dashboard_uids[user_email][deployment_label][dashboard_type] = dashboard_uid
        dashboard_ids[user_email][deployment_label][dashboard_type] = dashboard_id

        # Update the dashboard to include the dashboard url in the links and real uid
        dashboard = template.render(deployment_label=deployment_label,
                                    dashboard_url=dashboard_url,
                                    dashboard_uid='"' + dashboard_uid + '"')
        post('http://' + gf_endpoint + '/api/dashboards/db',
             auth=basicAuth(gf_admin_user, gf_admin_pw),
             json=loads(dashboard))

        # Set the permissions
        post('http://' + gf_endpoint + '/api/dashboards/id/' + dashboard_id + '/permissions',
             auth=basicAuth(gf_admin_user, gf_admin_pw),
             json={"items": [{"userId": user_ids[user_email], "permission": 1}]})

    return "Dashboards added", 200


@app.route('/dashboards', methods=['DELETE'])
def delete_dashboards():
    user_info = token_info(request.authorization)
    if not user_info:
        return "Access not authorized", 401

    user_email = user_info['email']

    json_data = request.json

    if 'deployment_label' in json_data:
        deployment_label = json_data['deployment_label']
    else:
        return "Request must include deployment_label", 403

    if user_email not in dashboard_uids or deployment_label not in dashboard_uids[user_email]:
        return "Could not find the deployment_label in the user list of dashboards", 404
    for dashboard in dashboard_uids[user_email][deployment_label]:
        r = delete('http://' + gf_endpoint + '/api/dashboards/uid/' +
                   dashboard_uids[user_email][deployment_label][dashboard],
                   auth=basicAuth(gf_admin_user, gf_admin_pw))
        if r.status_code != 200:
            return "Could not delete the dashboard " + dashboard + ": " + str(r.content), r.status_code

    dashboard_urls.pop(deployment_label)
    dashboard_uids.pop(deployment_label)
    dashboard_ids.pop(deployment_label)

    return "Dashboards deleted", 200


@app.route('/dashboards/user/', methods=['GET'])
def get_dashboards_user():
    user_info = token_info(request.authorization)
    if not user_info:
        return "Access not authorized", 401

    user_email = user_info['email']
    return dashboard_urls[user_email], 200


@app.route('/dashboards/deployment/<deployment_label>', methods=['GET'])
def get_dashboards_user(deployment_label):
    user_info = token_info(request.authorization)
    if not user_info:
        return "Access not authorized", 401

    user_email = user_info['email']
    if not deployment_label:
        return "Must provide the deployment_label", 403

    return dashboard_urls[user_email][deployment_label], 200


def token_info(access_token) -> dict:

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
        json = token_request.json()
        if "active" in json and json["active"] is False:
            return {}
        return json
    except Exception as e:
        logging.error(str(e))
        return {}


def get_user_id(user_email, user_name):
    r = get('http://' + gf_endpoint + '/api/users/lookup?loginOrEmail=' + user_email,
            auth=basicAuth(gf_admin_user, gf_admin_pw), json={})
    if r.status_code == 200:
        return r.json()['id']
    elif r.status_code == 404:
        # If the user isn't registered, register it.
        r = post('http://' + gf_endpoint + '/api/admin/users',
                 auth=basicAuth(gf_admin_user, gf_admin_pw), json={
                    "name": user_name,
                    "email": user_email,
                    "login": user_email,
                    "authLabels": ["OAuth"],
                    "password": "nothing"
                    }).json()
        if "id" in r:
            return r["id"]
        else:
            return None


def check_user_deployment_availability(user_email, deployment_label):
    for user in dashboard_uids:
        for deployment in dashboard_uids[user]:
            if deployment_label == deployment and user != user_email:
                return False
    return True
