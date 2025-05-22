from flask import Flask, request, jsonify
import requests
import os
#import decrypt
from dotenv import load_dotenv
from urllib.parse import quote
from cryptography.fernet import Fernet
import json

#decode file .env cua staging
with open("secret.key", "rb") as f:
    key = f.read()
fernet = Fernet(key)
# Giải mã file .env.enc
with open(".env.enc", "rb") as f:
    encrypted = f.read()
decrypted = fernet.decrypt(encrypted).decode()
# Nạp vào biến môi trường
for line in decrypted.splitlines():
    if "=" in line:
        k, v = line.strip().split("=", 1)
        os.environ[k] = v

app = Flask(__name__)
load_dotenv()  # Load từ .env
print("🔐 Token =", os.getenv("VAULT_TOKEN"))


VAULT_ADDR = os.getenv("VAULT_ADDR")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")
KEY_PATH= ["api_jira" , "api_fortigate"]

if not VAULT_ADDR or not VAULT_TOKEN:
    print("VAULT_ADDR or VAULT_TOKEN is not set in environment.")
    exit(1)

# Khởi tạo 2 biến chứa API key
JIRA_API_KEY = None
FORTIGATE_API_KEY = None

# Danh sách path và mapping với tên biến
PATH_MAPPING = {
    "api_jira": "JIRA_API_KEY",
    "api_fortigate": "FORTIGATE_API_KEY"
}

#SECRET_PATH_JIRA = "secret/data/jira"
for path, var_name in PATH_MAPPING.items():
    headers = {"X-Vault-Token": VAULT_TOKEN}
    secret_path = f"secret/data/{path}"
    url = f"{VAULT_ADDR}/v1/{secret_path}"

    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            api_key = res.json()["data"]["data"].get("api_key")
            if api_key:
                if var_name == "JIRA_API_KEY":
                    JIRA_API_TOKEN = api_key
                elif var_name == "FORTIGATE_API_KEY":
                    FORTIGATE_API_KEY = api_key
                print(f"{var_name} = {api_key}")
            else:
                print(f"[{path}] No 'api_key' found in secret.")
        else:
            print(f"[{path}] Error {res.status_code}: {res.text}")
    except Exception as e:
        print(f"[{path}] Exception: {str(e)}")


# Cấu hình FortiGate
FORTI_URL = os.getenv("FORTI_ADDR")
VERIFY_SSL = False  # đổi thành True nếu FortiGate có chứng chỉ hợp lệ
print(FORTI_URL)
# Cấu hình Jira    
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL")
print(JIRA_BASE_URL)

def ensure_address_exists(ip, headers):
    addr_name = ip
    encode_ip = quote(ip, safe="")
    resp = requests.get(
        f"{FORTI_URL}/api/v2/cmdb/firewall/address/{encode_ip}",
        headers=headers,
        verify=VERIFY_SSL
    )

    if resp.status_code == 404:
        # Chưa tồn tại -> tạo mới
        print(f"{addr_name} chua ton tai can phai tao moi")
        data = {
            "name": addr_name,
            "subnet": ip,
            "type": "ipmask"
        }
        data_json = json.dumps(data)
        create_resp = requests.post(
            f"{FORTI_URL}/api/v2/cmdb/firewall/address",
            headers=headers,
            data=data_json,
            verify=VERIFY_SSL
        )
        if create_resp.status_code == 200:
            try:
                print("thanh cong ! ket qua tra ve json la")
                print(create_resp.json())
            except ValueError:
                print(" noi dung tra ve khong phai json, in doan text")
                print(create_resp.text)

        elif not create_resp.ok:
            raise Exception(f"Failed to create address {ip}: {create_resp.text}")

    elif resp.status_code == 200:
        try:
            print("thanh cong ! ket qua tra ve json la")
            print(resp.json())
        except ValueError:
            print(" noi dung tra ve khong phai json, in doan text")
            print(resp.text)

    elif not resp.ok:
        raise Exception(f"Error checking address {ip}: {resp.text}")
    
def build_firewall_rule(data):
    source_ip = data.get("source_ip", "")
    dest_ip = data.get("dest_ip", "")
    # Phân tích srcintf dựa vào source_ip
    if source_ip.startswith("192.168.106."):
        srcintf_name = "User"
    elif source_ip.startswith("192.168.2."):
        srcintf_name = "VPN_ANM"
    else:
        srcintf_name = "port1"  # fallback nếu không khớp mẫu nào hoặc mở rông thêm 


    return {
        "name": f"JiraRule-{dest_ip}",
        "srcintf": [{"name": srcintf_name}],
        "dstintf": [{"name": "VPN_ANM"}],
        "srcaddr": [{"name": source_ip}],
        "dstaddr": [{"name": dest_ip}],
        "action": "accept",
        "schedule": "always",
        "service": [],  # sẽ được thêm bằng parse_ports()
        "logtraffic": "no",
        "status": "enable"
    }

def parse_ports(data, headers):
    services = []
    tcp_ports = data.get("port_tcp", "").split(",")
    udp_ports = data.get("port_udp", "").split(",")

    for port in tcp_ports:
        port = port.strip()
        if port:
            servicename = ensure_service_exists(port, "tcp", headers)
            services.append({"name": servicename})
    for port in udp_ports:
        port = port.strip()
        if port:
            servicename = ensure_service_exists(port, "udp", headers)
            services.append({"name": servicename})
    print("da chay xong ham [parse_ports]", services)
    return services

def ensure_service_exists(port, protocol, headers):
    service_name = f"{port}_{protocol.upper()}"
    url = f"{FORTI_URL}/api/v2/cmdb/firewall.service/custom/{service_name}"
    print("[ensure_service_exists][url]", url)
    #check xem service da ton tai chua
    resp = requests.get(url, headers, verify = VERIFY_SSL)
    print("[ensure_service_exists][GET]", service_name)
    if resp.status_code == 404:
        respCreateService = create_service(service_name, protocol, headers,  port)
        if not respCreateService:
            return "NA"
    elif resp.status_code != 200:
        return "NA"
    return service_name

def create_service(service_name,protocol, headers, port):
    data = {
            "name" : service_name,
            "protocol": "TCP/UDP",
        }
    if protocol.lower() == "tcp":
        data["tcp-portrange"] = port
    elif protocol.lower() == "udp":
        data["udp-portrange"] = port
    else:
        print(f"Protocol khong hop le: {protocol}")
        return 0
    data_json = json.dumps(data)
    create_resp = requests.post(
        f"{FORTI_URL}/api/v2/cmdb/firewall.service/custom",
        headers=headers,
        data=data_json,
        verify=VERIFY_SSL
    )
    print("[create_service][create_resp]", create_resp)
    if create_resp.status_code != 200 or create_resp.status_code != 201:
        print("Err create service",service_name , create_resp)
        return 0
    else:
        print("chay ham[create_service] thanh cong")
    return 1

def get_issue_details(issue_key):
    resp = requests.get(
        f"{JIRA_BASE_URL}/rest/proformalite/api/2/portal/1/issues/{issue_key}",
         headers={
            "Authorization": f"Bearer {JIRA_API_TOKEN}",
            "Accept": "application/json"
         }
    )
    
    if resp.status_code == 200:
        print(f"issue key cua jira la {issue_key}")
        return resp.json()
    else:
        raise Exception(f"Jira API error: {resp.status_code} - {resp.text}")

@app.route("/webhook/jira", methods=["POST"])
def receive_from_automation():
    data = request.get_json()
    issue_key = data.get("issue_key")

    if not issue_key:
        return jsonify({"status": "error", "msg": "Missing issue_key"}), 400
    key_data=get_issue_details(issue_key)
    print(key_data)
    try:     #issue_data = get_issue_details(issue_key)
        issue = key_data[0]  # Giả sử là danh sách
        print("-------------------------------")
        print(issue)

            # Trích xuất thông tin
        print("-------------------------------")
        payload_fw = {
                "source_ip" : issue["state"]["answers"]["13"]["text"],
                "dest_ip" : issue["state"]["answers"]["14"]["text"],
                "port_tcp" : issue.get("state").get("answers").get("15", {}).get("text"),
                "port_udp" : issue.get("state").get("answers").get("18", {}).get("text"),
                #"purpose" : issue.get["state"]["answers"]["12"]["text"]
            }
        print(payload_fw)
        print("---------------------")
        if payload_fw["port_udp"] == None:
           payload_fw.pop("port_udp")
        print(payload_fw)
        print("bat dau tao rule firewall")
        return create_firewall_rule_internal(payload_fw)
    
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500


def create_firewall_rule_internal(data):                                                                                                                                                                                                                                                                                            
    try:
        rule = build_firewall_rule(data)
        print(rule)

        # Gửi đến FortiGate API
        headers = {
            "Authorization": f"Bearer {FORTIGATE_API_KEY}",
            "Content-Type": "application/json"
        }
        print(headers)
        rule["service"] = parse_ports(data, headers)
        print(rule["service"])
        rule_json = json.dumps(rule)
        ensure_address_exists(data("source_ip"), headers)
        ensure_address_exists(data("dest_ip"), headers)
        resp = requests.post(
            f"{FORTI_URL}/api/v2/cmdb/firewall/policy",
            headers=headers,
            data=rule_json,
            verify=VERIFY_SSL
        )

        if resp.ok:
            return jsonify({"status": "success", "msg": "Rule created successfully"}), 200
        else:
            return jsonify({"status": "error", "msg": resp.text}), 400
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8101)