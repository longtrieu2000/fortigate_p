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

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
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
FORTI_URL = os.getenv("FORTI_URL")
VERIFY_SSL = False  # đổi thành True nếu FortiGate có chứng chỉ hợp lệ
print(FORTI_URL)
# Cấu hình Jira    
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL")
print(JIRA_BASE_URL)

#hàm này là để check xem địa chỉ IP đã tồn tại trong FortiGate hay chưa
# Nếu chưa tồn tại thì sẽ tạo mới
# Nếu đã tồn tại thì sẽ không làm gì cả
def ensure_address_exists(ip, headers):
    addr_name = ip
    encode_ip = quote(ip, safe="")
    print(f"{FORTI_URL}/api/v2/cmdb/firewall/address/{encode_ip}, headers={headers}, verify={VERIFY_SSL}")
    resp = requests.get(
        f"{FORTI_URL}/api/v2/cmdb/firewall/address/{encode_ip}",
        headers=headers,
        verify=VERIFY_SSL
    )
    print(resp.status_code)
    if 400 <= resp.status_code < 500:
        # Chưa tồn tại -> tạo mới
        print(f"{addr_name} chua ton tai can phai tao moi")
        data = {
            "name": addr_name,
            "subnet": ip,
            "type": "ipmask"
        }
        # Thêm trường interface dựa trên điều kiện IP
        if ip.startswith("192.168.106."):
            data["associated-interface"] = "User"
            print(data)
        elif ip.startswith("10."):
            data["associated-interface"] = "VPN_ANM"
            print(data)
        data_json = json.dumps(data)
        print(f"{FORTI_URL}/api/v2/cmdb/firewall/address,headers={headers},data={data_json}, verify={VERIFY_SSL}")
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
            message = f"Address {addr_name} created successfully."
            send_to_slack(message)

        elif not create_resp.ok:
            message = f"Failed to create address {addr_name}: {create_resp.text}"
            send_to_slack(message)

    elif resp.status_code == 200:
        try:
            print("thanh cong ! ket qua tra ve json la")
            print(resp.json())
        except ValueError:
            print(" noi dung tra ve khong phai json, in doan text")
            print(resp.text)

    elif not resp.ok:
        message = f"Error checking address {addr_name}: {resp.text}"
        send_to_slack(message)
        raise Exception(f"Error checking address {ip}: {resp.text}")

# Hàm này sẽ tạo rule firewall dựa trên dữ liệu từ Jira
# Chú ý là hàm này sẽ không tạo rule nếu địa chỉ IP đã tồn tại trong FortiGate
# Nếu địa chỉ IP đã tồn tại thì hàm này sẽ không làm gì cả  
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


    rule = {
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
    send_to_slack(f"Firewall rule built: {rule}")
    return rule

# Hàm này sẽ phân tích các cổng TCP và UDP từ dữ liệu và tạo dịch vụ tương ứng
# Nếu dịch vụ đã tồn tại thì sẽ không tạo mới
# Nếu dịch vụ chưa tồn tại thì sẽ tạo mới
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
    message = f"service tao rule la {services}"
    send_to_slack(message)
    return services

# Hàm này sẽ kiểm tra xem dịch vụ đã tồn tại trong FortiGate hay chưa
# Nếu dịch vụ đã tồn tại thì sẽ không làm gì cả
# Nếu dịch vụ chưa tồn tại thì sẽ tạo mới
def ensure_service_exists(port, protocol, headers):
    service_name = f"{port}_{protocol.upper()}"
    url = f"{FORTI_URL}/api/v2/cmdb/firewall.service/custom/{service_name}"
    print("[ensure_service_exists][url]", url)
    #check xem service da ton tai chua
    print(headers)
    resp = requests.get(url, headers, verify = VERIFY_SSL)
    print("[ensure_service_exists][GET]", service_name)
    if 400 <= resp.status_code < 500:
        respCreateService = create_service(service_name, protocol, headers,  port)
        if not respCreateService:
            return "NA"
    elif resp.status_code != 200:
        return "NA"
    return service_name

# Hàm này sẽ tạo dịch vụ mới trong FortiGate
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
    print(create_resp.status_code)
    print(create_resp.status_code != 200)
    print(create_resp.status_code != int(200))

    if (create_resp.status_code != 200) and (create_resp.status_code != 201):
        print("Err create service",service_name , create_resp)
        message = f"Failed to create service {service_name}: {create_resp.text}"
        send_to_slack(message)
        return 0
    else:
        print("chay ham[create_service] thanh cong")
        message = f"Service {service_name} created successfully."
        send_to_slack(message)
    return 1

# Hàm này sẽ lấy thông tin chi tiết key của issue từ Jira
# Dữ liệu trả về sẽ là một danh sách chứa thông tin chi tiết của issue
# Chú ý là hàm này sẽ không kiểm tra xem issue có tồn tại hay không
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
        message = f"ma {issue_key} cua ticket jira"
        send_to_slack(message)
        return resp.json()
    else:
        raise Exception(f"Jira API error: {resp.status_code} - {resp.text}")

# Hàm này sẽ nhận dữ liệu từ Jira Automation
# và gọi hàm tạo rule firewall
# Dữ liệu sẽ được gửi dưới dạng JSON
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
                "dest_ip" : issue["state"]["answers"]["72"]["text"],
                "port_tcp" : issue.get("state").get("answers").get("15", {}).get("text"),
                "port_udp" : issue.get("state").get("answers").get("18", {}).get("text"),
        }   
        user_create = issue.get("state").get("answers").get("71", {}).get("text")
        message = f"nguoi tao ticket la {user_create}, bat dau tao rule"
        send_to_slack(message)
        print(payload_fw)
        print("---------------------")
        if payload_fw["port_udp"] == None:
           payload_fw.pop("port_udp")
        print(payload_fw)
        print("bat dau tao rule firewall")
        return create_firewall_rule_internal(payload_fw)
    
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

# Hàm này sẽ tạo rule firewall trong FortiGate
# Dữ liệu sẽ được gửi từ hàm receive_from_automation
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
        ensure_address_exists(data.get("source_ip"), headers)
        ensure_address_exists(data.get("dest_ip"), headers)
        resp = requests.post(
            f"{FORTI_URL}/api/v2/cmdb/firewall/policy",
            headers=headers,
            data=rule_json,
            verify=VERIFY_SSL
        )

        if resp.ok:
            message = "Firewall rule created successfully."
            send_to_slack(message)
            return jsonify({"status": "success", "msg": "Rule created successfully"}), 200
        else:
            message = f"Failed to create firewall rule: {resp.text}"
            send_to_slack(message)
            return jsonify({"status": "error", "msg": resp.text}), 400
    except Exception as e:
        message = f"Error creating firewall rule: {str(e)}"
        send_to_slack(message)
        return jsonify({"status": "error", "msg": str(e)}), 500
    
# Hàm này sẽ gửi thông báo đến Slack
# Bạn cần cấu hình webhook URL trong biến môi trường SLACK_WEBHOOK_URL
# Bạn có thể sử dụng hàm này để gửi thông báo khi tạo rule thành công hoặc thất bại
def send_to_slack(message):
    #slack_webhook_url = os.getenv("SLACK_WEBHOOK_URL")  # Đảm bảo URL webhook của Slack được lưu trong biến môi trường
    if not SLACK_WEBHOOK:
        print("SLACK_WEBHOOK_URL is not set.")
        return

    payload = {
                "DevSecOps": "#Jira_ticket",
                "username": "Jira_Automation",
                "icon_emoji": ":ghost:",
                "attachments": [
                        {
                        "color": "#36a64f",
                        "text": message
                        }
                    ]
                }
    payload_json = json.dumps(payload)
    try:
        response = requests.post(SLACK_WEBHOOK, data=payload_json, headers={"ContentType": "application/json"}, verify=False)
        if response.status_code != 200:
            print(f"Failed to send message to Slack: {response.text}")
    except Exception as e:
        print(f"Error sending message to Slack: {str(e)}")

# Hàm này sẽ chạy Flask app 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8101)