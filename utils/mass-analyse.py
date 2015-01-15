#!/usr/bin/env python

import argparse
import json
import logging

import os
import sys
import time

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING
from lib.cuckoo.core.startup import init_modules
from lib.cuckoo.common.colors import bold, red, green, yellow


def parse_handle(handle):
    if isinstance(handle, (str, unicode)) and handle[:2] == "0x":
        return int(handle, 16)
    else:
        return int(handle)


class AbstractProcessAnalyser(object):
    def on_new_process(self, parent_id, process_name, process_id, first_seen):
        '''Call this when a new process spawns'''
        pass

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments,
                    call_id):
        '''Call this for every event that happens.
                   event: expects a call dict
                   pid: the pid where the call happened'''
        pass

    def on_http_request(self):
        pass

    def on_file_write(self):
        pass

    def on_file_delete(self):
        pass

    def on_registry_set(self):
        pass

    def on_registry_delete(self):
        pass

    def on_socket_connect(self):
        pass

    def on_shell_execute(self):
        pass


class UnknownApiCallException(Exception):
    pass


class ApiStateException(Exception):
    pass


class AggregateProcessAnalyser(AbstractProcessAnalyser):
    def __init__(self, event_handler):
        self.event_handler = event_handler

    def on_new_process(self, parent_id, process_name, process_id, first_seen):
        self.event_handler.on_new_process(parent_id, process_name, process_id, first_seen)

        log.info("New process: {0} (pid: {1}, parent_id: {2})".format(process_name, process_id, parent_id))

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments,
                    call_id):
        # Ignore failed calls
        if not status:
            return

        if category == "network":
            callback = self.__process_network_event
        elif category == "socket":
            callback = self.__process_socket_event
        elif category == "filesystem":
            callback = self.__process_filesystem_event
        elif category == "hooking":
            callback = self.__process_ignored_event
        elif category == "registry":
            callback = self.__process_registry_event
        elif category == "threading":
            callback = self.__process_ignored_event
        elif category == "process":
            callback = self.__process_ignored_event
        elif category == "system":
            callback = self.__process_system_event
        elif category == "synchronization":
            callback = self.__process_ignored_event
        elif category == "device":
            callback = self.__process_ignored_event
        elif category == "services":
            callback = self.__process_ignored_event
        else:
            callback = self.__process_unknown_event

        callback(process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments, call_id)

    def on_file_delete(self):
        super(AggregateProcessAnalyser, self).on_file_delete()

    def on_registry_set(self):
        super(AggregateProcessAnalyser, self).on_registry_set()

    def on_registry_delete(self):
        super(AggregateProcessAnalyser, self).on_registry_delete()

    def on_shell_execute(self):
        super(AggregateProcessAnalyser, self).on_shell_execute()

    def on_file_write(self):
        super(AggregateProcessAnalyser, self).on_file_write()

    def on_socket_connect(self, process_id, thread_id, socket_id, ip, port):
        print "Connect to " + ip + ":" + str(port)

    def on_http_request(self, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data):
        print http_verb + " " + http_url

    @staticmethod
    def __process_unknown_event(process_id, category, status, return_value, timestamp, thread_id, repeated, api,
                                arguments, call_id):
        raise UnknownApiCallException("Unknown API category: " + category)

    @staticmethod
    def __process_ignored_event(process_id, category, status, return_value, timestamp, thread_id, repeated, api,
                                arguments, call_id):
        pass

    def __process_registry_event(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api,
                                 arguments, call_id):
        pass

    def __process_socket_event(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api,
                               arguments, call_id):
        __socket_state = self.__get_state_for_pid(process_id)["socket"]

        if api == "socket":
            socket_id = parse_handle(return_value)

            if socket_id in __socket_state["sockets"]:
                # raise ApiStateException("Socket {0} is already created in this process!".format(socket_id))
                print "Socket {0} is already created in this process!".format(socket_id)
                return

            __socket_state["sockets"].append(socket_id)
        elif api == "connect":
            socket_id = parse_handle(arguments["socket"])

            if socket_id not in __socket_state["sockets"]:
                raise ApiStateException("Socket {0} is not yet created in this process!".format(socket_id))

            self.on_socket_connect(process_id, thread_id, socket_id, arguments["ip"], int(arguments["port"]))
        elif api == "closesocket" or api == "shutdown":
            socket_id = parse_handle(arguments["socket"])

            if socket_id not in __socket_state["sockets"]:
                raise ApiStateException("Socket {0} is not yet created in this process!".format(socket_id))

            __socket_state["sockets"].remove(socket_id)

    def __process_network_event(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api,
                                arguments, call_id):
        __network_state = self.__get_state_for_pid(process_id)["network"]

        if api == "InternetOpenW":
            handle = parse_handle(return_value)

            if handle in __network_state["handles"]:
                raise ApiStateException("InternetHandle {0} for this process exists already!".format(handle))

            # print "InternetHandle {0}".format(handle)

            __network_state["handles"].append(handle)
            __network_state["handle_state"][handle] = {
                "type": "internet",
                "session_handles": []
            }
        elif api == "InternetConnectW":
            internet_handle = parse_handle(arguments["InternetHandle"])
            session_handle = parse_handle(return_value)

            if internet_handle not in __network_state["handles"] \
                    or __network_state["handle_state"][internet_handle]["type"] != "internet":
                raise ApiStateException("InternetHandle {0} for this process does not exist!".format(internet_handle))

            if session_handle in __network_state["handles"]:
                # raise ApiStateException("SessionHandle {0} for this process exists already!".format(session_handle))
                print "SessionHandle {0} for this process exists already!".format(session_handle)
                print __network_state["handle_state"][session_handle]
                return

            # print "SessionHandle {0}".format(session_handle)

            __network_state["handles"].append(session_handle)
            __network_state["handle_state"][internet_handle]["session_handles"].append(session_handle)
            __network_state["handle_state"][session_handle] = {
                "internet_handle": internet_handle,
                "type": "session",
                "request_handles": [],
                "server_name": arguments["ServerName"],
                "server_port": int(arguments["ServerPort"])
            }
        elif api == "HttpOpenRequestW":
            session_handle = parse_handle(arguments["InternetHandle"])
            request_handle = parse_handle(return_value)

            if session_handle not in __network_state["handles"] \
                    or __network_state["handle_state"][session_handle]["type"] != "session":
                # raise ApiStateException("SessionHandle {0} for this process does not exist!".format(session_handle))
                print "SessionHandle {0} for this process does not exist!".format(session_handle)
                return

            if request_handle in __network_state["handles"]:
                # raise ApiStateException("RequestHandle {0} for this process exists already!".format(request_handle))
                print "RequestHandle {0} for this process exists already!".format(request_handle)
                return

            # print "RequestHandle {0}".format(request_handle)

            __network_state["handles"].append(request_handle)
            __network_state["handle_state"][session_handle]["request_handles"].append(request_handle)
            __network_state["handle_state"][request_handle] = {
                "session_handle": session_handle,
                "type": "request",
                "path": arguments["Path"],
                "verb": arguments["Verb"],
                "referer": arguments["Referer"],
                "data": ""
            }
        elif api == "InternetCloseHandle":
            handle = parse_handle(arguments["InternetHandle"])

            if handle not in __network_state["handles"]:
                # raise ApiStateException("Handle {0} for this process does not exist!".format(handle))
                print "Handle {0} for this process does not exist!".format(handle)
                return

            if __network_state["handle_state"][handle]["type"] == "request":
                session_handle = __network_state["handle_state"][handle]["session_handle"]

                if session_handle not in __network_state["handles"]:
                    # raise ApiStateException("The SessionHandle {0} of the Handle {1} for this process does not exist!".
                    # format(__network_state["handle_state"][handle]["session_handle"], handle))
                    print "The SessionHandle {0} of the Handle {1} for this process does not exist!".format(
                        __network_state["handle_state"][handle]["session_handle"], handle)
                    return

                protocol_handler = "http://"
                if __network_state["handle_state"][session_handle]["server_port"] == 443:
                    protocol_handler = "https://"

                http_verb = __network_state["handle_state"][handle]["verb"]
                http_url = protocol_handler + \
                           __network_state["handle_state"][session_handle]["server_name"] + ":" + \
                           str(__network_state["handle_state"][session_handle]["server_port"]) + \
                           __network_state["handle_state"][handle]["path"]
                http_response_data = __network_state["handle_state"][handle]["data"]

                if __network_state["handle_state"][session_handle]["server_port"] == 0 \
                        or __network_state["handle_state"][session_handle]["server_port"] == 80 \
                        or __network_state["handle_state"][session_handle]["server_port"] == 443:
                    http_url = protocol_handler + \
                               __network_state["handle_state"][session_handle]["server_name"] + \
                               __network_state["handle_state"][handle]["path"]

                self.on_http_request(process_id, thread_id, http_verb, http_url, None, http_response_data)

            # print "CloseHandle {0} ({1})".format(handle, __network_state["handle_state"][handle]["type"])

            __network_state["handles"].remove(handle)
            del __network_state["handle_state"][handle]
        elif api == "InternetReadFile":
            request_handle = parse_handle(arguments["InternetHandle"])

            if request_handle not in __network_state["handles"] \
                    or __network_state["handle_state"][request_handle]["type"] != "request":
                # raise ApiStateException("SessionHandle {0} for this process does not exist!".format(session_handle))
                print "RequestHandle {0} for this process does not exist!".format(request_handle)
                return

            __network_state["handle_state"][request_handle]["data"] = \
                __network_state["handle_state"][request_handle]["data"] + arguments["Buffer"]
        elif api == "InternetReadFileExW":
            request_handle = parse_handle(arguments["InternetHandle"])

            if request_handle not in __network_state["handles"] \
                    or __network_state["handle_state"][request_handle]["type"] != "request":
                # raise ApiStateException("SessionHandle {0} for this process does not exist!".format(session_handle))
                print "RequestHandle {0} for this process does not exist!".format(request_handle)
                return

            __network_state["handle_state"][request_handle]["data"] = \
                __network_state["handle_state"][request_handle]["data"] + arguments["Buffer"]

    def __process_filesystem_event(self, process_id, category, status, return_value, timestamp, thread_id, repeated,
                                   api, arguments, call_id):
        __filesystem_state = self.__get_state_for_pid(process_id)["filesystem"]

        if api == "NtCreateFile":
            file_handle = parse_handle(arguments["FileHandle"])

            if file_handle in __filesystem_state["handles"]:
                # raise ApiStateException("FileHandle {0} is already created in this process!".format(file_handle))
                print "FileHandle {0} is already created in this process!".format(file_handle)
                return

            __filesystem_state["handles"].append(file_handle)
            __filesystem_state["handle_state"][file_handle] = {
                "path": arguments["FileName"]
            }
        elif api == "NtOpenFile":
            file_handle = parse_handle(arguments["FileHandle"])

            if file_handle in __filesystem_state["handles"]:
                # raise ApiStateException("FileHandle {0} is already created in this process!".format(file_handle))
                print "FileHandle {0} is already created in this process!".format(file_handle)
                return

            __filesystem_state["handles"].append(file_handle)
            __filesystem_state["handle_state"][file_handle] = {
                "path": arguments["FileName"]
            }
        elif api == "DeleteFileA" or api == "DeleteFileW":
            file_path = arguments["FileName"]

            self.on_file_delete(file_path)
        else:
            print api

    def __process_system_event(self, process_id, category, status, return_value, timestamp, thread_id, repeated,
                                   api, arguments, call_id):
        __filesystem_state = self.__get_state_for_pid(process_id)["filesystem"]

        if api == "NtClose":
            file_handle = parse_handle(arguments["Handle"])

            if file_handle not in __filesystem_state["handles"]: # Not all NtClose calls are related to the FS
                #raise ApiStateException("Handle {0} is not yet created in this process!".format(file_handle))
                return

            __filesystem_state["handles"].remove(file_handle)
            del __filesystem_state["handle_state"][file_handle]
        else:
            print api


    __state = {}

    def __get_state_for_pid(self, process_id):
        if process_id not in self.__state:
            self.__state[process_id] = {
                "filesystem": {
                    "handles": [],
                    "handle_state": {}
                },
                "network": {
                    "handles": [],
                    "handle_state": {}
                },
                "socket": {
                    "sockets": []
                }
            }

        return self.__state[process_id]


class GraphGenerator(AbstractProcessAnalyser):
    pass


class LogProcessorException(Exception):
    pass


class AbstractLogProcessor:
    def __init__(self, task_id, event_handler):
        self.task_id = task_id
        self.event_handler = event_handler


class AbstractLogProcessorEventHandler:
    def __init__(self):
        pass

    def on_new_process(self, parent_id, process_name, process_id, first_seen):
        pass

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments,
                    call_id):
        pass


class JSONLogProcessor(AbstractLogProcessor):
    def __init__(self, task_id, event_handler):
        AbstractLogProcessor.__init__(self, task_id, event_handler)

        self.report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", "report.json")

        if not os.path.exists(self.report_path):
            raise LogProcessorException("Can't find report.json at " + self.report_path)

        self.json_data = json.load(open(self.report_path, "r"))
        self.process_data = self.json_data["behavior"]["processes"]
        self.processed_pids = []

        if len(self.process_data) > 0:
            self.process_data_index = 0
            self.process_data_len = len(self.process_data)

            self.current_process_data = self.process_data[self.process_data_index]

            self.current_process_calls = self.current_process_data["calls"]
            self.current_process_calls_index = 0
            self.current_process_calls_len = len(self.current_process_calls)

    def has_more_events(self):
        if len(self.process_data) != len(self.processed_pids):
            return True

        return False

    def parse_events(self, max_events_to_process=-1):
        # Report new process
        if self.current_process_calls_index == 0:
            self.event_handler.on_new_process(self.current_process_data["parent_id"],
                                              self.current_process_data["process_name"],
                                              self.current_process_data["process_id"],
                                              self.current_process_data["first_seen"])

        while self.current_process_calls_index < self.current_process_calls_len:
            current_process_call = self.current_process_calls[self.current_process_calls_index]

            if max_events_to_process == -1 or max_events_to_process > 0:
                self.event_handler.on_api_call(self.current_process_data["process_id"],
                                               current_process_call["category"],
                                               current_process_call["status"],
                                               current_process_call["return"],
                                               current_process_call["timestamp"],
                                               current_process_call["thread_id"],
                                               current_process_call["repeated"],
                                               current_process_call["api"],
                                               current_process_call["arguments"],
                                               current_process_call["id"])

                self.current_process_calls_index += 1
                max_events_to_process -= 1
            else:
                return

        # All calls are processed
        self.processed_pids.append(self.current_process_data["process_id"])

        self.process_data_index += 1

        # Update pointers to next
        if self.process_data_index < self.process_data_len:
            self.current_process_data = self.process_data[self.process_data_index]

            self.current_process_calls = self.current_process_data["calls"]
            self.current_process_calls_index = 0
            self.current_process_calls_len = len(self.current_process_calls)


class DAGLogProcessorEventHandler(AbstractLogProcessorEventHandler):
    def __init__(self, dag_event_handler):
        self.event_handler = dag_event_handler

    def on_new_process(self, parent_id, process_name, process_id, first_seen):
        self.event_handler.on_new_process(parent_id, process_name, process_id, first_seen)

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments,
                    call_id):
        new_arguments = {}
        for arg in arguments:
            new_arguments[arg["name"]] = arg["value"]

        self.event_handler.on_api_call(process_id, category, status, return_value, timestamp, thread_id, repeated,
                                       api, new_arguments, call_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="File with URLs to process.")
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-t", "--task", help="Process existing task", action="store_true", required=False)
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    init_modules()

    db = Database()

    skip_waiting = False

    if args.task:
        # Parse an existing analysis report
        task_id = args.input

        if not task_id.isdigit():
            print(bold(red("Error")) + ": " + task_id + " is not a valid task id")
            return False

        task_id = int(task_id)

        if not db.view_task(task_id):
            print(bold(red("Error")) + ": " + task_id + " is not a valid task")
            return False

        if db.view_task(task_id).status != TASK_REPORTED:
            print(bold(yellow("Warning")) + u": Task with ID {0} is not yet completed; Waiting...".format(task_id))

        skip_waiting = True
    else:
        # New task, we have to wait for completion
        file_name = args.input

        if not os.path.isfile(file_name):
            print(bold(red("Error")) + ": " + file_name + " is not a file!")
            return False

        url_list = []

        with open(args.url_list, "r") as f:
            for url in f:
                url = url.strip()

                if url != "" and url[0] != "#":
                    url_list.append(url)

        if len(url_list) == 0:
            print(bold(red("Error")) + ": " + file_name + " is empty!")
            return False

        task_id = db.add_urls(url_list)

        if not task_id:
            print(bold(red("Error")) + ": Task creation failure")
            return False

        print(bold(green("Success")) + u": Created task with ID {0}; Now wait for completion...".format(task_id))

    while True and not skip_waiting:
        if db.view_task(task_id).status == TASK_REPORTED:
            print(bold(green("Success")) + u": Task completed!")
            break
        elif db.view_task(task_id).status == TASK_FAILED_ANALYSIS or db.view_task(
                task_id).status == TASK_FAILED_PROCESSING:
            print(bold(red("Error")) + u": Task analysis or reporting FAILED!")
            return False

        time.sleep(1)

    log.info("Parse log....")

    log_processor = JSONLogProcessor(task_id, DAGLogProcessorEventHandler(AggregateProcessAnalyser(GraphGenerator())))

    while log_processor.has_more_events():
        log_processor.parse_events()


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
