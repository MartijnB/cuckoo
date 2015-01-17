#!/usr/bin/env python

import argparse
import heapq
import json
import logging

import os
import sys
import time

from igraph import *
import pprint

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING
from lib.cuckoo.core.startup import init_modules
from lib.cuckoo.common.colors import bold, red, green, yellow
from modules.processing.behavior import Processes


class Registry_Event_Handler(object):
    registry = {}
    anomalities = {}
    pp = pprint.PrettyPrinter(indent=4)

    # Nasty code incoming
    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments,
                    call_id):
        event = False
        pid = process_id
        if not self.registry.has_key(pid):
            self.registry[pid] = {
                "reg_keys_created": {},
                "reg_keys_deleted": {},
                "reg_keys_values": {},
                "reg_keys_process_handle": {
                    "0x80000000": "HKEY_CLASSES_ROOT",
                    "0x80000001": "HKEY_CURRENT_USER",
                    "0x80000002": "HKEY_LOCAL_MACHINE",
                    "0x80000003": "HKEY_USERS",
                    "0x80000004": "HKEY_PERFORMANCE_DATA",
                    "0x80000005": "HKEY_CURRENT_CONFIG",
                    "0x80000006": "HKEY_DYN_DATA"
                },
                "predefined_key_handle": {
                    "0x80000000": "HKEY_CLASSES_ROOT",
                    "0x80000001": "HKEY_CURRENT_USER",
                    "0x80000002": "HKEY_LOCAL_MACHINE",
                    "0x80000003": "HKEY_USERS",
                    "0x80000004": "HKEY_PERFORMANCE_DATA",
                    "0x80000005": "HKEY_CURRENT_CONFIG",
                    "0x80000006": "HKEY_DYN_DATA"
                }
            }
        thread_id_ = thread_id + "_"
        handle = ""
        if "KeyHandle" in arguments:
            handle = arguments["KeyHandle"]
        else:
            handle = arguments["Handle"]


        # CREATING REGISTRY KEYS
        if api == "NtCreateKey":
            path = arguments["ObjectAttributes"]
            self.registry[pid]["reg_keys_created"][path] = 1
            self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = path
        elif api == "RegCreateKeyExA" or api == "RegCreateKeyExW":
            # TODO: We're working with a subkey, not the whole key, check registry value...
            subkey = arguments["SubKey"]
            registry = arguments["Registry"]
            print "REGISTRY RegCreateKeyEx: Handle = %s, Registry = %s, SubKey = %s" % (handle, registry, subkey)
            if registry in self.registry[pid]["reg_keys_process_handle"]:
                print "REGISTRY\t entry exists in reg_keys_process_handle"
                print "REGISTRY\t voeg de key in ^ (is een van de predefined) toe aan de subkey en sla die op in created"
                print "REGISTRY\t Zet de TID_Handle -> volledige key in reg_keys_process_handle"
                self.registry[pid]["reg_keys_created"][
                    self.registry[pid]["reg_keys_process_handle"][registry] + r'\\' + subkey] = 1
                self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = \
                    self.registry[pid]["predefined_key_handle"][registry] + r'\\' + subkey
            else:
                try:
                    print "REGISTRY\t entry does NOT exist in reg_keys_process_handle, de registry key is dus niet predefined"
                    print "REGISTRY\t Mogelijk is het dus opgeslagen uit vorige entries als TID_handle"
                    name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + registry]
                    self.registry[pid]["reg_keys_created"][name + r'\\' + subkey] = 1
                    self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = \
                        self.registry[pid]["reg_keys_process_handle"][thread_id_ + registry] + r'\\' + subkey
                except:
                    # Pech gehad
                    print "REGISTRY\t Pech gehad..."
                    if "RegCreateKeyEx" in self.anomalities:
                        self.anomalities["RegCreateKeyEx"].append(
                            "Could not find handle to open the subkey '" + subkey + "'")
                    else:
                        self.anomalities["RegCreateKeyEx"] = [
                            "Could not find handle to open the subkey '" + subkey + "'"]

                        # self.registry[pid]["reg_keys_created"][subkey] = 1
                        #self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = subkey

        # OPENING REGISTRY KEYS
        elif api == "NtOpenKey":
            path = arguments["ObjectAttributes"]
            self.registry[pid]["reg_keys_created"][path] = 1
            self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = path
        elif api == "NtOpenKeyEx":
            path = arguments["ObjectAttributes"]
            self.registry[pid]["reg_keys_created"][path] = 1
            self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = path
        elif api == "RegOpenKeyExA" or api == "RegOpenKeyExW":
            registry = arguments["Registry"]
            subkey = arguments["SubKey"]
            if registry in self.registry[pid]["reg_keys_process_handle"]:
                self.registry[pid]["reg_keys_created"][
                    self.registry[pid]["reg_keys_process_handle"][registry] + r'\\' + subkey] = 1
                self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = \
                    self.registry[pid]["predefined_key_handle"][registry] + r'\\' + subkey
            else:
                try:
                    name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + registry]
                    self.registry[pid]["reg_keys_created"][name + r'\\' + subkey] = 1
                    self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle] = \
                        self.registry[pid]["reg_keys_process_handle"][thread_id_ + registry] + r'\\' + subkey
                except:
                    # Pech gehad
                    if "RegOpenKeyEx" in self.anomalities:
                        self.anomalities["RegOpenKeyEx"].append(
                            "Could not find handle to open the subkey '" + subkey + "'")
                    else:
                        self.anomalities["RegOpenKeyEx"] = ["Could not find handle to open the subkey '" + subkey + "'"]

        # SETTING REGISTRY KEYS
        elif api == "NtSetValueKey":
            registry_name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]
            self.registry[pid]["reg_keys_values"][registry_name + r'\\' + arguments["ValueName"]] = arguments["Buffer"]

            event = {"type": "set", "key": registry_name + r'\\' + arguments["ValueName"], "value": arguments["Buffer"]}
        elif api == "RegSetValueExA" or api == "RegSetValueExW":
            try:
                registry_name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]
                self.registry[pid]["reg_keys_values"][registry_name + r'\\' + arguments["ValueName"]] = arguments[
                    "Buffer"]
                event = {"type": "set", "key": registry_name + r'\\' + arguments["ValueName"],
                         "value": arguments["Buffer"]}
            except:
                if "RegSetValueEx" in self.anomalities:
                    self.anomalities["RegSetValueEx"].append(
                        "Could not find handle '" + handle + " to safe', value = '" + arguments["Buffer"] + "'")
                else:
                    self.anomalities["RegSetValueEx"] = [
                        "Could not find handle '" + handle + " to safe', value = '" + arguments["Buffer"] + "'"]

        # CLOSING REGISTRY KEYS
        elif api == "RegCloseKey":
            if thread_id_ + handle in self.registry[pid]["reg_keys_process_handle"]:
                del self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]

        # DELETING REGISTRY KEYS
        elif api == "NtDeleteKey":
            registry_name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]  # Naam die bij handle hoort
            self.registry[pid]["reg_keys_deleted"][registry_name] = 1

            event = {"type": "deleted", "key": registry_name}
        elif api == "RegDeleteKeyA" or api == "RegDeleteKeyW":
            registry_name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]  # Naam die bij handle hoort
            self.registry[pid]["reg_keys_deleted"][registry_name + r'\\' + arguments["SubKey"]] = 1

            event = {"type": "deleted", "key": registry_name + r'\\' + arguments["SubKey"]}
        elif api == "RegDeleteValueA" or api == "RegDeleteValueW":
            try:
                name = self.registry[pid]["reg_keys_process_handle"][thread_id_ + handle]
            except:
                name = arguments["ValueName"]
            self.registry[pid]["reg_keys_deleted"][name + r'\\' + arguments["ValueName"]] = 1

            event = {"type": "deleted", "key": name + r'\\' + arguments["ValueName"]}

        return event


class Detecter(object):
    name = "Analyzer"

    def analyze_graph(self, graph):
        pass

    # Handy dandy methods for subclasses

    # Returns a list of all child vertex IDs (excl. vertex) 
    def get_childs_of_vertex(self, graph, vertex):
        childs = []
        # Recursively getting all childs of vertex
        child_vids = self.get_childs(graph, vertex.index)
        self.recursion_childs(graph, childs, child_vids)
        return childs

    def recursion_childs(self, graph, childs, child_vids):
        if len(child_vids) > 0:
            childs.extend(child_vids)
            for child_vid in child_vids:
                self.recursion_childs(graph, childs, self.get_childs(graph, child_vid))


    def get_childs(self, graph, vertex_id):
        childs = graph.neighbors(vertex_id, mode=OUT)
        print "Childs of VID %i:" % vertex_id
        print childs
        return childs
        
        


    # Returns a list of vertex IDs from the vertex to the root node (excl. vertex)
    def vertex_to_root(self, vertex):
        list_of_vertices = []
        print "Finding parent of vertex ID %i (PID %i)" % (vertex.index, vertex["pid"])
        parent_index = self.get_parent(vertex)
        print "Parent index is %i" % parent_index
        if parent_index:
            parent = vertex.graph.vs[parent_index]
            while(parent):
                list_of_vertices.append(parent.index)
                print "Finding parent of vertex ID %i (Process %i)" % (parent.index, parent["pid"])
                parent_index = self.get_parent(parent)
                print "Parent index is %i" % parent_index
                if parent_index:
                    parent = vertex.graph.vs[parent_index]
                else:
                    parent = False
        return list_of_vertices

    def get_parent(self, vertex):
        neighbors = vertex.graph.neighbors(vertex.index, mode=IN)
        # neighbors contains a list of vertex IDs
        if len(neighbors) == 1: # There should be just one incoming edge
            parent = neighbors[0]
            return parent
        else:
            print "List of neighbors is %i long" % len(neighbors)
            print "Process information of this vertex:"
            print "\tProcess ID: %i\n\tParent ID: %i\n\tProcess name:%s" % (vertex["pid"], vertex["data"]["parent_id"], vertex["data"]["name"])
            return False

class Subprocess_from_tab(Detecter):
    name = "Subprocess_from_tab"

    def analyze_graph(self, graph):
        return_value = {"malware_found":False,"graph":False}
        # Get all vertices of event "on_process_new"
        new_process_events = graph.vs.select(type_eq="on_process_new")
        for vertex in new_process_events:
            # Check process depth
            print "Getting vertices to root..."
            vertices_to_root = self.vertex_to_root(vertex)
            print vertices_to_root

            if len(vertices_to_root) > 1:
                # Oh oh, we found a process two levels deep or lower *runs around*
                print "Oh oh, we found a process two levels deep or lower *runs around*"
                return_value["malware_found"] = True

                # Create subgraph
                all_relevant_vertices = [vertex.index]
                all_relevant_vertices.extend(vertices_to_root)
                print "Getting list of all childs of vertex..."
                all_relevant_vertices.extend(self.get_childs_of_vertex(graph, vertex))
                print "Create subgraph..."
                print "Relevant subvertices:"
                print all_relevant_vertices
                if return_value["graph"]:
                    return_value["graph"].append(graph.subgraph(all_relevant_vertices))
                else:
                    return_value["graph"] = [graph.subgraph(all_relevant_vertices)]

                # TODO: We might find multiple processes like this, that we find interesting: show them all in one graph...
                # For now, let just break

        return return_value



def parse_handle(handle):
    if isinstance(handle, (str, unicode)) and handle[:2] == "0x":
        return int(handle, 16)
    else:
        return int(handle)


class AbstractEventProcessor(object):
    def __init__(self, event_handler=None):
        if not event_handler:
            event_handler = NullEventProcessor()

        self.event_handler = event_handler

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        self.event_handler.on_process_new(parent_id, process_name, process_id, first_seen)

    def on_process_finished(self, process_id):
        self.event_handler.on_process_finished(process_id)

    def on_api_call(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments,
                    call_id):
        self.event_handler.on_api_call(timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments,
                    call_id)

    def on_http_request(self, timestamp, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data):
        self.event_handler.on_http_request(timestamp, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data)

    def on_file_write(self, timestamp, process_id, thread_id, path, data, offset):
        self.event_handler.on_file_write(timestamp, process_id, thread_id, path, data, offset)

    def on_file_delete(self, timestamp, process_id, thread_id, path):
        self.event_handler.on_file_delete(timestamp, process_id, thread_id, path)

    def on_registry_set(self, timestamp, process_id, thread_id, key, value):
        self.event_handler.on_registry_set(timestamp, process_id, thread_id, key, value)

    def on_registry_delete(self, timestamp, process_id, thread_id, key):
        self.event_handler.on_registry_delete(timestamp, process_id, thread_id, key)

    def on_shell_execute(self, timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command):
        self.event_handler.on_shell_execute(timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command)

    def on_socket_connect(self, timestamp, process_id, thread_id, socket_id, ip, port):
        self.event_handler.on_socket_connect(timestamp, process_id, thread_id, socket_id, ip, port)

    def on_anomaly_detected(self, timestamp, process_id, subcategory, function_name):
        self.event_handler.on_anomaly_detected(process_id, subcategory, function_name)

class NullEventProcessor(AbstractEventProcessor):
    def __init__(self):
        pass

    def on_socket_connect(self, timestamp, process_id, thread_id, socket_id, ip, port):
        pass

    def on_shell_execute(self, timestamp, process_id, thread_id, return_status, working_directory, process_spawned,
                         command, classname, shell_command):
        pass

    def on_registry_set(self, timestamp, process_id, thread_id, key, value):
        pass

    def on_registry_delete(self, timestamp, process_id, thread_id, key):
        pass

    def on_process_finished(self, process_id):
        pass

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        pass

    def on_http_request(self, timestamp, process_id, thread_id, http_verb, http_url, http_request_data,
                        http_response_data):
        pass

    def on_file_write(self, timestamp, process_id, thread_id, path, data, offset):
        pass

    def on_file_delete(self, timestamp, process_id, thread_id, path):
        pass

    def on_api_call(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api,
                    arguments, call_id):
        pass

    def on_anomaly_detected(self, timestamp, process_id, subcategory, function_name):
        pass


class UnknownApiCallException(Exception):
    pass


class ApiStateException(Exception):
    pass


class EventAggregateProcessor(AbstractEventProcessor):
    def __init__(self, event_handler):
        super(EventAggregateProcessor, self).__init__(event_handler=event_handler)

        self.registry = Registry_Event_Handler()

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        super(EventAggregateProcessor, self).on_process_new(parent_id, process_name, process_id, first_seen)

        print "New process: {0} (pid: {1}, parent_id: {2})".format(process_name, process_id, parent_id)

    def on_api_call(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments,
                    call_id):
        super(EventAggregateProcessor, self).on_api_call(timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments, call_id)

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
            callback = self.__process_process_event
        elif category == "system":
            callback = self.__process_system_event
        elif category == "synchronization":
            callback = self.__process_ignored_event
        elif category == "device":
            callback = self.__process_ignored_event
        elif category == "services":
            callback = self.__process_ignored_event
        elif category == "__notification__":
            callback = self.__process_notification_event
        else:
            callback = self.__process_unknown_event

        callback(timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments, call_id)

    def on_file_delete(self, timestamp, process_id, thread_id, path):
        print "Delete {0}".format(path)
        super(EventAggregateProcessor, self).on_file_delete(timestamp, process_id, thread_id, path)

    def on_registry_set(self, timestamp, process_id, thread_id, key, value):
        print "REGISTRY SET: %s = %s" % (key, value)
        super(EventAggregateProcessor, self).on_registry_set(timestamp, process_id, thread_id, key, value)

    def on_registry_delete(self, timestamp, process_id, thread_id, key):
        print "REGISTRY DELETE: %s" % key
        super(EventAggregateProcessor, self).on_registry_delete(timestamp, process_id, thread_id, key)

    def on_shell_execute(self, timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command):
        print "SHELL COMMAND: %s" % command
        super(EventAggregateProcessor, self).on_shell_execute(timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command)

    def on_file_write(self, timestamp, process_id, thread_id, path, data, offset):
        print "Write data to {0}".format(path)
        super(EventAggregateProcessor, self).on_file_write(timestamp, process_id, thread_id, path, data, offset)

    def on_socket_connect(self, timestamp, process_id, thread_id, socket_id, ip, port):
        print "Connect to " + ip + ":" + str(port)
        super(EventAggregateProcessor, self).on_socket_connect(timestamp, process_id, thread_id, socket_id, ip, port)

    def on_http_request(self, timestamp, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data):
        print http_verb + " " + http_url
        super(EventAggregateProcessor, self).on_http_request(timestamp, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data)

    def on_anomaly_detected(self, timestamp, process_id, subcategory, function_name):
        print "Anomaly detected: %s of %s" % (subcategory, function_name)
        super(EventAggregateProcessor, self).on_anomaly_detected(timestamp, process_id, subcategory, function_name)

    @staticmethod
    def __process_unknown_event(timestamp, process_id, category, status, return_value, thread_id, repeated, api,
                                arguments, call_id):
        raise UnknownApiCallException("Unknown API category: " + category)

    @staticmethod
    def __process_ignored_event(timestamp, process_id, category, status, return_value, thread_id, repeated, api,
                                arguments, call_id):
        pass

    def __process_registry_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api,
                                 arguments, call_id):
        event = self.registry.on_api_call(process_id, category, status, return_value, timestamp, thread_id, repeated,
                                          api, arguments, call_id)
        if event:
            # Call on_registry_delete() or on_registry_set
            if event["type"] == "set":
                self.on_registry_set(timestamp, process_id, thread_id, event["key"], event["value"])
            elif event["type"] == "deleted":
                self.on_registry_delete(timestamp, process_id, thread_id, event["key"])

    def __process_socket_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api,
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

            self.on_socket_connect(timestamp, process_id, thread_id, socket_id, arguments["ip"], int(arguments["port"]))
        elif api == "closesocket" or api == "shutdown":
            socket_id = parse_handle(arguments["socket"])

            if socket_id not in __socket_state["sockets"]:
                # raise ApiStateException("Socket {0} is not yet created in this process!".format(socket_id))
                print "Socket {0} is not yet created in this process!".format(socket_id)
                return

            __socket_state["sockets"].remove(socket_id)

    def __process_network_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api,
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
                "data": "",
                "timestamp": timestamp
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

                self.on_http_request(__network_state["handle_state"][handle]["timestamp"], process_id, thread_id, http_verb, http_url, None, http_response_data)

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

    def __process_filesystem_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated,
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
                "path": arguments["FileName"],
                "data": "",
                "offset": 0,
                "timestamp": timestamp
            }
        elif api == "NtOpenFile":
            file_handle = parse_handle(arguments["FileHandle"])

            if file_handle in __filesystem_state["handles"]:
                # raise ApiStateException("FileHandle {0} is already created in this process!".format(file_handle))
                print "FileHandle {0} is already created in this process!".format(file_handle)
                return

            __filesystem_state["handles"].append(file_handle)
            __filesystem_state["handle_state"][file_handle] = {
                "path": arguments["FileName"],
                "data": "",
                "offset": 0,
                "timestamp": timestamp
            }
        elif api == "NtWriteFile":
            file_handle = parse_handle(arguments["FileHandle"])

            if file_handle not in __filesystem_state["handles"]:
                # raise ApiStateException("FileHandle {0} is already created in this process!".format(file_handle))
                print "FileHandle {0} is already created in this process!".format(file_handle)
                return

            __filesystem_state["handle_state"][file_handle]["data"] = \
                __filesystem_state["handle_state"][file_handle]["data"] + arguments["Buffer"]

            if int(arguments["OffsetLowPart"]) > 0:
                __filesystem_state["handle_state"][file_handle]["offset"] = int(arguments["OffsetLowPart"])
        elif api == "DeleteFileA" or api == "DeleteFileW":
            file_path = arguments["FileName"]

            self.on_file_delete(timestamp, process_id, thread_id, file_path)

    def __process_process_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated,
                               api, arguments, call_id):
        if api == "ShellExecuteExA" or api == "ShellExecuteExW":
            print "GRAPH: hhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufhuppelpufuppelpuf"
            process_spawned = arguments["ProcessSpawned"]
            working_directory = arguments["WorkingDirectory"]
            shell_command = arguments["FilePath"] + " " + arguments["Parameters"]
            command = arguments["Command"]
            classname = arguments["Class"]
            return_status = status
            self.on_shell_execute(timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command)

    def __process_system_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated,
                               api, arguments, call_id):
        __filesystem_state = self.__get_state_for_pid(process_id)["filesystem"]

        if api == "NtClose":
            file_handle = parse_handle(arguments["Handle"])

            if file_handle not in __filesystem_state["handles"]:  # Not all NtClose calls are related to the FS
                # raise ApiStateException("Handle {0} is not yet created in this process!".format(file_handle))
                return

            if len(__filesystem_state["handle_state"][file_handle]["data"]) > 0:
                self.on_file_write(__filesystem_state["handle_state"][file_handle]["timestamp"],
                                   process_id,
                                   thread_id,
                                   __filesystem_state["handle_state"][file_handle]["path"],
                                   __filesystem_state["handle_state"][file_handle]["data"],
                                   __filesystem_state["handle_state"][file_handle]["offset"])

            __filesystem_state["handles"].remove(file_handle)
            del __filesystem_state["handle_state"][file_handle]

    def __process_notification_event(self, timestamp, process_id, category, status, return_value, thread_id, repeated,
                               api, arguments, call_id):
        if api == "__anomaly__":
            self.on_anomaly_detected(timestamp, process_id, arguments["Subcategory"], arguments["FunctionName"])

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


class EventReorderProcessor(AbstractEventProcessor):
    def __init__(self, event_handler):
        super(EventReorderProcessor, self).__init__(event_handler)

        self._process_event_queue_list = {}

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        super(EventReorderProcessor, self).on_process_new(parent_id, process_name, process_id, first_seen)

        self._process_event_queue_list[process_id] = []

    def on_process_finished(self, process_id):
        while len(self._process_event_queue_list[process_id]):
            (timestamp, functor, args) = heapq.heappop(self._process_event_queue_list[process_id])

            functor(*args)

        super(EventReorderProcessor, self).on_process_finished(process_id)

    def on_file_write(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_file_write, (timestamp, process_id) + args))

    def on_file_delete(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_file_delete, (timestamp, process_id) + args))

    def on_http_request(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_http_request, (timestamp, process_id) + args))

    def on_registry_set(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_registry_set, (timestamp, process_id) + args))

    def on_registry_delete(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_registry_delete, (timestamp, process_id) + args))

    def on_shell_execute(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_shell_execute, (timestamp, process_id) + args))

    def on_socket_connect(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_file_write, (timestamp, process_id) + args))

    def on_anomaly_detected(self, timestamp, process_id, *args):
        heapq.heappush(self._process_event_queue_list[process_id], (timestamp, self.event_handler.on_anomaly_detected, (timestamp, process_id) + args))


class EventGraphGenerator(AbstractEventProcessor):
    # The Graph :D
    graph = Graph(directed=True)

    # Dictionaries to make lookups in the graph a lot faster
    latest_get_per_process = {} # Process ID -> Unique ID
    first_get_of_process = {} # Process ID -> Unique ID
    id_counter = 0

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        print "GRAPH: on_process_new(%s, %s, %s, %s)" % (parent_id, process_name, process_id, first_seen)
        # Check if parent process exists in graph
        try:
            print "GRAPH: finding process parent..."
            parents = self.graph.vs.select(pid_eq=parent_id).select(type_eq="on_process_new")
            print "GRAPH: at least it didn't crash..."
            if len(parents) == 1:
                print "GRAPH: Found the parent!"
                parent = parents[0]
                self.graph.add_vertex()
                vertex_id = len(self.graph.vs) - 1
                self.graph.vs[vertex_id]["id"] = self.id_counter
                self.graph.vs[vertex_id]["pid"] = process_id
                self.graph.vs[vertex_id]["thread_id"] = 0
                self.graph.vs[vertex_id]["type"] = "on_process_new"
                self.graph.vs[vertex_id]["label"] = "Process: " + process_name
                self.graph.vs[vertex_id]["data"] = {"name":process_name,"timestamp":first_seen,"parent_id":parent_id}

                print "GRAPH: Created vertex of new process"

                # Distinguish between Tab processes and process spawned in tabs
                # If it's a tab process then the name is "iexplore.exe" AND
                # the parent vertex has no incoming edges
                if parent.index == 0 and parent["data"]["name"] == "Cuckoo Analyzer":
                    print "GRAPH: The parent is the root and it's process name is 'Cuckoo Analyzer'"
                    # It's a tab process, hang it below the parent
                    self.graph.add_edges([(int(parent.index), int(vertex_id))])
                elif parent["data"]["name"] == "iexplore.exe" and len(parent.graph.neighbors(parent.index, mode=IN)) > 0:
                    print "GRAPH: parent heeft de naam 'iexplore.exe' en heeft incoming edges"
                    # It's a process spawned by a tab
                    # Hang it below the latest GET from this tab
                    latest_get_from_tab = self.find_latest_get_from_tab(parent_id) 
                    self.graph.add_edges([(int(latest_get_from_tab.index), int(vertex_id))])
                elif parent["data"]["name"] != "iexplore.exe":
                    print "GRAPH: parent is geen tabje..."
                    # Hang it directly below this process
                    self.graph.add_edges([(int(parent.index), int(vertex_id))])
                else:
                    print "GRAPH: Oh oh, I didn't cover this case..."
            else:
                print "GRAPH: Found more than one parent, say wut..."
        except KeyError as e:
            # The Graph is empty
            print "GRAPH: graph is empty..."

            # Make root node
            self.graph.add_vertex()
            self.graph.vs[0]["id"] = self.id_counter
            self.graph.vs[0]["pid"] = parent_id
            self.graph.vs[0]["thread_id"] = 0
            self.graph.vs[0]["type"] = "on_process_new"
            self.graph.vs[0]["label"] = "Process: " + str(parent_id)
            self.graph.vs[0]["data"] = {"name":"Cuckoo Analyzer","timestamp":first_seen,"parent_id":0}
            self.id_counter += 1

            # Make node of the tab/window
            self.graph.add_vertex()
            self.graph.vs[1]["id"] = self.id_counter
            self.graph.vs[1]["pid"] = process_id
            self.graph.vs[1]["thread_id"] = 0
            self.graph.vs[1]["type"] = "on_process_new"
            self.graph.vs[1]["label"] = "Process: " + process_name
            self.graph.vs[1]["data"] = {"name":process_name,"timestamp":first_seen,"parent_id":parent_id}

            # Create edge from root node to tab/window process
            self.graph.add_edges([(0, 1)])
            

        self.id_counter += 1

    def on_http_request(self, timestamp, process_id, thread_id, http_verb, http_url, http_request_data, http_response_data):
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_http_request"
        #self.graph.vs[vertex_id]["label"] = http_verb + " " + http_url
        self.graph.vs[vertex_id]["data"] = {"method":http_verb,"url":http_url,"request":http_request_data,"response":http_response_data}

        print self.first_get_of_process
        print self.latest_get_per_process
        if not process_id in self.latest_get_per_process:
            print "GRAPH: There hasn't been an HTTP request yet"
            # There hasn't been an HTTP Request yet...
            # Hang it below the "on_process_new"

            # Lookup "on_process_new" met dezelfde process_id
            parents = self.graph.vs.select(pid_eq=process_id).select(type_eq="on_process_new")
            if len(parents) == 1:
                parent = parents[0]
                
                # Create edge
                self.graph.add_edges([(int(parent.index), int(vertex_id))])
            
            self.first_get_of_process[process_id] = self.id_counter
        else:
            # There was already a HTTP Request
            # Hang it below this first HTTP Request
            
            # Find that first HTTP request
            uid = self.first_get_of_process[process_id]
            vertexseq = self.graph.vs.select(id_eq=uid)
            if len(vertexseq) == 1:
                first_http = vertexseq[0]
                
                # Created edge
                self.graph.add_edges([(int(first_http.index), int(vertex_id))])
                        

        # Update dict met laatste HTTP request
        self.latest_get_per_process[process_id] = self.id_counter
        self.id_counter += 1

    def on_file_write(self, timestamp, process_id, thread_id, path, data, offset):
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_file_write"
        #self.graph.vs[vertex_id]["label"] = "Written to " + path
        self.graph.vs[vertex_id]["data"] = {"path":path,"data":data,"offset":offset}

        # Put it under the latest HTTP Request
        # or directly under the process if there was no HTTP Request
        self.put_under_http_or_process(process_id, vertex_id)

        self.id_counter += 1

    def on_file_delete(self, timestamp, process_id, thread_id, path):
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_file_delete"
        #self.graph.vs[vertex_id]["label"] = "Deleted file " + path
        self.graph.vs[vertex_id]["data"] = {"path":path}

        self.put_under_http_or_process(process_id, vertex_id)

        self.id_counter += 1

    def on_registry_set(self, timestamp, process_id, thread_id, key, value):
        if process_id in [3984, 3952, 3820, 2304]:
            print "GRAPH: on_registry_set: Subnode for malicious processes"
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_registry_set"
        #self.graph.vs[vertex_id]["label"] = key + " = " + value
        self.graph.vs[vertex_id]["data"] = {"key":key,"value":value}

        # Put it under the latest HTTP Request
        # or directly under the process if there was no HTTP Request
        self.put_under_http_or_process(process_id, vertex_id)

        self.id_counter += 1

    def on_registry_delete(self, timestamp, process_id, thread_id, key):
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_registry_delete"
        #self.graph.vs[vertex_id]["label"] = "DELETE " + key
        self.graph.vs[vertex_id]["data"] = {"key":key}

        # Put it under the latest HTTP Request
        # or directly under the process if there was no HTTP Request
        self.put_under_http_or_process(process_id, vertex_id)

        self.id_counter += 1

    def on_socket_connect(self, timestamp, process_id, thread_id, socket_id, ip, port):
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_socket_connect"
        self.graph.vs[vertex_id]["label"] = str(ip) + ":" + str(port)
        self.graph.vs[vertex_id]["data"] = {"socket_id":socket_id,"ip":ip,"port":port}

        self.put_under_http_or_process(process_id, vertex_id)

        self.id_counter += 1


    def on_shell_execute(self, timestamp, process_id, thread_id, return_status, working_directory, process_spawned, command, classname, shell_command):
        if process_id == 3820:
            print "GRAPH: dfshjsdgjhsdfhjkdhjkdgqhjdsfhjkdsghjkldfghjkdfghjdfgjhkdfghjk"
        # Create vertex
        self.graph.add_vertex()
        vertex_id = len(self.graph.vs) - 1
        self.graph.vs[vertex_id]["id"] = self.id_counter
        self.graph.vs[vertex_id]["pid"] = process_id
        self.graph.vs[vertex_id]["thread_id"] = thread_id
        self.graph.vs[vertex_id]["type"] = "on_shell_execute"
        self.graph.vs[vertex_id]["label"] = shell_command
        self.graph.vs[vertex_id]["data"] = {
            "Command":shell_command,
            "return_status":return_status,
            "working_directory":working_directory,
            "process_spawned":process_spawned,
            "class":classname,
            "cmd":command
        }

        self.put_under_http_or_process(process_id, vertex_id)
        
        self.id_counter += 1
                
    def find_latest_get_from_tab(self, pid):
        uid = self.latest_get_per_process[pid]
        matches = self.graph.vs.select(id_eq=uid)
        if len(matches) == 1:
            return matches[0]
        else:
            raise Exception("Unique ID not found")

    def put_under_http_or_process(self, process_id, vertex_id):
        if process_id in [3984, 3952, 3820, 2304]:
            print "GRAPH: Subnode for malicious processes"
        # HTTP Request already exists
        if process_id in self.latest_get_per_process:
            if process_id in [3984, 3952, 3820, 2304]:
                print "GRAPH: \tuhu"
            uid = self.latest_get_per_process[process_id]
            vertexseq = self.graph.vs.select(id_eq=uid)
            if len(vertexseq) == 1:
                get_request = vertexseq[0]
                self.graph.add_edges([(int(get_request.index), int(vertex_id))])
        else: # No HTTP Request has been seen for this process :(
            if process_id in [3984, 3952, 3820, 2304]:
                print "GRAPH: \tuhu"
            parents = self.graph.vs.select(pid_eq=process_id).select(type_eq="on_process_new")
            if len(parents) == 1:
                parent = parents[0]
                self.graph.add_edges([(int(parent.index), int(vertex_id))])
 
    def get_graph(self):
        return self.graph

class LogProcessorException(Exception):
    pass


class AbstractLogProcessor:
    def __init__(self, task_id, event_handler):
        self.task_id = task_id
        self.event_handler = event_handler

    def has_more_events(self):
        pass

    def parse_events(self, max_events_to_process=-1):
        pass


class AbstractLogProcessorEventHandler:
    def __init__(self):
        pass

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        pass

    def on_process_finished(self, process_id):
        pass

    def on_api_call(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments,
                    call_id):
        pass

class BSONLogProcessor(AbstractLogProcessor):
    def __init__(self, task_id, event_handler):
        AbstractLogProcessor.__init__(self, task_id, event_handler)

        self._processes = Processes(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "logs"))
        self._processes_data = self._processes.run()

        if len(self._processes_data) == 0:
            raise LogProcessorException("No processes found!")

        self._current_process_index = 0
        self._current_process_event_index = 0

        self.current_process_data = self._processes_data[self._current_process_index]
        self.current_process_call_parser = self.current_process_data["calls"]

    def has_more_events(self):
        if self._current_process_index < len(self._processes_data):
            return True

        return False

    def parse_events(self, max_events_to_process=-1):
        # Report new process
        if self._current_process_event_index == 0:
            self.event_handler.on_process_new(self.current_process_data["parent_id"],
                                              self.current_process_data["process_name"],
                                              self.current_process_data["process_id"],
                                              self.current_process_data["first_seen"])

        try:
            while True:
                if max_events_to_process == -1 or max_events_to_process > 0:
                    current_process_call = self.current_process_call_parser.next()

                    self.event_handler.on_api_call(current_process_call["timestamp"],
                                                   self.current_process_data["process_id"],
                                                   current_process_call["category"],
                                                   current_process_call["status"],
                                                   current_process_call["return"],
                                                   current_process_call["thread_id"],
                                                   current_process_call["repeated"],
                                                   current_process_call["api"],
                                                   current_process_call["arguments"],
                                                   current_process_call["id"])

                    self._current_process_event_index += 1
                    max_events_to_process -= 1
                else:
                    return
        except StopIteration:
            pass

        self.event_handler.on_process_finished(self.current_process_data["process_id"])

        # All calls are processed
        self._current_process_index += 1

        # Update pointers to next
        if self._current_process_index < len(self._processes_data):
            self._current_process_event_index = 0

            self.current_process_data = self._processes_data[self._current_process_index]
            self.current_process_call_parser = self.current_process_data["calls"]


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
            self.event_handler.on_process_new(self.current_process_data["parent_id"],
                                              self.current_process_data["process_name"],
                                              self.current_process_data["process_id"],
                                              self.current_process_data["first_seen"])

        while self.current_process_calls_index < self.current_process_calls_len:
            current_process_call = self.current_process_calls[self.current_process_calls_index]

            if max_events_to_process == -1 or max_events_to_process > 0:
                self.event_handler.on_api_call(current_process_call["timestamp"],
                                               self.current_process_data["process_id"],
                                               current_process_call["category"],
                                               current_process_call["status"],
                                               current_process_call["return"],
                                               current_process_call["thread_id"],
                                               current_process_call["repeated"],
                                               current_process_call["api"],
                                               current_process_call["arguments"],
                                               current_process_call["id"])

                self.current_process_calls_index += 1
                max_events_to_process -= 1
            else:
                return

        self.event_handler.on_process_finished(self.current_process_data["process_id"])

        # All calls are processed
        self.processed_pids.append(self.current_process_data["process_id"])

        self.process_data_index += 1

        # Update pointers to next
        if self.process_data_index < self.process_data_len:
            self.current_process_data = self.process_data[self.process_data_index]

            self.current_process_calls = self.current_process_data["calls"]
            self.current_process_calls_index = 0
            self.current_process_calls_len = len(self.current_process_calls)


class EventLogPreProcessHandler(AbstractLogProcessorEventHandler):
    def __init__(self, event_handler):
        self.event_handler = event_handler

    def on_process_new(self, parent_id, process_name, process_id, first_seen):
        self.event_handler.on_process_new(parent_id, process_name, process_id, first_seen)

    def on_process_finished(self, process_id):
        self.event_handler.on_process_finished(process_id)

    def on_api_call(self, timestamp, process_id, category, status, return_value, thread_id, repeated, api, arguments,
                    call_id):
        new_arguments = {}
        for arg in arguments:
            new_arguments[arg["name"]] = arg["value"]

        self.event_handler.on_api_call(timestamp, process_id, category, status, return_value, thread_id, repeated,
                                       api, new_arguments, call_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="File with URLs to process.")
    parser.add_argument("-j", "--json", help="Use the JSON files instead of the BSON files", action="store_true", required=False)
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
            print(bold(red("Error")) + ": " + str(task_id) + " is not a valid task id")
            return False

        task_id = int(task_id)

        if not db.view_task(task_id):
            print(bold(red("Error")) + ": " + str(task_id) + " is not a valid task")
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

        with open(file_name, "r") as f:
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

    graph_generator = EventGraphGenerator()
    process_chain = EventLogPreProcessHandler(EventAggregateProcessor(EventReorderProcessor(graph_generator)))

    if args.json:
        log_processor = JSONLogProcessor(task_id, process_chain)
    else:
        log_processor = BSONLogProcessor(task_id, process_chain)

    while log_processor.has_more_events():
        log_processor.parse_events()

    # Get the graph
    graph = graph_generator.get_graph()
    color_dict = {
        "on_file_delete": "blue",
        "on_file_write": "blue", 
        "on_socket_connect":"red",
        "on_process_new":"red",
        "on_registry_delete":"green",
        "on_registry_set":"green",
        "on_http_request":"yellow",
        "on_shell_execute":"red"
    }
    
    # Run Analyzers
    for analyzer in [Subprocess_from_tab()]:
        results = analyzer.analyze_graph(graph)
        if results["malware_found"]:
            print "Analyzer '%s' found:" % analyzer.name
            # Show subgraph with relevant data
            if results["graph"]:
                for subgraph in results["graph"]:
                    subgraph.vs["color"] = [color_dict[typez] for typez in subgraph.vs["type"]]
                    layout_graph = subgraph.layout("kk")
                    plot(subgraph, bbox=(3000,3000), layout=layout_graph)
        else:
            print "Analyzer '%s' did not find anything interesting." % analyzer.name
        
    # Show graph - used for debugging right now...
    dot_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", "report.dot")
    pdf_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", "report.pdf")

    graph.vs["color"] = [color_dict[typez] for typez in graph.vs["type"]]
    graph.write(dot_path)

    os.system("sfdp -Goverlap=prism -Tpdf -o {1} {0}".format(dot_path, pdf_path))

    layout_graph = graph.layout("kk")
    plot(graph, bbox=(3000,3000), layout=layout_graph)

if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
