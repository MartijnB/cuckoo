#!/usr/bin/env python

import argparse
import json
import logging

import os
import sys
import time

from igraph import *

logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING
from lib.cuckoo.core.startup import init_modules
from lib.cuckoo.common.colors import bold, red, green, yellow


class DAG_Generator(object):
    def new_process(self, parent_id, process_name, process_id, first_seen):
        '''Call this when a new process spawns'''
        pass

    def event_happened(self, event, pid):
        '''Call this for every event that happens.
                   event: expects a call dict
                   pid: the pid where the call happened'''
        pass

    def no_more_events(self):
        '''When Cuckoo stops or something, call this so I can return the DAG'''
        pass

class Event_Checker(object):                                                                         
        def crunch_call(self, event):                                                                
                '''Do the work'''                                                                    
                raise NotImplementedError

class Thread_Checker(object):
	threads = {}

	def crunch_call(self, event):
		'''Aggregate all calls under a thread'''
		if self.threads.has_key(event["thread_id"]):
			self.threads[event["thread_id"]].append(event)
		else:
			self.threads[event["thread_id"]] = [event]
	
	def get_datastructure(self):
		return self.threads

class Process_Tracker(object):
        def __init__(self, parent_id, process_name, process_id, first_seen):
                self.parent_id = parent_id
                self.process_name = process_name
                self.process_id = process_id
                self.first_seen = first_seen

                self.event_checkers = self.get_list_of_checkers()

                self.datastructure = {}
                                                                                                     
        def get_list_of_checkers(self):                                                              
                # For now, every process tracks everything but we can filter this                    
                # if we want...                                                                      
                checkers = [Thread_Checker()]
                return checkers                                                                      
                                                                                                     
        def event(self, event):                                                                      
                # Because multiple checkers might want to have access to the                         
                # same calls, we send every event to every checker                                   
                for checker in self.event_checkers:                                                  
                        returnvalue = checker.crunch_call(event)                                     
                        # If returnvalue                                                             
                                                                                                     
        def get_graph(self):                                                                         
                self.clean_up()                                                                           
                return self.datastructure                                                            
                                                                                                     
        def clean_up(self):                                                                          
		for checker in self.event_checkers:
			self.datastructure = checker.get_datastructure()

class Improved_Process_Tracker(object):
        def __init__(self, parent_id, process_name, process_id, first_seen):
                self.parent_id = parent_id
                self.process_name = process_name
                self.process_id = process_id
                self.first_seen = first_seen

                self.event_checkers = self.get_list_of_checkers()

                self.datastructure = {}
                                                                                                     
        def get_list_of_checkers(self):                                                              
                # For now, every process tracks everything but we can filter this                    
                # if we want...                                                                      
                checkers = [Thread_Checker()]
                return checkers                                                                      
                                                                                                     
        def event(self, event):                                                                      
                # Because multiple checkers might want to have access to the                         
                # same calls, we send every event to every checker                                   
                for checker in self.event_checkers:                                                  
                        returnvalue = checker.crunch_call(event)                                     
                        # If returnvalue                                                             
                                                                                                     
        def get_graph(self):                                                                         
                self.clean_up()                                                                           
                return self.datastructure                                                            
                                                                                                     
        def clean_up(self):                                                                          
		for checker in self.event_checkers:
			self.datastructure = checker.get_datastructure()

def Event(object):
	pass

def HTTP_Event(Event):
	pass

def File_Event(Event):
	pass

def Registry_Event(Event):
	pass
			
class Event_Based_DAG_Generator(DAG_Generator):
	events = {}
	graph = Graph()
	
        def new_process(self, parent_id, process_name, process_id, first_seen):
                self.processes[process_id] = Process_Tracker(parent_id, process_name, process_id, first_seen)
                # Put process in the graph, at the right place...
                # Check if parent exists in graph
                try:
                        parents = self.graph.vs.select(pid_eq=parent_id)
                        if len(parents) == 1:
                                parent = parents[0]
                                self.graph.add_vertex()
                                vertex_id = len(self.graph.vs) - 1
                                self.graph.vs[vertex_id]["pid"] = process_id
                                self.graph.vs[vertex_id]["parent_id"] = parent_id
                                self.graph.vs[vertex_id]["process_name"] = process_name
                                self.graph.vs[vertex_id]["first_seen"] = first_seen

                                self.graph.add_edges([(int(parent.index), int(vertex_id))])
                except Exception, e:
			print e
                        # The Graph is empty
                        print "The graph is empty..."
                        print "Create first vertex"
                        self.graph.add_vertex()
                        self.graph.vs[0]["pid"] = process_id
                        self.graph.vs[0]["parent_id"] = parent_id
                        self.graph.vs[0]["process_name"] = process_name
                        self.graph.vs[0]["first_seen"] = first_seen

		print self.graph


        def event_happened(self, event, pid):
                self.processes[pid].event(event)

        def no_more_events(self):
                self.clean_up()
                return self.graph

        def clean_up(self):
                for key in self.processes.iterkeys():
                        process_datastructure = self.processes[key].get_graph()
			pid_process = self.processes[key].process_id
			print "### PROCESS %s ###" % pid_process
			vertexseq = self.graph.vs.select(pid_eq=pid_process)
			if len(vertexseq) == 1:
				# Get ID of parent to make an edge
				vertex_id_process = vertexseq[0].index

			# For each Thread make a vertex
			for thread_id in process_datastructure.iterkeys():
				different_calls = {}
				self.graph.add_vertex()
				vertex_id = len(self.graph.vs) - 1
				self.graph.vs[vertex_id]["pid"] = thread_id
				self.graph.add_edges([(int(vertex_id_process), int(vertex_id))])
				for call in process_datastructure[thread_id]:
					if different_calls.has_key(call["api"]):
						# De vertex en edge bestaan al, zoek de vertex op en verhoog de count
						#wowz = str(thread_id) + "_" + call["api"] + "_" + str(different_calls[call["api"]])
						#matches = self.graph.vs.select(pid_eq=wowz)
						#vertex_api = ""
						#if len(matches) == 1:
						#	vertex_api = matches[0]
						#else:
						#	print "Geen matches gevonden"
						#different_calls[call["api"]] += 1
						#dfd = str(thread_id) + "_" + call["api"] + "_" + str(different_calls[call["api"]])
						#print "Thread %s: call %s happened %i times" % (thread_id, call["api"], different_calls[call["api"]])
						#vertex_api["pid"] = dfd
						a = 2
					else: # It's an API call we haven't seen before
						self.graph.add_vertex()
						vertex_id_call = len(self.graph.vs) - 1
						print "Thread %s: call %s happened for the first time! Vertex %i" % (thread_id, call["api"], vertex_id_call)
						self.graph.vs[vertex_id_call]["pid"] = thread_id + "_" + call["api"]# + "_" + str(1)
						different_calls[call["api"]] = 1
						self.graph.add_edges([(int(vertex_id), int(vertex_id_call))])

class Thread_Based_DAG_Generator(DAG_Generator):
        processes = {}
        graph = Graph()

        def new_process(self, parent_id, process_name, process_id, first_seen):
                self.processes[process_id] = Process_Tracker(parent_id, process_name, process_id, first_seen)
                # Put process in the graph, at the right place...
                # Check if parent exists in graph
                try:
                        parents = self.graph.vs.select(pid_eq=parent_id)
                        if len(parents) == 1:
                                parent = parents[0]
                                self.graph.add_vertex()
                                vertex_id = len(self.graph.vs) - 1
                                self.graph.vs[vertex_id]["pid"] = process_id
                                self.graph.vs[vertex_id]["parent_id"] = parent_id
                                self.graph.vs[vertex_id]["process_name"] = process_name
                                self.graph.vs[vertex_id]["first_seen"] = first_seen

                                self.graph.add_edges([(int(parent.index), int(vertex_id))])
                except Exception, e:
			print e
                        # The Graph is empty
                        print "The graph is empty..."
                        print "Create first vertex"
                        self.graph.add_vertex()
                        self.graph.vs[0]["pid"] = process_id
                        self.graph.vs[0]["parent_id"] = parent_id
                        self.graph.vs[0]["process_name"] = process_name
                        self.graph.vs[0]["first_seen"] = first_seen

		print self.graph


        def event_happened(self, event, pid):
                self.processes[pid].event(event)

        def no_more_events(self):
                self.clean_up()
                return self.graph

        def clean_up(self):
                for key in self.processes.iterkeys():
                        process_datastructure = self.processes[key].get_graph()
			pid_process = self.processes[key].process_id
			print "### PROCESS %s ###" % pid_process
			vertexseq = self.graph.vs.select(pid_eq=pid_process)
			if len(vertexseq) == 1:
				# Get ID of parent to make an edge
				vertex_id_process = vertexseq[0].index

			# For each Thread make a vertex
			for thread_id in process_datastructure.iterkeys():
				different_calls = {}
				self.graph.add_vertex()
				vertex_id = len(self.graph.vs) - 1
				self.graph.vs[vertex_id]["pid"] = thread_id
				self.graph.add_edges([(int(vertex_id_process), int(vertex_id))])
				for call in process_datastructure[thread_id]:
					if different_calls.has_key(call["api"]):
						# De vertex en edge bestaan al, zoek de vertex op en verhoog de count
						#wowz = str(thread_id) + "_" + call["api"] + "_" + str(different_calls[call["api"]])
						#matches = self.graph.vs.select(pid_eq=wowz)
						#vertex_api = ""
						#if len(matches) == 1:
						#	vertex_api = matches[0]
						#else:
						#	print "Geen matches gevonden"
						#different_calls[call["api"]] += 1
						#dfd = str(thread_id) + "_" + call["api"] + "_" + str(different_calls[call["api"]])
						#print "Thread %s: call %s happened %i times" % (thread_id, call["api"], different_calls[call["api"]])
						#vertex_api["pid"] = dfd
						a = 2
					else: # It's an API call we haven't seen before
						self.graph.add_vertex()
						vertex_id_call = len(self.graph.vs) - 1
						print "Thread %s: call %s happened for the first time! Vertex %i" % (thread_id, call["api"], vertex_id_call)
						self.graph.vs[vertex_id_call]["pid"] = thread_id + "_" + call["api"]# + "_" + str(1)
						different_calls[call["api"]] = 1
						self.graph.add_edges([(int(vertex_id), int(vertex_id_call))])
				

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

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments, call_id):
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
        self.dag_event_handler = dag_event_handler

    def on_new_process(self, parent_id, process_name, process_id, first_seen):
        log.info("New process: {0} (pid: {1}, parent_id: {2})".format(process_name, process_id, parent_id))

        self.dag_event_handler.new_process(parent_id, process_name, process_id, first_seen)

    def on_api_call(self, process_id, category, status, return_value, timestamp, thread_id, repeated, api, arguments, call_id):
        self.dag_event_handler.event_happened({
            "category": category,
            "status": status,
            "return": return_value,
            "timestamp": timestamp,
            "thread_id": thread_id,
            "repeated": repeated,
            "api": api,
            "arguments": arguments,
            "id": call_id
        }, process_id)


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

    dag_event_handler = Thread_Based_DAG_Generator()

    log_processor = JSONLogProcessor(task_id, DAGLogProcessorEventHandler(dag_event_handler))

    while log_processor.has_more_events():
        log_processor.parse_events()

    graph = dag_event_handler.no_more_events()
    graph.vs["label"] = graph.vs["pid"]
    #layout_graph = graph.layout("rt")
    layout_graph = graph.layout("kk")
    plot(graph, "~/Desktop/amazing.png", bbox=(9999,9999), layout=layout_graph)


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
