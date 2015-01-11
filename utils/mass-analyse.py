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

    def parse_events(self, max_events_to_process):
        # Report new process
        if self.current_process_calls_index == 0:
            self.event_handler.on_new_process(self.current_process_data["parent_id"],
                                              self.current_process_data["process_name"],
                                              self.current_process_data["process_id"],
                                              self.current_process_data["first_seen"])

        while self.current_process_calls_index < self.current_process_calls_len:
            current_process_call = self.current_process_calls[self.current_process_calls_index]

            if max_events_to_process > 0:
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

    dag_event_handler = DAG_Generator()

    log_processor = JSONLogProcessor(task_id, DAGLogProcessorEventHandler(dag_event_handler))

    while log_processor.has_more_events():
        log_processor.parse_events(100)

    print dag_event_handler.no_more_events()


if __name__ == "__main__":
    cfg = Config()

    try:
        main()
    except KeyboardInterrupt:
        pass
