# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

import collections
import logging
import time
import thread
import random

import comtypes
import comtypes.client

from _ctypes import COMError

import _winreg

MAX_TABS = 10

LOADING_TIMEOUT = 30
READY_TIMEOUT = 15

# http://msdn.microsoft.com/en-us/library/aa768360%28v=vs.85%29.aspx
NAV_OPEN_IN_NEW_TAB = 0x0800
NAV_OPEN_NEW_FOREGROUND_TAB = 0x10000

# http://msdn.microsoft.com/en-us/library/bb268228%28v=vs.85%29.aspx
READYSTATE_UNINITIALIZED = 0,
READYSTATE_LOADING = 1,
READYSTATE_LOADED = 2,
READYSTATE_INTERACTIVE = 3,
READYSTATE_COMPLETE = 4

# http://msdn.microsoft.com/en-us/library/windows/desktop/bb762153%28v=vs.85%29.aspx
SW_SHOW = 5

log = logging.getLogger(__name__)


class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def __init__(self, options={}):
        super(IE, self).__init__(options)

        self._open_tab_data = {}
        self._url_queue = collections.deque()
        self._wait_for_tab = False

        # Force the usage of 1 tab / process
        _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, "Software\Microsoft\Internet Explorer\Main")
        registry_key = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, "Software\Microsoft\Internet Explorer\Main", 0,
                                       _winreg.KEY_WRITE)
        _winreg.SetValueEx(registry_key, "TabProcGrowth", 0, _winreg.REG_DWORD, 0)
        _winreg.CloseKey(registry_key)

    def _check_url_list(self):
        try:
            # This is mainly used to wait for the initial tab.
            if self._wait_for_tab:
                log.debug("Waiting for browser window to open...")

                if self._get_open_tab_count() > 0:
                    for i in range(self._get_open_tab_count()):
                        ie_com_object = self._get_shell_windows_object().Item(i)

                        if ie_com_object:
                            self._wait_for_tab = False

                return True

            if len(self._url_queue) > 0 or self._get_open_tab_count() > 0:
                # Check the current open tabs and close them if needed
                self._check_tabs_and_close_after_timeout()

                # Sometimes call Quit() on a tab doesn't work (for example when a blocking UI dialog is open)
                # so we have to recheck how many tabs are actually open instead of relying on the amount of Quit() calls
                open_tab_count = self._get_open_tab_count()

                # Make sure the amount of open tabs is equal to MAX_TABS
                tabs_to_open = MAX_TABS - open_tab_count

                if len(self._url_queue) > 0 and tabs_to_open > 0:
                    log.info("Open (max) {0} new tab(s)".format(tabs_to_open))

                    while tabs_to_open > 0 and len(self._url_queue) > 0:
                        result_code = self._open_new_tab(self._url_queue.popleft(), tabs_to_open == MAX_TABS)

                        if not isinstance(result_code, bool):  # Return new pid
                            self._wait_for_tab = True

                            return result_code

                        tabs_to_open -= 1

                return True
            else:
                log.info("URL queue empty; all urls processed")

                return False

        except COMError as e:
            log.warning("COMError: {0}".format(e))
            pass
        except Exception as e:  # We can't accept that it would crash for some stupid reason,
            log.warning("Exception: {0}".format(e))  # so log Exceptions and ignore them
            pass

        return True

    def start(self, url):
        # If the url list contains only a single element, treat it as a normal url
        if isinstance(url, list) and len(url) == 1:
            url = url[0]

        if isinstance(url, list):
            # Turn the url list into a queue
            for u in url:
                # Force it to ascii as unicode strings gives issues later on with the starting of the process
                self._url_queue.append(u.encode('ascii', errors='backslashreplace'))

            # The default debug level generates way too much noise
            comtypes.logger.setLevel(logging.INFO)

            random.shuffle(self._url_queue)

            # Overrule the default check method with a custom implementation that executes the url list queue
            self.check = self._check_url_list
        else:
            iexplore = self.get_path("Internet Explorer")
            return self.execute(iexplore, "\"%s\"" % url)

    def _get_shell_windows_object(self):
        if not hasattr(self, "_shell_windows_object"):
            # IShellWindows (http://msdn.microsoft.com/en-us/library/windows/desktop/cc836570%28v=vs.85%29.aspx)
            self._shell_windows_object = comtypes.client.CreateObject("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}")

        return self._shell_windows_object

    def _get_open_tab_count(self):
        return self._get_shell_windows_object().Count

    def _check_tabs_and_close_after_timeout(self):
        for i in range(self._get_open_tab_count()):
            open_tab = self._get_shell_windows_object().Item(i)

            # Test if the tab still exists
            if open_tab is None:
                continue

            # Some sites have crap in their title
            website_title = open_tab.LocationName.encode('ascii', errors='backslashreplace')

            # log.debug("Found tab: " + website_title)

            if open_tab.LocationURL not in self._open_tab_data:
                self._open_tab_data[open_tab.LocationURL] = {
                    "status": open_tab.ReadyState,
                    "time": time.time()
                }

            if self._open_tab_data[open_tab.LocationURL]["status"] != open_tab.ReadyState:
                log.debug("Tab status changed to {0}".format(self._status_for_readystate(open_tab.ReadyState)))

                self._open_tab_data[open_tab.LocationURL]["status"] = open_tab.ReadyState
                self._open_tab_data[open_tab.LocationURL]["time"] = time.time()
            elif self._open_tab_data[open_tab.LocationURL]["status"] != READYSTATE_COMPLETE \
                    and (time.time() - self._open_tab_data[open_tab.LocationURL]["time"]) >= LOADING_TIMEOUT:
                log.info("Analysis timeout; close tab")

                open_tab.Stop()
                open_tab.Quit()
            elif self._open_tab_data[open_tab.LocationURL]["status"] == READYSTATE_COMPLETE \
                    and (time.time() - self._open_tab_data[open_tab.LocationURL]["time"]) >= READY_TIMEOUT:
                log.info("Analysis completed; close tab")

                open_tab.Stop()
                open_tab.Quit()

    @staticmethod
    def _nav_to_url(url):
        comtypes.CoInitialize()

        # We can't use _get_shell_windows_object as COM objects are thread specific
        shell_windows_object = comtypes.client.CreateObject("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}")

        for i in range(shell_windows_object.Count):
            ie_com_object = shell_windows_object.Item(i)

            if not ie_com_object:
                continue

            ie_com_object.Navigate(url, NAV_OPEN_IN_NEW_TAB)
            return

    def _open_new_tab(self, url, open_new_window):
        log.info("Open {0}".format(url))

        if open_new_window:
            log.info("Create new Internet Explorer window")

            iexplore = self.get_path("Internet Explorer")
            return self.execute(iexplore, "-noframemerging \"%s\"" % url)
        else:
            # for i in range(self._get_open_tab_count()):
            #     ie_com_object = self._get_shell_windows_object().Item(i)
            #
            #     if not ie_com_object:
            #         continue
            #
            #     # IWebBrowser2.Navigate() is a blocking COM call and require the full startup of the child process.
            #     # As this depends on the confirmation of the PipeServer that is waiting on the release of
            #     # PROCESS_LOCK this results in a deadlock.
            #     thread.start_new_thread(self._nav_to_url, (url,))
            #
            #     return False
            #
            # log.warning("Window not found; create a new one")
            #
            # # This should NEVER happen. But for some reason, we failed to find a valid reference to an existing IE window
            # return self._open_new_tab(url, True)

            iexplore = self.get_path("Internet Explorer")
            return self.execute(iexplore, "-noframemerging \"%s\"" % url)

    @staticmethod
    def _status_for_readystate(readystate):
        if readystate == READYSTATE_UNINITIALIZED:
            return "Uninitialized"
        elif readystate == READYSTATE_LOADING:
            return "Loading"
        elif readystate == READYSTATE_LOADED:
            return "Loaded"
        elif readystate == READYSTATE_INTERACTIVE:
            return "Interactive"
        elif readystate == READYSTATE_COMPLETE:
            return "Complete"
        else:
            return "UNKNOWN"