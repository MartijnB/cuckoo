# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package

class IE(Package):
    """Internet Explorer analysis package."""

    PATHS = [
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]

    def start(self, url):
        # If the url list contains only a single element, treat it as a normal url
        if isinstance(url, list) and len(url) == 1:
            url = url[0]

        iexplore = self.get_path("Internet Explorer")

        if isinstance(url, list):
            pass
        else:
            return self.execute(iexplore, "\"%s\"" % url)