# yalec - Yet Another Let's Encrypt Client
# Copyright (C) 2016 Falk Garbsch
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#

from pycurl import Curl
from cStringIO import StringIO

import logging
from encoding import consoleCleanBinary

class HttpProviderCurl(object):
    """
    Abstracts the HTTP interface to allow replacing the library used for
    connecting by something differend from pycurl.
    """
    def __init__(self, url):
        """
        Constructs a new class.
        
        @param url: The url to access by the HttpProvider.
        """
        logging.debug("create HttpProviderCurl for %s" % (url))
        self.__url = url
        self.__response = 0
        self.__header = []
        self.__data = StringIO()
    
    def prepareGet(self, moreHeader = []):
        """
        Prepares a HTTP GET request for the URL provided during initialization.
        
        @param moreHeader: An optional list of headers to be appended to the
            HTTP requests headers. This list must contain string values of the
            form <param>: <value> as they are directly injected into the HTTP
            header.
        """
        logging.debug("prepare GET")
        self.__data = StringIO()
        self.__response = 0
        self.__header = []
        c = Curl()
        c.setopt(c.CONNECTTIMEOUT, 10)
        c.setopt(c.TIMEOUT, 10)
        c.setopt(c.URL, self.__url)
        c.setopt(c.HTTPHEADER, moreHeader)
        c.setopt(c.WRITEDATA, self.__data)
        c.setopt(c.HEADERFUNCTION, self.__writeHeader)
        self.__curl = c
        return True

    def preparePost(self, postData, moreHeader = []):
        """
        Creates a HTTP POST request for the URL provided during initialization.
        
        This method sets the Content-Type to "application/json", so this should
        only be used when posting JSON data.
        
        @param postData: The data to be delivered via POST request encoded as
          string.
        @param moreHeader: An optional list of headers to be appended to the
            HTTP requests headers. This list must contain string values of the
            form <param>: <value> as they are directly injected into the HTTP
            header.
        """
        self.prepareGet(['Content-Type: application/json', 'Accept: application/json'] + moreHeader)
        logging.debug("switch to POST")
        c = self.__curl
        c.setopt(c.POST, 1)
        c.setopt(c.POSTFIELDS, postData)
        logging.debug("postData: %s" % (postData))
        return True

    def perform(self):
        """
        Performs the HTTP request.
        
        This performs the request that has been set up by prepareGet or
        preparePost before.
        
        This method will block until the request has finished and will fill the
        response, header and data-fields.
        
        @return The HTTP-response code as integer.
        """       
        c = self.__curl
        c.perform()
        self.__data.reset()
        resp = c.getinfo(c.RESPONSE_CODE)
        self.__response = int(resp)
        logging.info("%s: %s" % (resp, self.__url))
        cleanData = consoleCleanBinary(self.__data.getvalue())
        logging.debug("data: %s" % (cleanData))
        return self.__response

    def getHeader(self, key):
        """
        Returns all headers with the given name. This function will only return
        sane information after the query has been performed.
        
        @param key: Name of the reader to be returned. The key is handled
            case-insensitive during lookup.
        @return List of header fields.
        """
        rc = []
        for k, v in self.__header:
            if k.lower() == key.lower():
                rc.append(v)
        return rc

    def getContentType(self):
        """
        Returns the Content-Type after the request has been performed.
        
        The resulting string will be empty, if the server did not set the
        response header.
        """
        h = self.getHeader("Content-Type")
        if len(h) == 0:
            return ""
        return h[0]

    def getData(self):
        """
        Returns the stream object containing the data that has been received
        by the request.
        
        The data-object is reset directly after the response has been read and
        it can be used for reading without any further reset.
        
        @return Data received.
        """
        return self.__data

    def __writeHeader(self, data):
        """
        Internally stores a line of header data to the header-buffer.
        
        @param data The line of header to be saved.
        """
        if data.startswith("HTTP/1"):
            logging.debug(data.strip())
            data = "Response: %s" % (data)
        data = data.strip()
        hdr = data.split(": ", 2)
        if not len(hdr) == 2:
            return
        self.__header.append((hdr[0], hdr[1]))
        logging.debug("Header: %s=%s" % (hdr[0], hdr[1]))
