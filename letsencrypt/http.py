from pycurl import Curl
from cStringIO import StringIO

import logging

class HttpProviderCurl(object):
    '''
    Abstracts the HTTP interface to allow replacing the library used for
    connecting by something differend from pycurl.
    '''
    def __init__(self, url):
        '''
        Constructs a new class.
        
        @param url: The url to access by the HttpProvider.
        '''
        logging.debug("create HttpProviderCurl for %s" % (url))
        self.__url = url
        self.__response = 0
        self.__header = []
        self.__data = StringIO()
    
    def prepareGet(self, moreHeader = []):
        '''
        Prepares a HTTP GET request for the URL provided during initialization.
        '''
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
        '''
        Creates a HTTP POST request for the URL provided during initialization.
        
        @param postData: The data to be delivered via POST request encoded as
          string.
        @param moreHeader: 
        '''
        self.prepareGet(['Content-Type: application/json', 'Accept: application/json'] + moreHeader)
        logging.debug("switch to POST")
        c = self.__curl
        c.setopt(c.POST, 1)
        c.setopt(c.POSTFIELDS, postData)
        logging.debug("postData: %s" % (postData))
        return True

    def perform(self):
        '''
        Performs the HTTP request.
        
        @return Response-code for the HTTP request as integer.
        '''       
        c = self.__curl
        c.perform()
        self.__data.reset()
        resp = c.getinfo(c.RESPONSE_CODE)
        self.__response = int(resp)
        logging.info("%s: %s" % (resp, self.__url))
        logging.debug("data: %s" % (self.__data.getvalue()))
        return self.__response

    def getHeader(self, key):
        '''
        Returns all headers with the given name.
        
        @param key: Name of the reader to be returned.
        @return List of header fields.
        '''
        rc = []
        for k, v in self.__header:
            if k.lower() == key.lower():
                rc.append(v)
        return rc

    def getData(self):
        '''
        Retuens the stream object containing the data that has been received
        by the request.
        
        @return Data received.
        '''
        return self.__data

    def __writeHeader(self, data):
        '''
        Preserves one line of HTTP header data.
        
        @param data The line of header to be saved.
        '''
        if data.startswith("HTTP/1"):
            logging.debug(data.strip())
            data = "Response: %s" % (data)
        data = data.strip()
        hdr = data.split(": ", 2)
        if not len(hdr) == 2:
            return
        self.__header.append((hdr[0], hdr[1]))
        logging.debug("Header: %s=%s" % (hdr[0], hdr[1]))
