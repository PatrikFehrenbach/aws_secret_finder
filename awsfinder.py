from burp import IBurpExtender
from burp import IProxyListener
import re

class BurpExtender(IBurpExtender, IProxyListener):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("AWS Secrets Detector")
        callbacks.registerProxyListener(self)
        self.pattern = re.compile(r'(access|secret)([A-Za-z]*)(Key|Access)([A-Za-z]*)([=|:][\s"\']*)(AKIA|[\w/+]{40})([\s"\']*)', re.IGNORECASE | re.MULTILINE | re.DOTALL)
        print("AWS Secrets Detector extension loaded")
        
    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            httpRequest = message.getMessageInfo().getRequest()
            url = self.getUrl(httpRequest.tostring())
            httpService = message.getMessageInfo().getHttpService()
            if url is not None:
                self.checkForSecrets(httpRequest.tostring(), url, httpService)
        else:
            httpResponse = message.getMessageInfo().getResponse()
            if httpResponse is not None:
                httpRequest = message.getMessageInfo().getRequest()
                url = self.getUrl(httpRequest.tostring())
                httpService = message.getMessageInfo().getHttpService()
                if url is not None:
                    self.checkForSecrets(httpResponse.tostring(), url, httpService)
    
    def checkForSecrets(self, httpMessage, url, httpService):
        # Check if the file type should be excluded
        headers = self.callbacks.getHelpers().analyzeResponse(httpMessage).getHeaders()
        content_type = [header.split(": ", 1)[1] for header in headers if header.startswith("Content-Type")]
        if content_type and "text/css" in content_type[0]:
            return

        # Extract the message body
        messageBody = httpMessage[httpMessage.find(b"\r\n\r\n")+4:]
        # Search for AWS secrets
        try:
            decodedBody = messageBody.decode('utf-8')
        except UnicodeDecodeError:
            decodedBody = messageBody.decode('ISO-8859-1', 'ignore')
        secrets = re.findall(self.pattern, decodedBody)
        # Log any secrets that are found
        if secrets:
            fileName = url.split("/")[-1]
            print("AWS secrets found in file: " + fileName + " on host: " + httpService.getHost() + "\nSecrets found: " + str(secrets))
            self.callbacks.issueAlert("AWS secrets found in file: " + fileName + "\nSecrets found: " + str(secrets))

    
    def getUrl(self, request):
        # Extract the URL from the request
        url = None
        try:
            requestString = request.decode('utf-8')
            urlStart = requestString.find(" ") + 1
            urlEnd = requestString.find(" ", urlStart)
            url = requestString[urlStart:urlEnd]
        except:
            pass
        return url
