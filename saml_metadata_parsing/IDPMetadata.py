

class IDPMetadataDetails:

    def __init__(self):
        self._entityId = ""
        self._gateway = ""
        self._signingCert = ""
        self._encryptionCert = ""
        self._location = ""

    @property
    def entityId(self):
        return self._entityId

    @entityId.setter
    def entityId(self, entityId):
        self._entityId = entityId

    @property
    def gateway(self):
        return self._gateway

    @gateway.setter
    def gateway(self, gateway):
        self._gateway = gateway

    @property
    def signingcert(self):
        return self._signingCert

    @signingcert.setter
    def signingcert(self, signingcert):
        self._signingCert = signingcert

    @property
    def encryptioncert(self):
        return self._encryptionCert

    @encryptioncert.setter
    def encryptioncert(self, encryptioncert):
        self._encryptionCert = encryptioncert

    @property
    def location(self):
        return self._location

    @location.setter
    def location(self, url):
        self._location = url

    def __str__(self):
        return 'entityId: {} \ngateway: {} \nidpSigningCert: {} \nidpEncryptionCert: {} \nsoapHttpUrl: {}\n'.format(self._entityId, self._gateway, self._signingCert, self._encryptionCert, self._location)