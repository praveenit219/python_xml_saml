from lxml.etree import tostring, Element
from lxml import etree
from io import StringIO, BytesIO
import xml.etree.ElementTree as ET
from .IDPMetadata import IDPMetadataDetails


class IDPMetadataProcessor:


    def __init__(self, filename):
        self.filename = filename
        self.idpMetaDetails = IDPMetadataDetails()

    def parseidpspass(self):
        idpspasstree = etree.parse(self.filename)
        idpspassroot = idpspasstree.getroot()
        entityId = idpspassroot.get('entityID')
        self.idpMetaDetails._entityId = entityId
        namespace_xmlns = 'urn:oasis:names:tc:SAML:2.0:metadata'
        xpath_selector = "//x:KeyDescriptor[@use='signing']/*/*/*"
        signing_keyDescriptors = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
        xpath_selector = "//x:KeyDescriptor[@use='encryption']/*/*/*"
        encryption_keyDescriptors = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
        for signingKeyInfo in signing_keyDescriptors:
            signingcert = signingKeyInfo.text.strip()
            self.idpMetaDetails._signingCert = signingcert
            break
        for encryptionKeyInfo in encryption_keyDescriptors:
            encryptcert = encryptionKeyInfo.text.strip()
            self.idpMetaDetails._encryptionCert = encryptcert
            break
        xpath_selector = "//x:ArtifactResolutionService"
        artifactResolution = idpspasstree.xpath(xpath_selector, namespaces={'x': namespace_xmlns})
        for artifacts in artifactResolution:
            if artifacts.attrib.get('Binding') == 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP' and artifacts.attrib.get(
                    'index') == '0' and artifacts.attrib.get('isDefault') == 'true':
                httploc = artifacts.attrib.get('Location')
                self.idpMetaDetails._location = httploc
                break
        return self.idpMetaDetails


