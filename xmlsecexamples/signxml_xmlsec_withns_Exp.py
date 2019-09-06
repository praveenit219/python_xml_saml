
import re
import xmlsec
from saml import schema
from datetime import datetime, time
from lxml.etree import tostring, Element
from lxml import etree as ET
from saml.schema.base import _element_registry
import secrets
import requests
import base64

def build_artifact_resolve_simple(partnerid=None, artifact=None):
    target = schema.ArtifactResolve()
    target.id = '_'+secrets.token_hex(16)
    target.issuer = partnerid
    target.artifact = artifact.strip()
    return target


def sign(xml, elemid=None, stream=None, password=None):
    element = _element_registry.get(xml.tag)
    signature_node = xmlsec.template.create(
            xml,
            xmlsec.Transform.EXCL_C14N,
            xmlsec.Transform.RSA_SHA1, ns="ds")

    ki = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(ki)
    xml.insert(element.meta.signature_index, signature_node)
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1,  id=elemid)
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
    ctx = xmlsec.SignatureContext()
    #key = xmlsec.Key.from_memory(stream, xmlsec.KeyFormat.PEM, password)
    ctx.key = xmlsec.Key.from_memory(stream, xmlsec.KeyFormat.PEM, password)
    #ctx.sign(signature_node)
    #ctx.key = xmlsec.Key.from_file('clientkey', format=xmlsec.constants.KeyDataFormatPem)
    ctx.key.load_cert_from_file('clientcrt', xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature_node)
    return tostring(xml)

def signWay(xml, elemid=None, stream=None, password=None):
    artifactResolve = xml
    xmlsec.tree.add_ids(artifactResolve, ["ID"])
    elem_id = artifactResolve.get('ID', None)
    if elem_id:
        elem_id = '#' + elem_id
    print(elem_id)
    signature_node = xmlsec.template.create(artifactResolve, xmlsec.constants.TransformExclC14N, xmlsec.constants.TransformRsaSha1, ns="ds")
    artifactResolve.append(signature_node)
    ref = xmlsec.template.add_reference(signature_node, xmlsec.constants.TransformSha1, uri=elem_id)
    xmlsec.template.add_transform(ref, xmlsec.constants.TransformEnveloped)
    xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
    ki = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(ki)
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_memory(stream, xmlsec.KeyFormat.PEM, password)
    ctx.key.load_cert_from_file('clientcrt', xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature_node)
    return tostring(artifactResolve)



def soap_enclosed(signedxml):
    if not signedxml:
        return None
    st = ET.parse('soap_envelope.xml')
    soapenvelope = st.getroot()
    soapbody = soapenvelope[0]
    soapbody.append(ET.fromstring(signedxml))
    return tostring(st, xml_declaration=False, encoding="utf-8").decode()
    #return tostring(st, xml_declaration=True, encoding="utf-8")


def postsamlAssertion(artifactrequest, endpoint):
    headers = {
                'SOAPAction': 'http://www.oasis-open.org/committees/security',
               'Cache-control': 'no-cache, no-store',
               'Pragma': 'no-cache',
               'Content-Type': 'text/xml; charset=utf-8'
               }
    res = requests.post(endpoint, data=artifactrequest, headers=headers)
    if res.status_code == 200:
        return res.content
    else:
        return None

def saml_assertion_response(artifactresponse):
    root = ET.fromstring(artifactresponse)
    tree = ET.ElementTree(root)
    #to get all paths in xml
    """
    for e in root.iter():
        print(tree.getpath(e))
    """
    #/soap11:Envelope/soap11:Body/samlp:ArtifactResponse/samlp:Response/saml:EncryptedAssertion
    namespace_soap11 = 'http://schemas.xmlsoap.org/soap/envelope/'
    namespace_samlp = 'urn:oasis:names:tc:SAML:2.0:protocol'
    namespace_saml = 'urn:oasis:names:tc:SAML:2.0:assertion'
    namespace_xenc = 'http://www.w3.org/2001/04/xmlenc#'
    xpath_selector = '/x:Envelope/x:Body/y:ArtifactResponse/y:Response/z:EncryptedAssertion'
    encrypted_assertion = root.xpath(xpath_selector, namespaces={'x': namespace_soap11,
                                                                'y': namespace_samlp,
                                                                'z': namespace_saml
                                                           })
    encryptedDataRoot = None
    #print(encryptedData)
    for data in encrypted_assertion:
        encryptedDataRoot = data
        break
    """
    stringXml = to_str(artifactresponse)
    root = ET.parse(stringXml)
    print(stringXml)
    cleanedXMl = strip(stringXml)
    print(stringXml)
    ET.tostring(root, encoding='unicode', method='text')
    root = ET.fromstring(stringXml)
    encryptedAssertion = root.xpath('EncryptedAssertion')
    print(tostring(encryptedAssertion))
    """
    #decrypting the ecnrypted assertion
    print('----')
    encrypteddata = ET.ElementTree(encryptedDataRoot).getroot()
    enc_data = xmlsec.tree.find_child(encrypteddata, xmlsec.constants.NodeEncryptedData, xmlsec.constants.EncNs)
    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file('clientkey', format=xmlsec.constants.KeyDataFormatPem))
    ctx = xmlsec.EncryptionContext(manager)
    decrypted = ctx.decrypt(enc_data)
    decrypted_root = ET.ElementTree(decrypted).getroot()
    xmlsec.tree.add_ids(decrypted_root, ["ID"])
    signature_node = xmlsec.tree.find_node(decrypted_root, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    #key = xmlsec.Key.from_file('clientcrt', xmlsec.constants.KeyDataFormatPem)
    ctx.key = xmlsec.Key.from_file('id_rsa.pub.pem', xmlsec.KeyFormat.PEM)
    # ctx.sign(signature_node)
    # ctx.key = xmlsec.Key.from_file('clientkey', format=xmlsec.constants.KeyDataFormatPem)
    #ctx.key.load_cert_from_file('clientcrt', xmlsec.constants.KeyDataFormatPem)
    try:
        ctx.verify(signature_node)
    except xmlsec.VerificationError as signatureError:
        print('signature verfication failed')

    print(tostring(decrypted_root))
    return decrypted_root
    #print(tostring(decrypted))
    #print(tostring(encrypteddata))


def samlresponse(artifactresponse):
    root = ET.fromstring(artifactresponse)
    tree = ET.ElementTree(root)
    #to get all paths in xml
    """
    for e in root.iter():
        print(tree.getpath(e))
    """
    #/soap11:Envelope/soap11:Body/samlp:ArtifactResponse/samlp:Response/saml:EncryptedAssertion
    namespace_soap11 = 'http://schemas.xmlsoap.org/soap/envelope/'
    namespace_samlp = 'urn:oasis:names:tc:SAML:2.0:protocol'
    namespace_saml = 'urn:oasis:names:tc:SAML:2.0:assertion'
    namespace_xenc = 'http://www.w3.org/2001/04/xmlenc#'
    xpath_selector = '/x:Envelope/x:Body/y:ArtifactResponse/y:Response/z:EncryptedAssertion/a:EncryptedData'
    encryptedData = root.xpath(xpath_selector, namespaces={'x': namespace_soap11,
                                                                'y': namespace_samlp,
                                                                'z': namespace_saml,
                                                                'a': namespace_xenc})
    encryptedDataRoot = None
    #print(encryptedData)
    for data in encryptedData:
        encryptedDataRoot = data
        print(tostring(encryptedDataRoot))
        break
    """
    stringXml = to_str(artifactresponse)
    root = ET.parse(stringXml)
    print(stringXml)
    cleanedXMl = strip(stringXml)
    print(stringXml)
    ET.tostring(root, encoding='unicode', method='text')
    root = ET.fromstring(stringXml)
    encryptedAssertion = root.xpath('EncryptedAssertion')
    print(tostring(encryptedAssertion))
    """
    #decrypting the ecnrypted assertion
    """
    enc_data = xmlsec.tree.find_child(root, xmlsec.constants.NodeEncryptedData, xmlsec.constants.EncNs)
    print(enc_data)
    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file('clientkey', format=xmlsec.constants.KeyDataFormatPem))
    ctx = xmlsec.EncryptionContext(manager)
    decrypted = ctx.decrypt(enc_data)
    print(tostring(encryptedDataRoot))
    """

def extract_data_sp(decrypted_assertion):
    # assertion_root = ET.ElementTree(decrypted_assertion).getRoot()
    # /saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef
    # /saml:AttributeStatement/saml:Attribute/saml:AttributeValue
    # Name="UserName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    #root = ET.fromstring(decrypted_assertion)
    root = ET.ElementTree(decrypted_assertion)
    print(tostring(root))
    namespace_saml = 'urn:oasis:names:tc:SAML:2.0:assertion'
    xpath_selector = '/x:Assertion/x:AuthnStatement/x:AuthnContext/x:AuthnContextClassRef'
    authncontextref = root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for authncontext in authncontextref:
        print(authncontext.text)
    xpath_selector = '/x:Assertion/x:AttributeStatement/x:Attribute'
    attribute = root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for attribs in attribute:
        for key, val in attribs.items():
            print(attribs.get('Name'))
            print(attribs.get('NameFormat'))
            break
        break
    xpath_selector = '/x:Assertion/x:AttributeStatement/x:Attribute/x:AttributeValue'
    attribute_value=root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for user in attribute_value:
        print(user.text)
        break

def extract_data_cp(decrypted_assertion):
    # assertion_root = ET.ElementTree(decrypted_assertion).getRoot()
    # /saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef
    # /saml:AttributeStatement/saml:Attribute/saml:AttributeValue
    # Name="UserName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    #root = ET.fromstring(decrypted_assertion)
    root = ET.ElementTree(decrypted_assertion)
    print(tostring(root))
    namespace_saml = 'urn:oasis:names:tc:SAML:2.0:assertion'
    xpath_selector = '/x:Assertion/x:AuthnStatement/x:AuthnContext/x:AuthnContextClassRef'
    authncontextref = root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for authncontext in authncontextref:
        print(authncontext.text)
    xpath_selector = '/x:Assertion/x:AttributeStatement/x:Attribute'
    attribute = root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for attribs in attribute:
        for key, val in attribs.items():
            print(attribs.get('Name'))
            print(attribs.get('NameFormat'))
            break
        break
    xpath_selector = '/x:Assertion/x:AttributeStatement/x:Attribute/x:AttributeValue'
    attribute_value=root.xpath(xpath_selector, namespaces={'x': namespace_saml})
    for user in attribute_value:
        print(user.text)
        user_data = base64.b64decode(user.text)
        user_data = to_str(user_data)
        user_data = strip(user_data)
        print(user_data)
        user_info = user_data.split('</UserInfo>')
        for user_info_result in user_info:
            if user_info_result.startswith('<UserInfo>'):
                user_final = user_info_result+'</UserInfo>'
            elif user_info_result.startswith('<AuthAccess>'):
                auth_access = user_info_result+'</UserInfo>'
        break

    print(user_final)
    print(auth_access)
    print(base64.b64encode(to_bytes(auth_access)))


def strip(text):
    if not text:
        return None
    text = text.replace('\n', '')
    text = text.replace('\r', '')
    text = text.strip()
    return text if text else None


def to_bytes(bytes_or_str):
    if isinstance(bytes_or_str, str):
        value = bytes_or_str.encode() # uses 'utf-8' for encoding
    else:
        value = bytes_or_str
    return value # Instance of bytes


def to_str(bytes_or_str):
    if isinstance(bytes_or_str, bytes):
        value = bytes_or_str.decode('utf-8') # uses 'utf-8' for decoding
    else:
        value = bytes_or_str
    return value # Instance of str


def main():
    """
    #for SP local mockserver
    artifactid = 'AAQAAES0pW0VpFlmXMnNzniG8VN8z8UvBxnyd1cYkVEqx7Vspdg8PgqqNgJlZmF1bHRQ'
    partnerid = 'http://localhost:5156/SP/samlArt'
    endpoint =  'http://localhost:5156/singpass/soap'
    """
    #for CP local mockserver
    artifactid = 'AAQAACiTItxGwGr/WoVpXfymhxUkREPv2mRzvDmxEKp3IYGz20Dn/BK2hQQAAAAAAAAA'
    partnerid = 'http://localhost:5156/CP/samlArt'
    endpoint = 'http://localhost:5156/corppass/soap'

    target_signing = build_artifact_resolve_simple(partnerid, artifactid)
    elem = '#'+target_signing.id
    result = target_signing.serialize()
    fp = open('clientkey', "rb")
    content = fp.read()
    #signedxml = sign(result, elem, content, 'secret')
    signedxml = signWay(result, elem, content, 'secret')
    artifactrequest = soap_enclosed(signedxml)
    #finalRequest = to_bytes(strip(artifactrequest))
    #print(finalRequest)
    #postsamlAssertion(strip(artifactrequest))
    artifactresponse = postsamlAssertion(artifactrequest, endpoint)
    decryptedassertion = None
    if not artifactresponse:
        print('error or not a valid response')
    else:
        #samlresponse(artifactresponse)
        decryptedassertion = saml_assertion_response(artifactresponse)
    #extract_data_sp(decryptedassertion)
    extract_data_cp(decryptedassertion)
    #print(strip(artifactrequest))



if __name__ == '__main__':
        main()