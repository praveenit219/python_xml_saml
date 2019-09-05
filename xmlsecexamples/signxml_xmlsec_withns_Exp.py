import xmlsec
from saml import schema
from datetime import datetime, time
from lxml.etree import tostring, Element
from lxml import etree as ET
from saml.schema.base import _element_registry
import secrets
import requests

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
    print(tostring(signature_node))
    print(tostring(xml))
    ctx.sign(signature_node)
    print(tostring(signature_node))
    return tostring(xml)

def signWay(xml, elemid=None, stream=None, password=None):
    artifactResolve = xml
    xmlsec.tree.add_ids(artifactResolve, ["ID"])
    elem_id = artifactResolve.get('ID', None)
    print(elem_id)
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

    print('----before----')
    print('----AR----')
    print(tostring(artifactResolve))
    print('----SIG----')
    print(tostring(signature_node))
    ctx.sign(signature_node)
    #return tostring(xml)
    print('----after----')
    print('----SIG----')
    print(tostring(signature_node))
    print('----AR----')
    print(tostring(artifactResolve))
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


def postsamlAssertion(artifactrequest):
    headers = {
                'SOAPAction': 'http://www.oasis-open.org/committees/security',
               'Cache-control': 'no-cache, no-store',
               'Pragma': 'no-cache',
               'Content-Type': 'text/xml; charset=utf-8'
               }
    res = requests.post('http://localhost:5156/singpass/soap', data=artifactrequest, headers=headers)
    print(res.status_code)
    print(res.content)


def strip(text):
    if not text:
        return None
    text = text.replace('\n', '')
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
        value = bytes_or_str.decode() # uses 'utf-8' for encoding
    else:
        value = bytes_or_str
    return value # Instance of str


def main():
    artifactid = 'AAQAAES0pW0VpFlmXMnNzniG8VN8z8UvBxnyd1cYkVEqx7Vspdg8PgqqNgJlZmF1bHRQ'
    partnerid = 'http://localhost:5156/SP/samlArt'
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
    postsamlAssertion(artifactrequest)
    #print(strip(artifactrequest))



if __name__ == '__main__':
        main()