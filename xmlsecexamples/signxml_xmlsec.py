import xmlsec
from saml import schema
from datetime import datetime
from lxml.etree import tostring, Element
from lxml import etree as ET
from saml.schema.base import _element_registry

def build_artifact_resolve_simple():
    target = schema.ArtifactResolve()
    target.id = '_cce4ee769ed970b501d680f697989d14'
    target.issue_instant = datetime(2019, 9, 5, 9, 21, 58)
    target.issuer = 'https://idp.example.org/SAML2'
    target.artifact = '''
            AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8=
        '''.strip()
    return target

def sign(xml, stream=None, password=None):
    element = _element_registry.get(xml.tag)
    signature_node = xmlsec.template.create(
            xml,
            xmlsec.Transform.EXCL_C14N,
            xmlsec.Transform.RSA_SHA1)

    ki = xmlsec.template.ensure_key_info(signature_node)
    xmlsec.template.add_x509_data(ki)
    xml.insert(element.meta.signature_index, signature_node)
    ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1)
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    ctx = xmlsec.SignatureContext()
    key = xmlsec.Key.from_memory(stream, xmlsec.KeyFormat.PEM, password)
    ctx.key = key
    #ctx.sign(signature_node)
    #ctx.key = xmlsec.Key.from_file('clientkey', format=xmlsec.constants.KeyDataFormatPem)
    ctx.key.load_cert_from_file('clientcrt', xmlsec.constants.KeyDataFormatPem)
    ctx.sign(signature_node)
    return tostring(xml)


def soap_enclosed(signedxml):
    if not signedxml:
        return None
    st = ET.parse('soap_envelope.xml')
    soapenvelope = st.getroot()
    soapbody = soapenvelope[0]
    soapbody.append(ET.fromstring(signedxml))
    return tostring(st, xml_declaration=True, encoding="utf-8").decode()


def strip(text):
    if not text:
        return None
    text = text.replace('\n', '')
    text = text.strip()
    return text if text else None


def main():
    target_signing = build_artifact_resolve_simple()
    result = target_signing.serialize()
    fp = open('clientkey', "rb")
    content = fp.read()
    signedxml = sign(result, content, 'secret')
    artifactrequest = soap_enclosed(signedxml)
    print(strip(artifactrequest))



if __name__ == '__main__':
        main()