import saml
from saml import schema
from datetime import datetime
from lxml import etree
from lxml.etree import tostring, Element
import xmlsec

consts = xmlsec.constants


def build_artifact_resolve_simple():
    target = schema.ArtifactResolve()
    target.id = '_cce4ee769ed970b501d680f697989d14'
    target.issue_instant = datetime(2019, 9, 5, 9, 21, 58)
    target.issuer = 'https://idp.example.org/SAML2'
    target.artifact = '''
            AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8=
        '''.strip()
    return target


def artifact_sign():
    target_signing = build_artifact_resolve_simple()
    result = target_signing.serialize()
    fp = open('clientkey', "rb")
    content = fp.read()
    saml.sign(result, content, 'secret')
    print('-----')
    st = etree.parse('soap_envelope.xml')
    root1 = st.getroot()
    seletec = root1[0]
    signedxml = tostring(result)
    seletec.append(etree.fromstring(signedxml))
    print(tostring(st, pretty_print=True, xml_declaration=True, encoding="utf-8"))


def main():
    artifact_sign()


if __name__ == '__main__':
    main()
