from lxml import etree
from lxml.etree import tostring, Element
import xmlsec

consts = xmlsec.constants

template = etree.parse('doc_x509.xml').getroot()
print(tostring(template))
signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
ctx = xmlsec.SignatureContext()
#key = xmlsec.Key.from_file('clientkey', xmlsec.constants.KeyDataFormatPem)
ki = xmlsec.template.ensure_key_info(signature_node)
xmlsec.template.add_x509_data(ki)
ctx.key = xmlsec.Key.from_file('clientkey', format=consts.KeyDataFormatPem)
ctx.key.load_cert_from_file('clientcrt', consts.KeyDataFormatPem)
ctx.sign(signature_node)
print(tostring(template))