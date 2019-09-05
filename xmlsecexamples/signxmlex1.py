from lxml import etree
from lxml.etree import tostring, Element
import xmlsec

template = etree.parse('doc_RSA.xml').getroot()
print(tostring(template))

signature_node = xmlsec.tree.find_node(template, xmlsec.constants.NodeSignature)
print(tostring(signature_node))
ctx = xmlsec.SignatureContext()
key = xmlsec.Key.from_file('clientkey', xmlsec.constants.KeyDataFormatPem)
ctx.key = key
ctx.sign(signature_node)
print(etree.tostring(template))