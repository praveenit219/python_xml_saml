from lxml import etree

root = etree.Element('root')
etree.SubElement(root, 'child').text = 'child1'
etree.SubElement(root, 'child').text = 'child2'
etree.SubElement(root, 'another').text = 'child3'

print(etree.tostring(root, pretty_print=True))