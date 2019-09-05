import xml.etree.ElementTree as ET

myTree = ET.parse('sample.xml')
myroot = myTree.getroot()
# print(myroot.tag[0:4])
# print(myroot.attrib)
# print(myroot[0].tag)

"""
get the first child of root with all the elements inside child thier attributes and values
"""
# for child in myroot[0]:
#     dir(child)
#     print(child.tag, child.attrib, child.text)
"""
get all child values in the root
"""
# for child in myroot.findall('food'):
#     item = child.find('item').text
#     price = child.find('price').text
#     print(item, price)
#
"""
update a value for one of the child element
"""
# for description in myroot.iter('description'):
#     new_desc = str(description.text)+'will be served'
#     description.text = str(new_desc)
#     description.set('updated', 'yes')
#
# myTree.write('sample_updated.xml')

"""
add a tag to the first child of root 
"""
# ET.SubElement(myroot[0], 'speciality')
# for x in myroot[0].iter('speciality'):
#     new_desc = 'south indian special'
#     x.text = str(new_desc)
#
# myTree.write('sample_speciality.xml')

"""
deleting attributes or sub element using ET
"""
# myroot[0][0].attrib.pop('name',None)
# myTree.write('sample_deleted_attrib.xml')
"""
remove complete tag, removing first tag in first child of root
"""
# myroot[0].remove(myroot[0][0])
# myTree.write('sample_remove_tag.xml')
"""
to delete all tags 
"""
myroot[0].clear()
myTree.write('sample_firstchild_remove.xml')
