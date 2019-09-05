from lxml.etree import tostring, Element
from lxml import etree
root = Element("iris")
print(tostring(root))
root.append(Element("setosa"))
root.append(Element("versicolor"))
root.append(Element("virginica"))
print(tostring(root))
print(len(root))
selected = root[2]
print(tostring(selected))
print(selected.tag)
print(root.index(selected))
children = list(root)
print(children)
for child in children:
    print(child.tag)

root.insert(0, Element('arctica'))
print('---$$$$----')
start = root[:1]
end = root[-1:]
print(list(root))
print('----')
print(start[0].tag)
print(end[0].tag)

tag = Element("iris", kingdom="plantae")
print(tostring(tag))
print(tag.get('kingdom'))
print(tag.get('non-existing'))

tag.set('kind', 'flower')
print(tag.get('kind'))
print(tostring(tag))

print(tag.keys())
print(tag.values())
print(tag.items())

for key, value in tag.items():
    print(f'{key} - {value}')
print('-------')
print(tag.attrib['kingdom'])
#tag.attrib['nothing'] #throw keyerro
tag.attrib['species'] = 'setosa'
print(tag.attrib.get('species'))
print(tag.attrib)
print(tag.attrib.items())

tag.text='setosa'
print(tag.text)
print(tostring(tag))

print('-------')
print(tostring(root, pretty_print=True))
print(etree.tostring(root,  encoding='iso-8859-1', pretty_print=True))
