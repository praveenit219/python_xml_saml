import csv
import requests
import xml.etree.ElementTree as ET

def loadrss(url):
    if url == "":
        print('please pass an rss url')
    else:
        resp = requests.get(url)
        #print(resp.text)
        if resp.status_code == 200:
            with open('hindustantopnewsfeed.xml','wb') as f:
                f.write(resp.content)


def parsexml(xmlfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    newsItems = []
    for item in root.findall('channel/item'):
        news = {}
        for child in item:
            if child.tag == '{http://search.yahoo.com/mrss/}content':
                news['media'] = child.attrib['url']
            else:
                news[child.tag] = child.text.encode('utf8')

        newsItems.append(news)
    return newsItems


def saveTocsv(newsItems, filename):
    fields = ['guid', 'title', 'pubDate', 'description', 'link', 'media']
    with open(filename, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)
        writer.writeheader()
        writer.writerows(newsItems)



def main():
    rssurl = "https://www.hindustantimes.com/rss/topnews/rssfeed.xml";
    loadrss(rssurl)
    newsItems = parsexml('hindustantopnewsfeed.xml')
    saveTocsv(newsItems, 'hindustantopnews.csv')


if __name__ == "__main__":
    main()
