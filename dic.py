
# Import the required modules
import xmltodict
import pprint
  
# Open the file and read the contents
with open('data.xml', 'r', encoding='utf-8') as file:
    my_xml = file.read()
  
# Use xmltodict to parse and convert 
# the XML document
my_dict = xmltodict.parse(my_xml)
  
# Print the dictionary
pprint.pprint(my_dict, indent=2)