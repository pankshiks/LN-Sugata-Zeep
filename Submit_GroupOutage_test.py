from zeep.wsse.signature import BinarySignature
from zeep.wsse import utils
from datetime import datetime, timedelta
import contextlib
import os
import requests
from requests_pkcs12 import Pkcs12Adapter
from zeep.transports import Transport
from zeep import Client, Settings, xsd
from pathlib import Path
from tempfile import NamedTemporaryFile
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
import random
import logging.config
import json
from pytz import timezone
import xmltodict
import xml.etree.ElementTree as ET
import re

# USE THE MOST VERBOSE LOGGING LEVEL
logging.config.dictConfig({
 'version': 1,
 'formatters': {
 'verbose': {
 'format': '%(name)s: %(message)s'
 }
 },
 'handlers': {
 'console': {
 'level': 'DEBUG',
 'class': 'logging.StreamHandler',
 'formatter': 'verbose',
 },
 },
 'loggers': {
 'zeep.transports': {
 'level': 'DEBUG',
 'propagate': True,
 'handlers': ['console'],
 },
 }
})

def text_get(match):
  with open("Ercot_constants.rc", "r") as file:
      for line in file:
        line = line.replace(' ', '')
        line = line.replace('\n','')
        param = match.replace(' ', '')
        if param in line:
              matchess = re.search(r'=(.*)', line)
              return matchess.group(1)

#this function is used for get string text before = sign in text file
def text_response_get(match):
  with open("Ercot_constants.rc", "r") as file:
      for line in file:
        line = line.replace(' ', ' ')
        line = line.replace('\n',' ')
        param = match.replace(' ', ' ')
     
        if param in line:
            text = line.split('=')[0].split('.')[1].strip()

            return text

# this function is used for convert string into lower 
def equalignoreCase(param):
    return param.lower()

class BinarySignatureTimestamp(BinarySignature):
    def apply(self, envelope, headers):
        security = utils.get_security_header(envelope)

        created = datetime.utcnow()
        expired = created + timedelta(seconds=1 * 60)

        timestamp = utils.WSU('Timestamp')
        timestamp.append(utils.WSU('Created', created.replace(microsecond=0).isoformat()+'Z'))
        timestamp.append(utils.WSU('Expires', expired.replace(microsecond=0).isoformat()+'Z'))

        security.append(timestamp)

        super().apply(envelope, headers)
        return envelope, headers

    def verify(self, envelope):
        return envelope

@contextlib.contextmanager

def pfx_to_pem(pfx_path, pfx_password):
 ''' Decrypts the .pfx file to be used with requests. '''
 pfx = Path(pfx_path).read_bytes()
 private_key, main_cert, add_certs = load_key_and_certificates(pfx, pfx_password.encode('utf-8'), None)

 with NamedTemporaryFile(suffix='.pem', delete=False) as t_pem:
   with open(t_pem.name, 'wb') as pem_file:
     pem_file.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
     pem_file.write(main_cert.public_bytes(Encoding.PEM))
     for ca in add_certs:
       pem_file.write(ca.public_bytes(Encoding.PEM))
   yield t_pem.name

def matchValue(text):
   
   match = re.search(r"(?<=\.)[a-zA-Z]+\d+", text)
   return match.group()


def generate_nonce(length=15):
 """Generate pseudorandom number."""
 return ''.join([str(random.randint(0, 9)) for i in range(length)])

def datetime_valid(dt_str):
    try:
        datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except:
        return False
    return True

def datetime_format(currentDate):
    isIOSFormat = datetime_valid(currentDate)

    if(isIOSFormat == False):
        format = "%Y-%m-%dT%H:%M:%S:%f%z"
        iosFormat = datetime.strptime(currentDate, format).replace(microsecond=0).isoformat()
        date = iosFormat.replace('+00:00', '-07:00')
        return date
    else:
        return currentDate

# CERTIFICATES PATHS

api_p12_key = os.path.join('./Certs/API Outplan OSI TCC MOTE.p12')
api_certificate = os.path.join('./Certs/OSITCC.crt')
api_pfx_key = os.path.join('./Certs/API Outplan OSI TCC MOTE.pfx')

# SETUP
wsdl_file = os.path.join('./XSD/Nodal.wsdl')

api_base_url = "https://testmisapi.ercot.com"
session = requests.Session()
session.mount(api_base_url, Pkcs12Adapter(pkcs12_filename=api_p12_key, pkcs12_password='AEP'))
session.verify = None

transport = Transport(session=session)
settings = Settings(forbid_entities=False, strict=True, xsd_ignore_sequence_order=False)

# CREATE CLIENT
print("Creating client.")
with pfx_to_pem(pfx_path=api_pfx_key, pfx_password='AEP') as pem_fle:
   client = Client(wsdl=wsdl_file, settings=settings, transport=transport,
   wsse=BinarySignatureTimestamp(pem_fle, api_certificate, "AEP"))

contents = []
eroctNatureOfWork = ''
emerRestInHours = ''
ercot_rdfid = ''
transmissionType = ''
ercotname = ''
voltage = ''
status = ''
o_status=''
plannedStart = ''
plannedEnd = ''
earlistStart = ''
ercotLatestEnd = ''
equipData = []
some_data = []

responseData = []
response = []
equipmentOutageIds = []

#Read JSON FILE
try:
    with open("ERCOT_test.json") as f:
        contents = json.load(f)
except Exception as e:
    print(e)
f.close()

for item in contents:
    description = item['description']
    createdAt   = item['createdAt']
    if 'fromStation'in item:
        fromStation = ""
    else:
        fromStation= ""

    # if 'projectName'in item:
    #     projectName = "AEP"
    # else:
    #     projectName= "AEP"

    username = item['updatedByUser']['userDisplayName']
    if 'equipmentOutages' in item:
        equipmentOutages = item['equipmentOutages']
    if 'customFieldValuesExt' in item:
        eroctNatureOfWork = item['customFieldValuesExt']['ERCOT_nature_of_work-T']
        emerRestInHours = item['customFieldValuesExt']['ERCOT_emergency_restoration_in_hours']
        ercotOutageType = item['customFieldValuesExt']['ERCOT_outage_type-T']
   
for equipment in equipmentOutages:
    if 'status' in equipment:
        status = equipment['status']
        if equalignoreCase(status) == equalignoreCase("OPEN"):
            status = "O"
        elif equalignoreCase(status) == equalignoreCase("Close"):
            status = "C"
        else: 
            status= ""

    if 'customFieldValuesExt' in equipment:
            #ERCOT_latest_end 
        # print(equipment['customFieldValuesExt'])  

        voltage = re.match('[0-9]+',equipment['asset']['Voltage'])    
  
    equipData.append({
        "operatingCompany": "TAEPTC",
        "equipmentName": equipment['asset']['ERCOT Name'],
        "equipmentIdentifier": equipment['asset']['ERCOT RDFID'],
    #   "transmissionType": equipment['asset']['_modelTypeId']
        "transmissionType": text_get(equipment['asset']['_modelTypeId']),
        "fromStation": fromStation,
        "outageState": status,
        "voltage": voltage.group(),
        "projectName": "",
        "emergencyRestorationTime": emerRestInHours,
        "natureOfWork": text_get(eroctNatureOfWork),
    })
    if 'status' in equipment:
        status = equipment['status']
    if 'plannedStart' in equipment:
        plannedStart = equipment['plannedStart']
    if 'plannedEnd' in equipment:
        plannedEnd = equipment['plannedEnd']
    if 'customFieldValuesExt' in equipment and 'ERCOT_earliest_start' in equipment['customFieldValuesExt'] :
        earlistStart = equipment['customFieldValuesExt']['ERCOT_earliest_start']
    if 'customFieldValuesExt' in equipment and 'ERCOT_latest_end' in equipment['customFieldValuesExt']:
        ercotLatestEnd = equipment['customFieldValuesExt']['ERCOT_latest_end']


#UTC CREATED AT
UTC = timezone('UTC')
utc_dt = datetime.now(UTC)
date = (utc_dt.isoformat( timespec="seconds"))
payloadData =  {
  "Header": {
    "Verb": "create",
    "Noun": "OutageSet",
    "ReplayDetection": {
      "Nonce": generate_nonce(15),
      "Created": date
    },
    "Revision": 4,
    "Source": "TAEPTC",
    "UserID": "API_OutplanOSITCC"
  },
  
"Payload": {
    "OutageSet": {
      "Outage": {
        "OutageInfo": {
          "outageType":text_get(ercotOutageType),
          "participant": "TAEPTC",
          "Requestor": {
            "name": 2241,
            "userFullName": username,
            "tertiaryContact": "512-555-1234"
          },
          "Disclaimer": "Temp Disclaimer",
          "disclaimerAck": True
        },
        "Group": {
          "name": "GRP1",
          "GroupTransmissionOutage": (equipData)
        },
       "Schedule": {
          "plannedStart":datetime_format(plannedStart),
          "plannedEnd": datetime_format(plannedEnd),
          "earliestStart": earlistStart,
          "latestEnd": ercotLatestEnd
        },
        "OSNotes":{
            "RequestorNotes":{
                "Note":{
                    "createdTime":datetime_format(plannedStart),
                    "createdBy":"AEPUser",
                    "company":"TAEPTC",
                    "comment":description
                }
            }
        }
      }
    }
  }
} 

# <ns2:createdTime>2022-11-22T11:00:00</ns2:createdTime>
#                            <ns2:createdBy>AEPUser</ns2:createdBy>
#                            <ns2:company>TAEPTC</ns2:company>
#                            <ns2:comment>EIP call test</ns2:comment>


with client.settings(raw_response=True):
    response = client.service.MarketTransactions(**payloadData)

print("############# START RESPONSE ######")
data_dict = xmltodict.parse(response.content)

print("############# TODAY Response JSON ######")
responseBody = data_dict['SOAP-ENV:Envelope']['SOAP-ENV:Body']

replyRes = responseBody['ns0:ResponseMessage']['ns0:Reply']


if 'ns0:ReplyCode' in replyRes and replyRes['ns0:ReplyCode'] == 'OK' :
    outageJson = responseBody['ns0:ResponseMessage']['ns0:Payload']['ns1:OutageSet']['ns1:Outage']
    outageGroup = outageJson['ns1:Group']['ns1:GroupTransmissionOutage']
    notes = outageJson['ns1:OSNotes']
    euidpIDs = []
    itemOutageArr = []
    for equipmentOutage in equipmentOutages:
        euidpIDs.append(equipmentOutage['id'])
    
    for index, itemOutage in enumerate(outageGroup):
        id = euidpIDs[index]
        itemOutageArr.append({
            id: {
                'customFieldValuesText': {
                    "ERCOT_outage_ID": itemOutage['ns1:mRID']
                }
            }})
    

    response = {
        "customFieldValuesExt": {
            'ERCOT_group_outage_ID': outageJson['ns1:Group']['ns1:groupId'],
            'ERCOT_outage_state': text_response_get(outageJson['ns1:OutageInfo']['ns1:state']),
            'ERCOT_outage_status': text_response_get(outageJson['ns1:OutageInfo']['ns1:status']),
            'ERCOT_submit_response': "{} Timestamp:-{}".format(replyRes['ns0:ReplyCode'],replyRes['ns0:Timestamp']),
        },
        'equipmentOutages': itemOutageArr
    }

    if 'ns1:SupportingNotes' in notes and notes['ns1:SupportingNotes'] is not None:
        response["customFieldValuesExt"]["ERCOT_supporting_notes"] = notes['ns1:SupportingNotes']

    if 'ns1:RASPSNotes' in notes and notes['ns1:RASPSNotes'] is not None:
        response["customFieldValuesExt"]["ERCOT_rasps_notes"] = notes['ns1:RASPSNotes']

    if 'ns1:ReviewerNotes' in notes and notes['ns1:ReviewerNotes'] is not None:
        response["customFieldValuesExt"]["ERCOT_reviewer_notes"] = notes['ns1:ReviewerNotes']
        

print(json.dumps(response, sort_keys=True, indent=4))

# with open("result.json", "w") as outfile:
#     outfile.write(json.dumps(response, indent=4))