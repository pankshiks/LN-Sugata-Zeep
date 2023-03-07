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


def generate_nonce(length=15):
 """Generate pseudorandom number."""
 return ''.join([str(random.randint(0, 9)) for i in range(length)])


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

print("Making request.")
# request_data = {
#  "Header": {
#     "Verb": "create",
#     "Noun": "OutageSet",
#     "ReplayDetection": {
#       "Nonce": generate_nonce(),
#       "Created": "2023-01-13T02:37:00-07:00"
#     },#change this to a time which is less than maximum of 5 minutes from current time
#     "Revision": "004",
#     "Source": "TAEPTC",
#     "UserID": "API_OutplanOSITCC",
#   },
#   "Payload": {
#       "OutageSet": {
#           "@xmlns": "http://www.ercot.com/schema/2007-06/nodal/ews",
#           "Outage": {
#               "Group": {
#                   "GroupTransmissionOutage": [
#                       {
#                           "emergencyRestorationTime": "1",
#                           "equipmentIdentifier": "_{28E961BD-19ED-4A26-9068-3C009EAB11E5}",
#                           "equipmentName": "6014",
#                           "fromStation": None,
#                           "natureOfWork": "RE",
#                           "operatingCompany": "TAEPTC",
#                           "outageState": "O",
#                           "projectName": "Project2",
#                           "transmissionType": "DSC",
#                           "voltage": "69",
#                       },
#                       {
#                           "emergencyRestorationTime": "1",
#                           "equipmentIdentifier": "_{7EEF8BDC-BA64-4331-B4F9-A16816B72F9F}",
#                           "equipmentName": "6035",
#                           "fromStation": None,
#                           "natureOfWork": "RE",
#                           "operatingCompany": "TAEPTC",
#                           "outageState": "O",
#                           "projectName": "Project3",
#                           "transmissionType": "CB",
#                           "voltage": "138",
#                       },
#                   ],
#                   "name": "Grp2",
#               },
#               "OutageInfo": {
#                   "Disclaimer": "Temp " "Disclaimer",
#                   "Requestor": {
#                       "name": "2241",
#                       "tertiaryContact": "512-555-1234",
#                       "userFullName": "Alex " "Smith",
#                   },
#                   "disclaimerAck": "true",
#                   "outageType": "PL",
#                   "participant": "TAEPTC",
#               },
#               "Schedule": {
#                   "earliestStart": "2023-03-19T10:13:00-07:00",
#                   "latestEnd": "2023-03-20T10:13:00-07:00",
#                   "plannedEnd": "2023-03-20T10:13:00-07:00",
#                   "plannedStart": "2023-03-19T10:13:00-07:00",
#               },
#           },
#       }
#   }
#  }

# factory = client.type_factory('ns0')
# headerData = client.get_type('ns0:HeaderType')(
#   Verb = 'create',
#   Noun = 'OutageSet',
#   Revision = '001',
#   ReplayDetection = {'Nonce' :'2333',  'Created' :  "2023-02-20T12:09:49.979-06:00"},
#   Source = 'TAEPTC',
#   UserID = 'API_OutplanOSITCC',   
# )

# headerData = client.get_type('ns0:HeaderType')(
#   Verb = 'create',
#   Noun = 'OutageSet',
#   Revision = '001',
#   ReplayDetection = {'Nonce' : generate_nonce(),  'Created' :  "2023-02-20T21:05:26.681-06:00"},
#   Source = 'TAEPTC',
#   UserID = 'API_OutplanOSITCC',   
# )
# print(headerData)

# payloadData = client.get_type('ns0:PayloadType')(
#   OutageSet = {
#     "Outage" : {
#       "OutageInfo": {
#         "outageType": "PL",
#         "participant": "TAEPTC",
#         "Requestor": {
#           "name": 2241,
#           "userFullName": "Alex Smith",
#           "tertiaryContact": "512-555-1234"
#         },
#         "Disclaimer": "Temp Disclaimer",
#         "disclaimerAck": True
#       },
#       "Group": {
#         "name": "Grp2",
#          "GroupTransmissionOutage": [
#             {
#               "operatingCompany": "TAEPTC",
#               "equipmentName": 6014,
#               "equipmentIdentifier": "_{28E961BD-19ED-4A26-9068-3C009EAB11E5}",
#               "transmissionType": "DSC",
#               "fromStation": "",
#               "outageState": "O",
#               "voltage": 69,
#               "projectName": "Project2",
#               "emergencyRestorationTime": 1,
#               "natureOfWork": "RE"
#             },
#             {
#               "operatingCompany": "TAEPTC",
#               "equipmentName": 6035,
#               "equipmentIdentifier": "_{7EEF8BDC-BA64-4331-B4F9-A16816B72F9F}",
#               "transmissionType": "CB",
#               "fromStation": "",
#               "outageState": "O",
#               "voltage": 138,
#               "projectName": "Project3",
#               "emergencyRestorationTime": 1,
#               "natureOfWork": "RE"
#             }
#           ]
#       },
#       "Schedule": {
#         "plannedStart": "2023-03-19T10:13:00-07:00",
#         "plannedEnd": "2023-03-20T10:13:00-07:00",
#         "earliestStart": "2023-03-19T10:13:00-07:00",
#         "latestEnd": "2023-03-20T10:13:00-07:00"
#       }
#     }
#   }
# )

# print( client.get_type('ns0:PayloadType')(OutageSet={
#   'Outage': {}
# }) )

# print(payloadData)
payloadData =  {
  "Header": {
    "Verb": "create",
    "Noun": "OutageSet",
    "ReplayDetection": {
      "Nonce": 9,
      "Created": "2023-02-21T11:28:42.801-06:00"
    },
    "Revision": 4,
    "Source": "TAEPTC",
    "UserID": "API_OutplanOSITCC"
  },
  
"Payload": {
    "OutageSet": {
      "Outage": {
        "OutageInfo": {
          "outageType": "PL",
          "participant": "TAEPTC",
          "Requestor": {
            "name": 2241,
            "userFullName": "Alex Smith",
            "tertiaryContact": "512-555-1234"
          },
          "Disclaimer": "Temp Disclaimer",
          "disclaimerAck": True
        },
        "Group": {
          "name": "Grp2",
          "GroupTransmissionOutage": [
            {
              "operatingCompany": "TAEPTC",
              "equipmentName": 6014,
              "equipmentIdentifier": "_{28E961BD-19ED-4A26-9068-3C009EAB11E5}",
              "transmissionType": "DSC",
              "fromStation": "",
              "outageState": "O",
              "voltage": 69,
              "projectName": "Project2",
              "emergencyRestorationTime": 1,
              "natureOfWork": "RE"
            },
            {
              "operatingCompany": "TAEPTC",
              "equipmentName": 6035,
              "equipmentIdentifier": "_{7EEF8BDC-BA64-4331-B4F9-A16816B72F9F}",
              "transmissionType": "CB",
              "fromStation": "",
              "outageState": "O",
              "voltage": 138,
              "projectName": "Project3",
              "emergencyRestorationTime": 1,
              "natureOfWork": "RE"
            }
          ]
        },
        "Schedule": {
          "plannedStart": "2023-03-19T10:13:00-07:00",
          "plannedEnd": "2023-03-20T10:13:00-07:00",
          "earliestStart": "2023-03-19T10:13:00-07:00",
          "latestEnd": "2023-03-20T10:13:00-07:00"
        }
      }
    }
  }
} 
# print(client.service.MarketTransactions(Header=headerData, Payload=payloadData))
print(client.service.MarketTransactions(**payloadData))