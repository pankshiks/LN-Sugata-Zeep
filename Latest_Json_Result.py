import json
import re
from pytz import timezone
from datetime import datetime, timedelta
import random
import xmltodict

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
error = ''
ERCOT_rasps_notes = ''
ERCOT_supporting_notes = ''

# this function is used for convert string into lower 
def equalignoreCase(param):
    return param.lower()

def generate_nonce(length=15):
 """Generate pseudorandom number."""
 return ''.join([str(random.randint(0, 9)) for i in range(length)])

def datetime_format(currentDate):
    isIOSFormat = datetime_valid(currentDate)

    if(isIOSFormat == False):
        format = "%Y-%m-%dT%H:%M:%S:%f%z"
        iosFormat = datetime.strptime(currentDate, format).replace(microsecond=0).isoformat()
        date = iosFormat.replace('+00:00', '-07:00')
        return date
    else:
        return currentDate

def datetime_valid(dt_str):
    try:
        datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except:
        return False
    return True

def text_get(match):
  with open("Ercot_constants.rc", "r") as file:
      for line in file:
        line = line.replace(' ', '')
        line = line.replace('\n','')
        param = match.replace(' ', '')
        if param in line:
              matchess = re.search(r'=(.*)', line)
              return matchess.group(1)

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
        ERCOT_rasps_notes = item['customFieldValuesExt']['ERCOT_rasps_notes']
        ERCOT_supporting_notes = item['customFieldValuesExt']['ERCOT_supporting_notes']
        
        

   
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

json_data = {
        "Note" : {
            "createdTime":datetime_format(plannedStart),
            "createdBy":"abc",
            "company":"abc",
            "comment":ERCOT_rasps_notes
        }
    }

json_data2 = {
        "Note" : {
                "createdTime":datetime_format(plannedStart),
                "createdBy":"abc",
                "company":"abc",
                "comment":ERCOT_supporting_notes
        }
    }

if ERCOT_supporting_notes !="":
    payloadData['Payload']['OutageSet']['Outage']['OSNotes']['ERCOT_supporting_notes'] = json_data2

if ERCOT_rasps_notes !="":
    payloadData['Payload']['OutageSet']['Outage']['OSNotes']['ERCOT_rasps_notes'] = json_data

print(json.dumps(payloadData, sort_keys=True, indent=4))