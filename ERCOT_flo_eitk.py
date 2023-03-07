import json
import datetime
import time
import calendar
import sys
import base64

from osi import flo_eitk_util
from osi.flo_eitk_util import EXIT_FAILURE
from osi.flo_eitk_util import EXIT_SUCCESS
from osi.flo_eitk_util import DrmsScriptRunner


NAME = 'flo_eitk'

class Runner(DrmsScriptRunner):
    def __init__(self, task_info):
        super().__init__(task_info, NAME)
               
    def run(self, step_info):
        self.initial_setup(step_info, NAME)
        input_payload = step_info.get_input_payload()
        input_message = input_payload.get_message(0)
        eventID = 0
        createdDate = ""
        int_val =[]
        ## set up our output body/headers
        out_message = step_info.get_output_payload().create_message()
        ## Get our script parameters (to figure out which function to run)
        params = step_info.get_script_parameters()
        ###############################################################################################
        #### following options run various actions depending on input args configured in EITK step ####
        ###############################################################################################
        if params["function"] == "parsedercomms":
        ## parse and set variables from DERComms input
            self.logger.debug("Read/parse input body from DERComms")
        ## Read/parse input body from DERComms
            with input_message.get_body().get_stream() as input_stream:
                json_byte = input_stream.read()
                input_body = json.loads(json_byte)
            ## First validate our input payload (for the fields we need to make sure are there)
            if "operationType" not in input_body.keys() or "operationParameters" not in input_body.keys(): 
               self.logger.error("No OperationType/operationParameters")
               self.stop_log()
               return EXIT_FAILURE
            elif (input_body["operationType"]["operation"]) != "ExecuteEvent" :
               self.logger.error("Operation is not ExecuteEvent")
               self.stop_log()
               return EXIT_FAILURE
            elif "duration" not in input_body["operationParameters"].keys() or  "action" not in input_body["operationParameters"].keys() or \
                 "targets" not in input_body["operationParameters"].keys(): 
               self.logger.error("No duration/action/targets")
               self.stop_log()
               return EXIT_FAILURE 
            ##Extracting the integer part of the "value" tag
            limit_actual = input_body["operationParameters"]["action"]["value"]
            self.logger.debug("Actual Limit: {}".format(limit_actual))
            int_val = limit_actual.split(".")
            self.logger.debug("Integer part of Limit: {}".format(int_val[0]))             
            ##CreatedDate for response body
            createdDate = (datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))+ ".000Z"
            step_info.get_runtime_args().put_arg('createdDate', createdDate)            
            ##Get user/pass and convert to Base64
            user = params['user']
            password = params['password']
            flo_creds = ':'.join([user, password]) 
            flo_enc_cred = base64.b64encode(flo_creds.encode("utf-8"))
            flo_enc_cred_Str = str(flo_enc_cred, "utf-8")
            flo_fin_creds = ' '.join(["Basic", flo_enc_cred_Str]) 
            ##Set Auth. header
            step_info.get_runtime_args().put_arg('Authorization', flo_fin_creds)
            ##Get Station ID from input payload and set as argument
            stationID = str(input_body["operationParameters"]["targets"]["include"]["serialNumbers"][0])
            self.logger.debug("Device Id: {}".format(stationID))
            step_info.get_runtime_args().put_arg('stationID', stationID)
            ##Get duration from input payload and set as argument
            duration = input_body["operationParameters"]["duration"]
            self.logger.debug("Duration: {}".format(duration))
            step_info.get_runtime_args().put_arg('duration', duration)
            ##Get limit from input payload and set as argument
            step_info.get_runtime_args().put_arg('limit', int_val[0])
        ###############################################################################################
        elif params["function"] == "sendResponse":
            self.logger.debug("Creating Response body")
            response = {"createdDate": step_info.get_runtime_args().get_arg('createdDate')}
            with out_message.get_body().get_stream() as out:
                 out.write(json.dumps(response))        
        ###############################################################################################
        else:
            self.logger.error("Incorrect parameter provided")
        ## Something went wrong - we shouldnt be here
            self.stop_log()
            return EXIT_FAILURE
        ###############################################################################################
        self.stop_log()
        return EXIT_SUCCESS