import datetime
import multiprocessing
import sys

import pyshark

global rccSetupAtt
global rccSetupSucc
global rccSetupFail
global ueContextSetupAtt
global ueContextSetupSucc
global ueContextSetupFail

f1ap_procedure_codes = {
    '5': "UEContextSetup",
    '6': "UEContextRelease",
    '7': "UEContextModification",
    '8': "UEContextModificationRequired",
    '10': "UEContextReleaseRequest",
    '11': "InitialULRRCMessageTransfer",
    '12': "DLRRCMessageTransfer",
    '13': "ULRRCMessageTransfer",
    '15': "UEInactivityNotification",
    '18': "Paging"
}

rrc_dict = {'DL-CCCH-Message': {'c1': {'0': "rrcReject", '1': "rrcSetup"}
                                },
            'DL-DCCH-Message': {'c1': {"0": "rrcReconfiguration",
                                       "1": "rrcResume",
                                       "2": "rrcRelease",
                                       "3": "rrcReestablishment",
                                       "4": "securityModeCommand",
                                       "5": "dlInformationTransfer",
                                       "6": "ueCapabilityEnquiry",
                                       "7": "counterCheck",
                                       "8": "mobilityFromNRCommand",
                                       "9": "dlDedicatedMessageSegment-r16",
                                       "10": "ueInformationRequest-r16",
                                       "11": "dlInformationTransferMRDC-r16",
                                       "12": "loggedMeasurementConfiguration-r16",

                                       }},
            'PCCH-Message': {'c1': {"0": "paging"}
                             },
            "UL-CCCH-Message": {'c1': {"0": "rrcSetupRequest",
                                       "1": "rrcResumeRequest",
                                       "2": "rrcReestablishmentRequest",
                                       "3": "rrcSystemInfoRequest",
                                       }},
            'UL-DCCH-Message': {'c1': {"0": "measurementReport",
                                       "1": "rrcReconfigurationComplete",
                                       "2": "rrcSetupComplete",
                                       "3": "rrcReestablishmentComplete",
                                       "4": "rrcResumeComplete",
                                       "5": "securityModeComplete",
                                       "6": "securityModeFailure",
                                       "7": "ulInformationTransfer",
                                       "8": "locationMeasurementIndication",
                                       "9": "ueCapabilityInformation",
                                       "10": "counterCheckResponse",
                                       "11": "ueAssistanceInformation",
                                       "12": "failureInformation",
                                       "13": "ulInformationTransferMRDC",
                                       "14": "scgFailureInformation",
                                       "15": "scgFailureInformationEUTRA",

                                       }, 'c2': {"0": "ulDedicatedMessageSegment-r16",
                                                 "1": "dedicatedSIBRequest-r16",
                                                 "2": "mcgFailureInformation-r16",
                                                 "3": "ueInformationResponse-r16",
                                                 "4": "sidelinkUEInformationNR-r16",
                                                 "5": "ulInformationTransferIRAT-r16",
                                                 "6": "iabOtherInformation-r16",
                                                 "7": "spare9",
                                                 "8": "spare8",
                                                 "9": "spare7",
                                                 "10": "spare6",
                                                 "11": "spare5",
                                                 "12": "spare4",
                                                 "13": "spare3",
                                                 "14": "spare2",
                                                 "15": "spare1",
                                                 }}
            }

my_dict = {
    'UL-CCCH-Message': {
        '0': "rrcSetupRequest",
        '1': "rrcResumeRequest",
        '2': "rrcReestablishmentRequest",
        '3': "rrcSystemInfoRequest",
    },
    'DL-CCCH-Message': {'0': "rrcReject", '1': "rrcSetup"},
    'UL-DCCH-Message': {'0': 'measurementReport',
                        '1': 'rrcReconfigurationComplete',
                        '2': 'rrcSetupComplete',
                        '3': 'rrcReestablishmentComplete',
                        '4': 'rrcResumeComplete',
                        '5': 'securityModeComplete',
                        '6': 'securityModeFailure',
                        '8': 'locationMeasurementIndication',
                        '13': 'ulInformationTransferMRDC'

                        },
    'DL-DCCH-Message': {'0': "dlInformationTransfer", '4': "securityModeCommand"},
    'id-InitialUEMessage': {'0x41': 'registrationRequest'},
    'UL-RRC-Message': {"0", 'measurementReport'}

}

cause_radio_network_dict = {
    0: 'unspecified',
    1: 'rl-failure-rlc',
    2: 'unknown-or-already-allocated-gnb-cu-ue-f1ap-id',
    3: 'unknown-or-already-allocated-gnd-du-ue-f1ap-id',
    4: 'unknown-or-inconsistent-pair-of-ue-f1ap-id',
    5: 'interaction-with-other-procedure',
    6: 'not-supported-qci-Value',
    7: 'action-desirable-for-radio-reasons',
    8: 'no-radio-resources-available',
    9: 'procedure-cancelled',
    10: 'normal-release',
    11: 'cell-not-available',
    12: 'rl-failure-others',
    13: 'ue-rejection',
    14: 'resources-not-available-for-the-slice'
}
misc_code_to_desc = {
    '0': 'Controlprocessingoverload',
    '1': 'Notenoughuserplaneprocessingresources',
    '2': 'Hardwarefailure',
    '3': 'OMintervention',
    '4': 'Unspecified',
}
establishment_cause = {
    '0': 'emergency',
    '1': 'highPriorityAccess',
    '2': 'mt-Access',
    '3': 'mo-Signalling',
    '4': 'mo-Data',
    '5': 'mo-VoiceCall',
    '6': 'mo-VideoCall',
    '7': 'mo-SMS',
    '8': 'mps-PriorityAccess',
    '9': 'mcs-PriorityAccess',
    '10': 'spare6',
    '11': 'spare5',
    '12': 'spare4',
    '13': 'spare3',
    '14': 'spare2',
    '15': 'spare1'
}

cause_code_to_desc = {
    '0': 'RadioNetworkLayerCause',
    '1': 'TransportLayerCause',
    '2': 'ProtocolCause',
    '3': 'MiscellaneousCause'
}

message_entity_map = {'rrcSetupComplete': 'DU-CUCP',
                      'rrcSetupRequest': 'DU-CUCP',
                      'securityModeComplete': 'DU-CUCP',
                      'securityModeCommand': 'CUCP-DU', 'rrcSetup': 'CUCP-DU',
                      'registrationRequest': 'CUCP-AMF', 'BearerContextSetupRequest': 'CUCP-CUUP',
                      'BearerContextSetupResponse': 'CUUP-CUCP',
                      'measurementReport': 'DU-CUCP',
                      'BearerContextSetupFailure': 'CUUP-CUCP',
                      'BearerContextModificationRequest': 'CUCP-CUUP',
                      'BearerContextModificationResponse': 'CUCP-CUUP',
                      'BearerContextModificationFailure': 'CUUP-CUCP',
                      'BearerContextModificationRequired': 'CUUP-CUCP',
                      'BearerContextModificationConfirm': 'CUCP-CUUP',
                      'BearerContextReleaseCommand': 'CUCP-CUUP',
                      'BearerContextReleaseComplete': 'CUUP-CUCP',
                      'BearerContextReleaseRequest': 'CUUP-CUCP',
                      'BearerContextInactivityNotification': 'CUUP-CUCP',
                      'UEContextSetupRequest': 'CUCP-DU',
                      'UEContextSetupResponse': 'DU-CUCP',
                      'UEContextSetupFailure': 'CUCP-DU',
                      'UEContextReleaseCommand': 'CUCP-DU',
                      'UEContextReleaseComplete': 'CUCP-DU',
                      'UEContextModificationRequest': 'CUCP-DU',
                      'UEContextModificationResponse': 'DU-CUCP',
                      'UEContextModificationFailure': 'DU-CUCP',
                      'UEContextModificationRequired': 'DU-CUCP',
                      'UEContextModificationConfirm': 'CUCP-DU',
                      'UEContextReleaseRequest': 'DU-CUCP',
                      'ngapUEContextReleaseRequest': 'CUCP-AMF',
                      'ngapUEContextReleaseCommand': 'AMF-CUCP',
                      'ngapUEContextReleaseComplete': 'CUCP-AMF',
                      'DL-DCCH-Message': 'CUCP-DU',
                      'UL-DCCH-Message': 'DU-CUCP',
                      'ServiceRequest': "CUCP-AMF",
                      'InitialULRRCMessageTransfer': "DU-CUCP",
                      'InitialContextSetupRequest': 'AMF-CUCP',
                      'InitialContextSetupResponse': 'CUCP-AMF',
                      'InitialUEMessage': 'CUCP-AMF',
                      'InitialContextSetupFailure': "CUCP-AMF",
                      'PathSwitchRequest': 'CUCP-AMF',
                      'PathSwitchRequestAcknowledge': 'AMF-CUCP',
                      'PathSwitchRequestFailure': 'AMF-CUCP',
                      'Paging': 'AMF-CUCP',
                      'HandoverFailure': "CUCP-AMF",
                      'HandoverCancelAcknowledge': 'AMF-CUCP',
                      'HandoverSuccess': 'AMF-CUCP',
                      'HandoverRequest': "AMF-CUCP",
                      'HandoverRequestAcknowledge': "CUCP-AMF",
                      'HandoverRequired': 'CUCP-AMF',
                      'HandoverCommand': "AMF-CUCP",
                      'HandoverPreparationFailure': "AMF-CUCP",
                      'securityModeFailure': "DU-CUCP",
                      'rrcReestablishmentRequest': "CUCP-DU",
                      "rrcReestablishment": "CUCP-DU",
                      "securityModeCommand": "CUCP-DU",
                      "rrcResume": "CUCP-DU",
                      "rrcRelease": "CUCP-DU",
                      "dlInformationTransfer": "CUCP-DU",
                      "ueCapabilityEnquiry": "CUCP-DU",
                      "counterCheck": "CUCP-DU",
                      "mobilityFromNRCommand": "CUCP-DU",
                      "dlDedicatedMessageSegment-r16": "CUCP-DU",
                      "ueInformationRequest-r16": "CUCP-DU",
                      "dlInformationTransferMRDC-r16": "CUCP-DU",
                      "loggedMeasurementConfiguration-r16": "CUCP-DU",
                      "measurementReport": "DU-CUCP",
                      "rrcReconfigurationComplete": "DU-CUCP",
                      "rrcReconfiguration": "CUCP-DU",
                      "rrcSetupComplete": "DU-CUCP",
                      "rrcReestablishmentComplete": "DU-CUCP",
                      "rrcResumeComplete": "DU-CUCP",
                      "securityModeComplete": "DU-CUCP",
                      "securityModeFailure": "DU-CUCP",
                      "ulInformationTransfer": "DU-CUCP",
                      "locationMeasurementIndication": "DU-CUCP",
                      "ueCapabilityInformation": "DU-CUCP",
                      "counterCheckResponse": "DU-CUCP",
                      "ueAssistanceInformation": "DU-CUCP",
                      "failureInformation": "DU-CUCP",
                      "ulInformationTransferMRDC": "DU-CUCP",
                      "scgFailureInformation": "DU-CUCP",
                      "scgFailureInformationEUTRA": "DU-CUCP",
                      "ulDedicatedMessageSegment-r16": "DU-CUCP",
                      "dedicatedSIBRequest-r16": "DU-CUCP",
                      "mcgFailureInformation-r16": "DU-CUCP",
                      "ueInformationResponse-r16": "DU-CUCP",
                      "sidelinkUEInformationNR-r16": "DU-CUCP",
                      "ulInformationTransferIRAT-r16": "DU-CUCP",
                      "iabOtherInformation-r16": "DU-CUCP",
                      "spare9": "DU-CUCP",
                      "spare8": "DU-CUCP",
                      "spare7": "DU-CUCP",
                      "spare6": "DU-CUCP",
                      "spare5": "DU-CUCP",
                      "spare4": "DU-CUCP",
                      "spare3": "DU-CUCP",
                      "spare2": "DU-CUCP",
                      "spare1": "DU-CUCP",
                      "rrcSystemInfoRequest": "DU-CUCP",

                      }


def packetAnalyzer(pcap_file):
    print("calling...")
    fields_dict = {}

    num_processes = multiprocessing.cpu_count()  # use all available CPUs

    packets = pyshark.FileCapture(pcap_file, display_filter='f1ap or e1ap or ngap',
                                  tshark_path="C:\Program Files\Wireshark", )
    for packet in packets:
        t = sys.getsizeof(packet)
        print(t)
        frame_number = packet.frame_info.number
        timestamp = packet.sniff_timestamp
        frame_time = datetime.datetime.fromtimestamp(float(timestamp))
        frame_time = frame_time.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S-%f')
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        if "f1ap" in (layer.layer_name.lower() for layer in packet.layers):
            layer_fields = packet.f1ap._all_fields
            packet = packet_dict(packet)
            print(packet)
            message_desc = get_message_desc(packet)
            procedurecode = layer_fields.get("f1ap.procedureCode")
            if message_desc == "rrcSetupRequest":
                if 'rrcSetupRequest' in message_entity_map.keys():
                    src_entity, dst_entity = message_entity_map.get('rrcSetupRequest').split('-')
                    process_rrc_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                              frame_time, src_entity, dst_entity)
                # elif procedurecode == "12":
            elif message_desc == "rrcSetup":
                src_entity, dst_entity = message_entity_map.get('rrcSetup').split('-')
                process_rrc_setup(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                  src_entity, dst_entity)

            elif message_desc == "rrcSetupComplete":
                src_entity, dst_entity = message_entity_map.get('rrcSetupComplete').split('-')
                process_rrc_setup_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                           frame_time, src_entity, dst_entity)
                # elif procedurecode == "13":
                '''elif message_desc == "securityModeCommand":
                src_entity, dst_entity = message_entity_map.get('securityModeCommand').split('-')
                process_rrc_security_mode_command(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                  frame_time, src_entity, dst_entity)
            # message_desc = get_message_desc(layer_fields)
            elif message_desc == "securityModeComplete":
                src_entity, dst_entity = message_entity_map.get('securityModeComplete').split('-')

                process_security_mode_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                               frame_time, src_entity, dst_entity)

            elif message_desc == "securityModeFailure":
                src_entity, dst_entity = message_entity_map.get('securityModeFailure').split('-')
                process_security_mode_failure(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                              frame_time, src_entity, dst_entity)
            elif message_desc == "measurementReport":
                src_entity, dst_entity = message_entity_map.get('measurementReport').split('-')
                process_measurement_report(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                           frame_time, src_entity, dst_entity)'''

            elif procedurecode == '5':
                if layer_fields.get('f1ap.UEContextSetupRequest_element') == "UEContextSetupRequest":
                    src_entity, dst_entity = message_entity_map.get('UEContextSetupRequest').split('-')
                    process_ue_context_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                     frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get('f1ap.UEContextSetupResponse_element') == "UEContextSetupResponse":
                    src_entity, dst_entity = message_entity_map.get('UEContextSetupResponse').split('-')
                    process_ue_context_setup_response(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                      frame_number, frame_time, src_entity, dst_entity)
            elif procedurecode == '7':
                if layer_fields.get('f1ap.UEContextModificationRequest_element') == "UEContextModificationRequest":
                    src_entity, dst_entity = message_entity_map.get('UEContextModificationRequest').split('-')
                    process_ue_context_setup_mod_request(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                         frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get('f1ap.UEContextModificationResponse_element') == "UEContextModificationResponse":
                    src_entity, dst_entity = message_entity_map.get('UEContextModificationResponse').split('-')
                    process_ue_context_setup_mod_response(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                          frame_number, frame_time, src_entity, dst_entity)
            elif procedurecode == '6':
                if layer_fields.get('f1ap.UEContextReleaseCommand_element') == "UEContextReleaseCommand":
                    src_entity, dst_entity = message_entity_map.get('UEContextReleaseCommand').split('-')
                    process_ue_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                       frame_number, frame_time, src_entity, dst_entity)
            elif layer_fields.get('f1ap.UEContextReleaseComplete_element') == "UEContextReleaseComplete":
                src_entity, dst_entity = message_entity_map.get('UEContextReleaseComplete').split('-')
                process_ue_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                    frame_number, frame_time, src_entity, dst_entity)

            else:
                if procedurecode == '12':
                    message_desc = get_message(layer_fields)
                    if message_desc is not None:
                        src_entity, dst_entity = message_entity_map.get(message_desc).split('-')
                    else:
                        src_entity, dst_entity = message_entity_map.get('DL-DCCH-Message').split('-')
                    process_f1ap_dl_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                             frame_number, frame_time, src_entity, dst_entity, message_desc)
                elif procedurecode == '13':

                    message_desc1 = get_message(layer_fields)
                    if message_desc is not None:
                        src_entity, dst_entity = message_entity_map.get(message_desc).split('-')
                    else:
                        src_entity, dst_entity = message_entity_map.get('UL-DCCH-Message').split('-')
                    process_f1ap_ul_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                             frame_number, frame_time, src_entity, dst_entity, message_desc1)

                    # process_ue_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip,
                    #    frame_number, frame_time, src_entity, dst_entity)
        if "E1AP" in (layer.layer_name.upper() for layer in packet):

            layer_fields = packet.e1ap._all_fields
            procedurecode = layer_fields.get("e1ap.procedureCode")
            if procedurecode == '8':
                if layer_fields.get('e1ap.BearerContextSetupRequest_element') == "BearerContextSetupRequest":
                    src_entity, dst_entity = message_entity_map.get('BearerContextSetupRequest').split('-')
                    process_e1ap_bearer_context_setup_req(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                          frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get('e1ap.BearerContextSetupResponse_element') == "BearerContextSetupResponse":
                    src_entity, dst_entity = message_entity_map.get('BearerContextSetupResponse').split('-')
                    process_e1ap_bearer_context_setup_resp(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                           frame_number, frame_time, src_entity, dst_entity)
            elif procedurecode == '9':
                if layer_fields.get(
                        'e1ap.BearerContextModificationRequest_element') == "BearerContextModificationRequest":
                    src_entity, dst_entity = message_entity_map.get('BearerContextModificationRequest').split('-')
                    process_e1ap_bearer_context_mod_req(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                        frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get(
                        'e1ap.BearerContextModificationResponse_element') == "BearerContextModificationResponse":
                    src_entity, dst_entity = message_entity_map.get('BearerContextModificationResponse').split('-')
                    process_e1ap_bearer_context_mod_res(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                        frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get(
                        'e1ap.BearerContextModificationFailure_element') == "BearerContextModificationFailure":
                    src_entity, dst_entity = message_entity_map.get('BearerContextModificationFailure').split('-')
            elif procedurecode == '11':
                if layer_fields.get(
                        'e1ap.BearerContextReleaseCommand_element') == "BearerContextReleaseCommand":
                    src_entity, dst_entity = message_entity_map.get('BearerContextReleaseCommand').split('-')
                    process_e1ap_bearer_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                                frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get(
                        'e1ap.BearerContextReleaseComplete_element') == "BearerContextReleaseComplete":
                    src_entity, dst_entity = message_entity_map.get('BearerContextReleaseComplete').split('-')
                    process_e1ap_bearer_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                                 frame_number, frame_time, src_entity, dst_entity)


            elif procedurecode == '13':
                if layer_fields.get(
                        'e1ap.BearerContextInactivityNotification_element') == "BearerContextInactivityNotification":
                    src_entity, dst_entity = message_entity_map.get('BearerContextInactivityNotification').split('-')
                    process_e1ap_bearer_context_release_inact(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                              frame_number, frame_time, src_entity, dst_entity)


        elif "ngap" in [layer.layer_name.lower() for layer in packet.layers]:

            layer_fields = packet.ngap._all_fields
            procedurecode = layer_fields.get("ngap.procedureCode")
            if layer_fields.get('nas_5gs.mm.message_type') == "0x41":
                src_entity, dst_entity = message_entity_map.get('registrationRequest').split('-')
                update_status(fields_dict, frame_time, "registrationRequest")
                process_ngap_registration_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                  frame_time, src_entity, dst_entity)
            elif layer_fields.get('nas_5gs.mm.message_type') == "0x4c":
                src_entity, dst_entity = message_entity_map.get('ServiceRequest').split('-')
                process_ngap_service_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                             frame_time, src_entity, dst_entity)
            elif procedurecode == "14":

                if layer_fields.get(
                        'ngap.InitialContextSetupRequest_element') == "InitialContextSetupRequest":
                    update_status(fields_dict, frame_time, "InitialContextSetupRequest")
                    src_entity, dst_entity = message_entity_map.get('InitialContextSetupRequest').split('-')
                    process_ngap_initial_context_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                               frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get(
                        'ngap.InitialContextSetupResponse_element') == "InitialContextSetupResponse":
                    src_entity, dst_entity = message_entity_map.get('InitialContextSetupResponse').split('-')
                    update_status(fields_dict, frame_time, "InitialContextSetupResponse")
                    process_ngap_initial_context_setup_response(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                                frame_number, frame_time, src_entity, dst_entity)

                else:
                    src_entity, dst_entity = message_entity_map.get('InitialContextSetupFailure').split('-')
                    update_status(fields_dict, frame_time, "InitialContextSetupFailure")
                    process_ngap_initial_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                               frame_number, frame_time, src_entity, dst_entity)

            elif procedurecode == "42":
                if layer_fields.get(
                        'ngap.UEContextReleaseRequest_element') == "UEContextReleaseRequest":
                    src_entity, dst_entity = message_entity_map.get('ngapUEContextReleaseRequest').split('-')
                    process_ngap_context_release_request(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                         frame_number, frame_time, src_entity, dst_entity)
            elif procedurecode == "41":
                if layer_fields.get(
                        'ngap.UEContextReleaseCommand_element') == "UEContextReleaseCommand":
                    src_entity, dst_entity = message_entity_map.get('ngapUEContextReleaseCommand').split('-')
                    process_ngap_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                         frame_number, frame_time, src_entity, dst_entity)
                elif layer_fields.get(
                        'ngap.UEContextReleaseComplete_element') == "UEContextReleaseComplete":
                    src_entity, dst_entity = message_entity_map.get('ngapUEContextReleaseComplete').split('-')
                    process_ngap_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                          frame_number, frame_time, src_entity, dst_entity)


                else:
                    src_entity, dst_entity = message_entity_map.get('InitialContextSetupFailure').split('-')
                    process_ngap_initial_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                               frame_number, frame_time, src_entity, dst_entity)

            else:
                pass
        #    loop.stop()  # stop the event loop
        # loop.close()  # close the event loop
        del packet
    return fields_dict


def get_message_desc(layer_fields):
    for key, value in my_dict.items():
        if key in layer_fields.values():
            c1_value = layer_fields.get('nr-rrc.c1')

            if c1_value is not None and c1_value in value:
                return value[c1_value]
    return None


def packet_dict(packet):
    print(packet)
    # Extract IP layer if it exists
    if 'IP' in packet:
        ip_layer = packet.ip._all_fields
    else:
        ip_layer = {}

    # Extract F1AP layer if it exists
    if 'F1AP' in packet:
        f1ap_layer = packet.f1ap._all_fields

    else:
        f1ap_layer = {}

    # Extract NGAP layer if it exists
    if 'NGAP' in packet:
        ngap_layer = packet.ngap._all_fields
    else:
        ngap_layer = {}
    # Extract E1AP layer if it exists
    if 'E1AP' in packet:
        e1ap_layer = packet.e1ap._all_fields
    else:
        e1ap_layer = {}
    # Combine all layers into a single dictionary
    packet_dict = {**ip_layer, **f1ap_layer, **ngap_layer, **e1ap_layer}
    new_dict = {}
    return packet_dict


def get_message(layer_fields):
    for key, value in rrc_dict.items():
        if key in layer_fields.values():
            c1_value = layer_fields.get('nr-rrc.c1')
            c2_value = layer_fields.get('nr-rrc.c2')
            if c1_value is not None:
                v = value["c1"].get(c1_value)
                if v is None:
                    v = key
                return v
            elif c2_value is not None:
                v = value["c2"].get(c2_value)
                if v is None:
                    v = key
                return v

            else:
                return key


def process_rrc_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                              dst_entity):
    c_rnti = layer_fields.get('f1ap.C_RNTI')
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    establish_desc = ""
    key = f"{c_rnti}_{gnb_du_ue_f1ap_id}"
    if key not in fields_dict:
        fields_dict[key] = {"c_rnti": c_rnti,
                            "gnb_du_ue_f1ap_id": gnb_du_ue_f1ap_id,
                            "gnb_cu_ue_f1ap_id": None,
                            "gnb_cu_cp_ue_e1ap_id": None,
                            "gnb_cu_up_ue_e1ap_id": None,
                            "ran_ue_ngap_id": None,
                            "amf_ue_ngap_id": None,
                            f"rrcSetupRequest_{frame_number}": {
                                "src_node-src_ip": f'{src_entity}_{src_ip}',
                                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                                "packet": packet,
                                "frame_time": frame_time,
                            },
                            "rrcSetupRequest": "Attempt"
                            }


def process_rrc_setup(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                      dst_entity):
    gnb_du_ue_f1ap_id = layer_fields['f1ap.GNB_DU_UE_F1AP_ID']
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id:
        for key, value in fields_dict.items():
            if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and value.get(
                    "gnb_cu_ue_f1ap_id") is None:
                value[f"rrcSetup_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id


def process_rrc_setup_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                               dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    for key, value in fields_dict.items():
        if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and value.get(
                "gnb_cu_ue_f1ap_id") == gnb_cu_ue_f1ap_id:
            value[f"rrcSetupComplete_{frame_number}"] = {
                "src_node-src_ip": f'{src_entity}_{src_ip}',
                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                "packet": packet,
                "frame_time": frame_time,
            }
            value["rrcSetupRequest"] = "Success"


def process_rrc_setup_release(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                              dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    for key, value in fields_dict.items():
        if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and value.get(
                "gnb_cu_ue_f1ap_id") == gnb_cu_ue_f1ap_id:
            value[f"rrcSetupComplete_{frame_number}"] = {
                "src_node-src_ip": f'{src_entity}_{src_ip}',
                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                "packet": packet,
                "frame_time": frame_time,
            }
            value["rrcSetup"] = "Success"


def process_rrc_security_mode_command(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                      src_entity,
                                      dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"SecurityModeCommand_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,

                    }


def process_security_mode_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                   src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')

    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"SecurityModeComplete_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_security_mode_failure(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                  src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"SecurityModeCommandFailure_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_measurement_report(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                               src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"measurementReport_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                     src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value["rrcSetupRequest"] == "Success":
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"UEContextSetupRequest_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_response(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                      src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value["rrcSetupRequest"] == "Success":
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"UEContextSetupResponse_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_mod_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                         src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value["rrcSetupRequest"] == "Success":
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"UEContextModificationRequest_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_mod_response(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                          src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value["rrcSetupRequest"] == "Success":
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"UEContextModificationResponse_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                     src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"ueContextSetupResponse_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                     src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                    value[f"ueContextSetupResponse_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }


def process_ue_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                       frame_number, frame_time, src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"UEContextReleaseCommand_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    for k, v in value.items():
                        if "rrcSetupRequest_" in k:
                            time = v["frame_time"]
                            # calculate the difference between the timestamps
                            t2 = datetime.datetime.strptime(frame_time, '%Y-%m-%d-%H-%M-%S-%f')
                            t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                            time_diff = t2 - t1
                            # check if the difference is less than or equal to one second
                            if time_diff == datetime.timedelta(seconds=1):
                                # log the message
                                value["rrcSetupRequest"] = "Failure"
                                break


def process_ue_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                        frame_number, frame_time, src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"UEContextReleaseComplete_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    value["regStatus"] = "Failure"


def process_f1ap_dl_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                             frame_number, frame_time, src_entity, dst_entity, message_desc):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
        update_status(fields_dict, frame_time, message_desc)


def process_f1ap_ul_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                             frame_number, frame_time, src_entity, dst_entity, message_desc):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
        update_status(fields_dict, frame_time, message_desc)


def update_status(fields_dict, frame_time, message):
    t2 = datetime.datetime.strptime(frame_time, '%Y-%m-%d-%H-%M-%S-%f')
    _10s = datetime.timedelta(seconds=10)
    _1s = datetime.timedelta(seconds=1)
    _3s = datetime.timedelta(seconds=3)
    for key, value in fields_dict.items():
        for k, v in value.items():
            if message == "securityModeCommand":
                value["securityModeCommand"] = "Attempt"
                break
            elif "securityModeCommand_" in k and message == "securityModeComplete":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["securityModeCommand"] = "Success"
                    break
                else:
                    value["securityModeCommand"] = "Failure"
                    break
            # RRC
            if message == "rrcResumeRequest":
                value["rrcResumeRequest"] = "Attempt"
                break
            elif "rrcResumeRequest_" in k and message == "rrcResumeComplete":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["rrcResumeRequest"] = "Success"
                    break
                else:
                    value["rrcResumeRequest"] = "Failure"
                    break
            if message == "rrcReestablishmentRequest":
                value["rrcReestablishmentRequest"] = "Attempt"
                break
            elif "rrcReestablishmentRequest_" in k and message == "rrcReestablishmentComplete":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["rrcReestablishmentRequest"] = "Success"
                    break
                else:
                    value["rrcReestablishmentRequest"] = "Failure"
                    break
            if message == "ueInformationRequest-r16":
                value["ueInformationRequest-r16"] = "Attempt"
                break
            elif "ueInformationRequest-r16_" in k and message == "ulInformationTransfer":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["ueInformationRequest-r16"] = "Success"
                    break
                else:
                    value["ueInformationRequest-r16"] = "Failure"
                    break
            if message == "ueCapabilityEnquiry":
                value["ueCapabilityEnquiry"] = "Attempt"
                break
            elif "ueCapabilityEnquiry_" in k and message == "ueCapabilityInformation":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["ueCapabilityEnquiry"] = "Success"
                    break
                else:
                    value["ueCapabilityEnquiry"] = "Failure"
                    break
            if message == "rrcReconfiguration":
                value["rrcReconfiguration"] = "Attempt"
                break
            elif "rrcReconfiguration_" in k and message == "rrcReconfigurationComplete":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["rrcReconfiguration"] = "Success"
                    break
                else:
                    value["rrcReconfiguration"] = "Failure"
                    break
            if message == "BearerContextSetupRequest":
                value["BearerContextSetupRequest"] = "Attempt"
                break
            elif "BearerContextSetupRequest_" in k and message == "BearerContextSetupResponse":
                time = v["frame_time"]
                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _3s:
                    value["BearerContextSetupRequest"] = "Failure"
                    break
                else:
                    value["BearerContextSetupRequest"] = "Failure"
                    break
            elif "BearerContextSetupFailure_" in k:
                value["BearerContextSetupRequest"] = "Failure"
                break
            if message == "InitialContextSetupRequest":
                value["InitialContextSetupRequest"] = "Attempt"
                break
            elif "InitialContextSetupRequest_" in k and message == "InitialContextSetupResponse":
                time = v["frame_time"]

                t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
                time_diff = t2 - t1
                if time_diff <= _10s:
                    value["InitialContextSetupRequest"] = "Success"
                    break
                else:
                    value["InitialContextSetupRequest"] = "Failure"
                    break
            elif "InitialContextSetupFailure_" in k:
                value["InitialContextSetupRequest"] = "Failure"
                break


def get_failure_reason(layer_fields):
    cause_code = layer_fields.get('f1ap.Cause')
    if cause_code in cause_code_to_desc:
        cause_desc = cause_code_to_desc[cause_code]
        misc_code = layer_fields.get('f1ap.misc')
        rn_code = layer_fields.get('f1ap.radioNetwork')
        if misc_code in misc_code_to_desc:
            misc_desc = misc_code_to_desc[misc_code]
        elif rn_code in cause_radio_network_dict:
            misc_desc = cause_radio_network_dict[rn_code]
        else:
            misc_desc = 'Unknown Misc'
    else:
        cause_desc = 'Unknown Code'
        misc_desc = 'Unknown Misc'
    failure_reason = cause_desc + '_' + misc_desc
    return failure_reason


# Process E1AP messages

def process_e1ap_bearer_context_setup_req(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                          src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                value["gnb_cu_cp_ue_e1ap_id"] = gnb_cu_cp_ue_e1ap_id
                value[f"BearerContextSetupRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                value["BearerContextSetup"] = 'Init'


def process_e1ap_bearer_context_setup_resp(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                           src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                value[f"BearerContextSetupResponse_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                value["BearerContextSetup"] = 'Success'


def process_e1ap_bearer_context_mod_req(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                        src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value['gnb_cu_cp_ue_e1ap_id'] and gnb_cu_up_ue_e1ap_id == value[
                'gnb_cu_up_ue_e1ap_id']:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextModificationRequest_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextMod"] = 'Init'


def process_e1ap_bearer_context_mod_res(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                        src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextModificationResponse_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextMod"] = 'Success'


def process_e1ap_bearer_context_mod_fail(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                         src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextModificationFailure_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextMod"] = 'Failure'


def process_e1ap_bearer_context_mod_required(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                             frame_time,
                                             src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextModificationRequired_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextModRequired"] = 'Init'


def process_e1ap_bearer_context_mod_confirm(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                            frame_time,
                                            src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextModificationConfirm_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextModRequired"] = 'Success'


def process_e1ap_bearer_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                frame_time,
                                                src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextReleaseCommand_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextRelease"] = 'Init'


def process_e1ap_bearer_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                 frame_time,
                                                 src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextReleaseComplete_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextRelease"] = 'Success'


def process_e1ap_bearer_context_release_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                frame_time,
                                                src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextReleaseRequest_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextRelease"] = 'Init'


def process_e1ap_bearer_context_release_inact(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                              frame_time,
                                              src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                "gnb_cu_up_ue_e1ap_id"]:
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value["rrcSetupRequest"] == "Success":
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"BearerContextInactivityNotification_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                value["BearerContextRelease"] = 'Success'


# NGAP procedures

def process_ngap_registration_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                      frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("gnb_cu_ue_f1ap_id") and value.get("AMF_UE_NGAP_ID") is None and value[
                "rrcSetupRequest"] == "Success":
                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value["amf_ue_ngap_id"] = None
                value[f"registrationRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Init'


def process_ngap_service_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                 frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():

            if ran_ue_ngap_id == value.get("gnb_cu_ue_f1ap_id") and value.get("AMF_UE_NGAP_ID") is None and value[
                "rrcSetupRequest"] == "Success":
                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value["amf_ue_ngap_id"] = None
                value[f"ServiceRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Init'
            break


def process_ngap_initial_context_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                               frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value.get("amf_ue_ngap_id") == None:
                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value['amf_ue_ngap_id'] = amf_ue_ngap_id
                value[f"InitialContextSetupRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Init'


def process_ngap_initial_context_setup_response(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                                frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value['amf_ue_ngap_id'] == amf_ue_ngap_id:
                value[f"InitialContextSetupResponse_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Success'


def process_ngap_context_release_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                         frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value['amf_ue_ngap_id'] == amf_ue_ngap_id:
                value[f"UEContextReleaseRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Success'


def process_ngap_context_release_command(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                         frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value['amf_ue_ngap_id'] == amf_ue_ngap_id:
                value[f"UEContextReleaseCommand_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Success'


def process_ngap_context_release_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                          frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value['amf_ue_ngap_id'] == amf_ue_ngap_id:
                value[f"UEReleaseComplete_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["RegStatus"] = 'Success'


def process_ngap_initial_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                               frame_time, src_entity, dst_entity):
    ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
    amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']
    if ran_ue_ngap_id:
        for key, value in fields_dict.items():
            if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value['amf_ue_ngap_id'] == amf_ue_ngap_id:
                value[f"InitialContextSetupFailure_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,

                }
                value["ServiceReq"] = 'Init'


'''if __name__ == '__main__':
    pcap_file = r'lv007.pcap'
    test = packetAnalyzer(pcap_file)
    for key in test:
        for value in test[key].keys():
            if "rrcSetupRequest_" in value:
                print("end")'''
