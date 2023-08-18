import datetime
import multiprocessing
from collections import defaultdict

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

ngap_dict = {
    "registrationRequest": "0x40",
    "registrationAccept": "0x42",
    "registrationComplete": "0x43",
    "registrationReject": "0x44",
    "deregistrationRequest(UEOriginating)": "0x45",
    "deregistrationAccept(UEOriginating)": "0x46",
    "deregistrationRequest(UETerminated)": "0x47",
    "deregistrationAccept(UETerminated)": "0x48",
    "serviceRequest": "0x4C",
    "serviceReject": "0x4D",
    "serviceAccept": "0x4E",
    "configurationUpdateCommand": "0x54",
    "configurationUpdateComplete": "0x55",
    "authenticationRequest": "0x58",
    "authenticationResponse": "0x59",
    "authenticationReject": "0x5A",
    "authenticationFailure": "0x5B",
    "authenticationResult": "0x5C",
    "identityRequest": "0x5D",
    "identityResponse": "0x5E",
    "securityModeCommand": "0x5F",
    "securityModeComplete": "0x60",
    "securityModeReject": "0x61",
    "5GMMStatus": "0x68",
    "notification": "0x69",
    "notificationResponse": "0x6A",
    "ULNASTransport": "0x6B",
    "DLNASTransport": "0x70",
    "pduSessionEstablishmentRequest": "0xC1",
    "pduSessionEstablishmentAccept": "0xC2",
    "pduSessionEstablishmentReject": "0xC3",
    "pduSessionAuthenticationCommand": "0xC5",
    "pduSessionAuthenticationComplete": "0xC6",
    "pduSessionAuthenticationResult": "0xC7",
    "pduSessionModificationRequest": "0xCA",
    "pduSessionModificationReject": "0xCB",
    "pduSessionModificationCommand": "0xCC",
    "pduSessionModificationComplete": "0xCD",
    "pduSessionModificationCommandReject": "0xCE",
    "pduSessionReleaseRequest": "0xD1",
    "pduSessionReleaseReject": "0xD2",
    "pduSessionReleaseCommand": "0xD3",
    "pduSessionReleaseComplete": "0xD4",
    "5GSMStatus": "0xD6"
}

rrc_dict = defaultdict(lambda: defaultdict(lambda: 'UnknownMessage'))

rrc_dict.update({
    'DL-CCCH-Message': {
        'c1': {
            '0': "rrcReject",
            '1': "rrcSetup"
        }
    },
    'DL-DCCH-Message': {
        'c1': {
            '0': "rrcReconfiguration",
            '1': "rrcResume",
            '2': "rrcRelease",
            '3': "rrcReestablishment",
            '4': "securityModeCommand",
            '5': "dlInformationTransfer",
            '6': "ueCapabilityEnquiry",
            '7': "counterCheck",
            '8': "mobilityFromNRCommand",
            '9': "dlDedicatedMessageSegment-r16",
            '10': "ueInformationRequest-r16",
            '11': "dlInformationTransferMRDC-r16",
            '12': "loggedMeasurementConfiguration-r16"
        }
    },
    'PCCH-Message': {
        'c1': {
            '0': "paging"
        }
    },
    "UL-CCCH-Message": {
        'c1': {
            "0": "rrcSetupRequest",
            "1": "rrcResumeRequest",
            "2": "rrcReestablishmentRequest",
            "3": "rrcSystemInfoRequest",
        }
    },
    'UL-DCCH-Message': {
        'c1': {
            "0": "measurementReport",
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
            "15": "scgFailureInformationEUTRA"
        },
        'c2': {
            "0": "ulDedicatedMessageSegment-r16",
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
        }
    }
})

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
                      'serviceRequest': "CUCP-AMF",
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
                      "registrationReject": "AMF-CUCP",
                      "identityRequest": "AMF-CUCP",
                      "deregistrationRequest(UEOriginating)": "CUCP-AMF",
                      "authenticationFailure": "CUCP-AMF",
                      "authenticationResult": "AMF-CUCP"

                      }


def packet_generator(pcap_file):
    with pyshark.FileCapture(pcap_file, display_filter='f1ap or e1ap or ngap') as packets:
        for packet in packets:
            yield packet


def packetAnalyzer(pcap_file):
    print("calling...")

    # fields_dict = {}
    fields_dict = defaultdict(list)

    num_processes = multiprocessing.cpu_count()  # use all available CPUs

    # packets = pyshark.FileCapture(pcap_file, display_filter='f1ap or e1ap or ngap')
    for packet in packet_generator(pcap_file):
        frame_number = packet.frame_info.number
        timestamp = packet.sniff_timestamp
        frame_time = datetime.datetime.fromtimestamp(float(timestamp))
        frame_time = frame_time.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S-%f')
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        if "f1ap" not in (layer.layer_name.lower() for layer in packet.layers):
            return

        layer_fields = packet.f1ap._all_fields
        packet_dict = dict(packet)
        message_desc = get_message_desc(packet_dict)
        procedurecode = layer_fields.get("f1ap.procedureCode")

        message_processing_map = {
            "rrcSetupRequest": process_rrc_setup_request,
            "rrcSetup": process_rrc_setup,
            "rrcSetupComplete": process_rrc_setup_complete,
            "UEContextSetupRequest": process_ue_context_setup_request,
            "UEContextSetupResponse": process_ue_context_setup_response,
            "UEContextModificationRequest": process_ue_context_setup_mod_request,
            "UEContextModificationResponse": process_ue_context_setup_mod_response,
            "UEContextReleaseCommand": process_ue_context_release_command,
            "UEContextReleaseComplete": process_ue_context_release_complete,
        }

        if message_desc in message_processing_map:
            src_entity, dst_entity = message_entity_map.get(message_desc).split('-')
            message_processing_map[message_desc](layer_fields, fields_dict, packet_dict, src_ip, dst_ip,
                                                 frame_number, frame_time, src_entity, dst_entity)
        else:
            if procedurecode == '12':
                message_desc = get_message(layer_fields)
                if message_desc is not None:
                    src_entity, dst_entity = message_entity_map.get(message_desc).split('-')
                else:
                    src_entity, dst_entity = message_entity_map.get('DL-DCCH-Message').split('-')
                process_f1ap_dl_rrc_trfr(layer_fields, fields_dict, packet_dict, src_ip, dst_ip,
                                         frame_number, frame_time, src_entity, dst_entity, message_desc)
            elif procedurecode == '13':
                message_desc = get_message(layer_fields)
                if message_desc is not None:
                    src_entity, dst_entity = message_entity_map.get(message_desc).split('-')
                else:
                    src_entity, dst_entity = message_entity_map.get('UL-DCCH-Message').split('-')
                process_f1ap_ul_rrc_trfr(layer_fields, fields_dict, packet_dict, src_ip, dst_ip,
                                         frame_number, frame_time, src_entity, dst_entity, message_desc)

        if "e1ap" in packet:
            layer_fields = packet.e1ap._all_fields
            packet = packet_dict(packet)
            procedurecode = layer_fields.get("e1ap.procedureCode")

            processing_functions = {
                '8': process_bearer_context_setup,
                '9': process_bearer_context_mod,
                '11': process_bearer_context_release,
                '13': process_bearer_context_release_inact
            }

            processing_function = processing_functions.get(procedurecode)

            if processing_function:
                element = None

                for element_name in ['BearerContextSetupRequest_element', 'BearerContextSetupResponse_element',
                                     'BearerContextModificationRequest_element',
                                     'BearerContextModificationResponse_element',
                                     'BearerContextModificationFailure_element', 'BearerContextReleaseCommand_element',
                                     'BearerContextReleaseComplete_element',
                                     'BearerContextInactivityNotification_element']:
                    if layer_fields.get(element_name):
                        element = layer_fields.get(element_name)
                        break

                src_entity, dst_entity = message_entity_map.get(element).split('-')
                processing_function(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                    src_entity, dst_entity)

        if "ngap" in packet:
            layer_fields = packet.ngap._all_fields
            packet = packet_dict(packet)
            procedurecode = layer_fields.get("ngap.procedureCode")
            ngap_msg_desc = get_ngap_message(layer_fields)
            if ngap_msg_desc is not None:
                print(ngap_msg_desc)
                src_entity, dst_entity = message_entity_map[ngap_msg_desc].split('-')
                ngap_functions = {
                    "14-InitialContextSetupRequest": process_ngap_initial_context_setup_request,
                    "14-InitialContextSetupResponse": process_ngap_initial_context_setup_response,
                    "14-InitialContextSetupFailure": process_ngap_initial_context_setup_failure,
                    "41-UEContextReleaseCommand": process_ngap_context_release_command,
                    "41-UEContextReleaseComplete": process_ngap_context_release_complete,
                    "42-UEContextReleaseRequest": process_ngap_context_release_request
                }
                ngap_functions.get(f"{procedurecode}-{ngap_msg_desc}", lambda *_: None)(layer_fields, fields_dict,
                                                                                        packet, src_ip, dst_ip,
                                                                                        frame_number, frame_time,
                                                                                        src_entity, dst_entity)
            else:
                src_entity, dst_entity = message_entity_map.get('InitialContextSetupFailure').split('-')
                process_ngap_initial_context_setup_failure(layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                           frame_number, frame_time, src_entity, dst_entity)
        #    loop.stop()  # stop the event loop
        # loop.close()  # close the event loop
        del packet
        del layer_fields
    return fields_dict


def get_message_desc(layer_fields):
    for key, value in my_dict.items():
        if key in layer_fields.values():
            c1_value = layer_fields.get('nr-rrc.c1')

            if c1_value is not None and c1_value in value:
                return value[c1_value]
    return None


def packet_dict(packet):
    # Extract all layers into a single dictionary
    ip_layer = packet.ip._all_fields if 'IP' in packet else {}
    f1ap_layer = packet.f1ap._all_fields if 'F1AP' in packet else {}
    ngap_layer = packet.ngap._all_fields if 'NGAP' in packet else {}
    e1ap_layer = packet.e1ap._all_fields if 'E1AP' in packet else {}
    packet_dict = {**ip_layer, **f1ap_layer, **ngap_layer, **e1ap_layer}
    return packet_dict


def get_message(layer_fields):
    for key, value in rrc_dict.items():
        if key in layer_fields.values():
            c1_value = layer_fields.get('nr-rrc.c1')
            c2_value = layer_fields.get('nr-rrc.c2')
            if c1_value is not None:
                return value['c1'].get(c1_value, key)
            elif c2_value is not None:
                return value['c2'].get(c2_value, key)
            else:
                return key
    return 'Unknown Message'


def get_ngap_message(layer_fields):
    mm_message_type = layer_fields.get('nas_5gs.mm.message_type', '').upper()
    sm_message_type = layer_fields.get('nas_5gs.sm.message_type', '').upper()

    for key, value in ngap_dict.items():
        if value.lower() in layer_fields.values():
            if mm_message_type == key.upper():
                return key
            elif sm_message_type == key.upper():
                return value

    return None


def process_rrc_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                              dst_entity):
    c_rnti = layer_fields.get('f1ap.C_RNTI')
    pci = layer_fields.get('nr-rrc.pdcch_DMRS_ScramblingID')
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    key = f"{c_rnti}_{gnb_du_ue_f1ap_id}"
    fields_dict.setdefault(key, {})
    fields_dict[key]["c_rnti"] = c_rnti
    fields_dict[key]["gnb_du_ue_f1ap_id"] = gnb_du_ue_f1ap_id
    fields_dict[key]["gnb_cu_ue_f1ap_id"] = None
    fields_dict[key]["gnb_cu_cp_ue_e1ap_id"] = None


fields_dict[key]["gnb_cu_up_ue_e1ap_id"] = None
fields_dict[key]["ran_ue_ngap_id"] = None
fields_dict[key]["amf_ue_ngap_id"] = None
fields_dict[key][f"rrcSetupRequest_{frame_number}"] = {
    "src_node-src_ip": f'{src_entity}_{src_ip}',
    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
    "packet": packet,
    "frame_time": frame_time,
}
fields_dict[key]["rrcSetupRequest"] = "Attempt"
fields_dict[key]["pci"] = f'{pci}'


def process_rrc_setup(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                      dst_entity):
    gnb_du_ue_f1ap_id = layer_fields['f1ap.GNB_DU_UE_F1AP_ID']
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    match = next((value for value in fields_dict.values() if
                  value["gnb_du_ue_f1ap_id"] == gnb_du_ue_f1ap_id and value.get("gnb_cu_ue_f1ap_id") is None), None)
    if match:
        match[f"rrcSetup_{frame_number}"] = {
            "src_node-src_ip": f'{src_entity}_{src_ip}',
            "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
            "packet": packet,
            "frame_time": frame_time,
        }
        match["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id


def process_rrc_setup_complete(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time, src_entity,
                               dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    for key, value in fields_dict.items():
        if gnb_du_ue_f1ap_id == value.get("gnb_du_ue_f1ap_id") and value.get("gnb_cu_ue_f1ap_id") == gnb_cu_ue_f1ap_id:
            value[f"rrcSetupComplete_{frame_number}"] = {
                "src_node-src_ip": f'{src_entity}_{src_ip}',
                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                "packet": packet,
                "frame_time": frame_time,
            }
            value["rrcSetupRequest"] = "Success"
            break


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
    del packet


def process_ue_context_setup_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                     src_entity, dst_entity):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    for value in fields_dict.values():
        if "gnb_du_ue_f1ap_id" in value and value["gnb_du_ue_f1ap_id"] == gnb_du_ue_f1ap_id \
                and "gnb_cu_ue_f1ap_id" in value and value["gnb_cu_ue_f1ap_id"] == gnb_cu_ue_f1ap_id \
                and value.get("rrcSetupRequest") == "Success":
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
    for value in fields_dict.values():
        if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value["rrcSetupRequest"] == "Success":
            if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id == value["gnb_cu_ue_f1ap_id"]:
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
    del packet


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
    del packet


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
    del packet


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
    del packet


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
    del packet


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
    del packet


def process_f1ap_dl_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                             frame_number, frame_time, src_entity, dst_entity, message_desc):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for key, value in fields_dict.items():
            try:
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value["gnb_cu_ue_f1ap_id"]:
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node-src_ip": f'{src_entity}_{src_ip}',
                        "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    update_status(fields_dict, frame_time, message_desc)
            except KeyError:
                pass


def process_f1ap_ul_rrc_trfr(layer_fields, fields_dict, packet, src_ip, dst_ip,
                             frame_number, frame_time, src_entity, dst_entity, message_desc):
    gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
    gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
    if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
        for value in fields_dict.values():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value \
                    and gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] \
                    and gnb_cu_ue_f1ap_id in value["gnb_cu_ue_f1ap_id"]:
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                update_status(fields_dict, frame_time, message_desc)


def is_success(value, k, message, frame_time, t2, max_time_delta):
    if message in k and message.endswith("Complete"):
        time = value["frame_time"]
        t1 = datetime.datetime.strptime(time, '%Y-%m-%d-%H-%M-%S-%f')
        time_diff = t2 - t1
        if time_diff <= max_time_delta:
            return "Success"
        else:
            return "Failure"
    else:
        return None


def update_status(fields_dict, frame_time, message):
    t2 = datetime.datetime.strptime(frame_time, '%Y-%m-%d-%H-%M-%S-%f')
    max_time_delta = datetime.timedelta(seconds=3)
    bcs_req_attempted = False
    for key, value in fields_dict.items():
        rrc_setup = value.get("rrcSetupRequest") == "Success"
        reg_req_attempted = value.get("registrationRequest") == "Attempt"

        if message == "securityModeCommand" and rrc_setup:
            value["securityModeCommand"] = "Attempt"
            break

        if message == "rrcResumeRequest":
            value["rrcResumeRequest"] = "Attempt"
            break
        result = is_success(value, key, message, frame_time, t2, max_time_delta)
        if result is not None:
            if message == "rrcResumeComplete":
                value["rrcResumeRequest"] = result
                break
            if message == "rrcReestablishmentRequest":
                value["rrcReestablishmentRequest"] = "Attempt"
                break
            elif message == "rrcReestablishmentComplete":
                value["rrcReestablishmentRequest"] = result
                break
            if message == "ueInformationRequest-r16":
                value["ueInformationRequest-r16"] = "Attempt"
                break
            elif message == "ulInformationTransfer":
                value["ueInformationRequest-r16"] = result
                break
            if message == "ueCapabilityEnquiry":
                value["ueCapabilityEnquiry"] = "Attempt"
                break
            elif message == "ueCapabilityInformation":
                value["ueCapabilityEnquiry"] = result
                break
            if message == "rrcReconfiguration":
                value["rrcReconfiguration"] = "Attempt"
                break
            elif message == "rrcReconfigurationComplete":
                value["rrcReconfiguration"] = result
                break
            if message == "BearerContextSetupRequest":
                if reg_req_attempted:
                    value["BearerContextSetupRequest"] = "Attempt"
                    bcs_req_attempted = True
                    break
            elif message == "BearerContextSetupResponse":
                if bcs_req_attempted:
                    value["BearerContextSetupRequest"] = result
                    break
            elif message == "BearerContextSetupFailure":
                if bcs_req_attempted:
                    value["BearerContextSetupRequest"] = "Failure"
                    break

        if (message == "registrationRequest" or message == "serviceRequest") and rrc_setup:
            value["registrationRequest"] = "Attempt"
            break
        elif message == "InitialContextSetupResponse" and reg_req_attempted:
            value["registrationRequest"] = is_success(value, key, message, frame_time, t2, max_time_delta)
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
    gtp_teid = layer_fields.get("e1ap.gTP_TEID")
    if gnb_cu_cp_ue_e1ap_id:
        for key, value in fields_dict.items():
            if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and value[
                "rrcSetupRequest"] == "Success" and \
                    value.get("registrationRequest") == "Attempt" and gtp_teid == value.get('gTP_TEID'):
                value["gnb_cu_cp_ue_e1ap_id"] = gnb_cu_cp_ue_e1ap_id
                value[f"BearerContextSetupRequest_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                update_status(fields_dict, frame_time, "BearerContextSetupRequest")
    del packet


def process_e1ap_bearer_context_setup_resp(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number, frame_time,
                                           src_entity, dst_entity):
    gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
    gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
    if gnb_cu_cp_ue_e1ap_id:
        ctxt_dst_ip = None
        for key, value in fields_dict.items():
            for i, j in fields_dict[key].items():
                if "BearerContextSetupRequest_" in i:
                    ctxt_dst_ip = str(j.get("dst_node-dst_ip").split("_")[1])
                    print(ctxt_dst_ip, src_ip, ctxt_dst_ip == src_ip, dst_ip)

            if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and \
                    value.get("rrcSetupRequest") == "Success" and \
                    value.get("registrationRequest") != "Success" and ctxt_dst_ip == src_ip:
                value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                value[f"BearerContextSetupResponse_{frame_number}"] = {
                    "src_node-src_ip": f'{src_entity}_{src_ip}',
                    "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                update_status(fields_dict, frame_time, "BearerContextSetupResponse")
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


# NGAP procedures

def process_ngap_registration_request(layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                      frame_time, src_entity, dst_entity, message_desc):
    amf_ue_ngap_id = layer_fields.get("ngap.AMF_UE_NGAP_ID")
    ran_ue_ngap_id = layer_fields.get('ngap.RAN_UE_NGAP_ID')
    print("in ngap")
    for key, value in fields_dict.items():
        if ran_ue_ngap_id == value.get("gnb_cu_ue_f1ap_id") and value.get("AMF_UE_NGAP_ID") is None and value.get(
                "rrcSetupRequest") == "Success" and message_desc in ["registrationRequest", "serviceRequest"] and \
                all([f"{message_desc}_" not in value.get(k, "") for k in value]) and value.get(
            "amf_ue_ngap_id") is None:
            value["ran_ue_ngap_id"] = ran_ue_ngap_id
            value["amf_ue_ngap_id"] = None
            value[f"{message_desc}_{frame_number}"] = {
                "src_node-src_ip": f'{src_entity}_{src_ip}',
                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                "packet": packet,
                "frame_time": frame_time,
            }
            update_status(fields_dict, frame_time, message_desc)

        elif ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value.get("amf_ue_ngap_id") is None and \
                any([f"{t}_" in value.get(k, "") for t in ["serviceRequest", "registrationRequest"] for k in value]) and \
                message_desc not in ["registrationRequest", "serviceRequest"]:
            value["ran_ue_ngap_id"] = ran_ue_ngap_id
            value['amf_ue_ngap_id'] = amf_ue_ngap_id
            value[f"InitialContextSetupRequest_{frame_number}"] = {
                "src_node-src_ip": f'{src_entity}_{src_ip}',
                "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                "packet": packet,
                "frame_time": frame_time,
            }
            update_status(fields_dict, frame_time, message_desc)

    del packet


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
                if layer_fields.get('ngap.gTP_TEID'):
                    value["gTP_TEID"] = layer_fields.get('ngap.gTP_TEID')
    del packet


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
                update_status(fields_dict, frame_time, "InitialContextSetupResponse")
        del packet


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
        del packet


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
        del packet


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
        del packet


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
        del packet


'''if __name__ == '__main__':
    pcap_file = r'lv007.pcap'
    test = packetAnalyzer(pcap_file)
    for key in test:
        for value in test[key].keys():
            if "rrcSetupRequest_" in value:
                        self.my_dict = PacketAnalyzer.packetAnalyzer(self.pcap_file)
("end")'''
