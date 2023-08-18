import datetime
import queue
import time
from collections import defaultdict

import pyshark


class PacketAnalyzerN:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.fields_dict = defaultdict(list)
        self.packet_queue = queue.Queue()

        self.ngap_nas_procedures = {
            "registrationRequest": "0x41",
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
        self.ngap_procedures = [
            "14-InitialContextSetupRequest",
            "14-InitialContextSetupResponse",
            "14-InitialContextSetupFailure",
            "19-UEContextReleaseRequest",
            "20-UEContextReleaseCommand",
            "21-UEContextReleaseComplete",
            "42-UEContextReleaseRequest",
            "41-UEContextReleaseCommand",
            "41-UEContextReleaseComplete",
            "19-NASNonDeliveryIndication",
            "46-UplinkNASTransport",
        ]
        self.xnap_procedures = [
            "0-HandoverRequest",
            "19-HandoverResponse",
            "1-SNStatusTransfer",
            "0-HandoverRequestAcknowledge",
            "20-HandoverPreparationFailure",
            "6-UEContextRelease",
            "42-HandoverCancel",
            "41-NotificationControlIndication",
            "41-RetrieveUEContextRequest",
            "19-RetrieveUEContextResponse"
            "19-HandoverRequestAcknowledge",
            "20-HandoverSuccess",
            "21-ConditionalHandoverCancel",
            "42-EarlyStatusTransfer",
            "41-HandoverReport",
            "41-RetrieveUEContextFailure",
            "19-SNodeAdditionRequest"
        ]
        self.f1ap_procedures = [
            "5-UEContextSetupRequest",
            "5-UEContextSetupResponse",
            "5-UEContextSetupFailure",
            "6-UEContextReleaseCommand",
            "6-UEContextReleaseComplete",
            "7-UEContextModificationRequest",
            "7-UEContextModificationResponse",
            "7-UEContextModificationFailure",
            "8-UEContextModificationRequired",
            "8-UEContextModificationConfirm",
            "10-UEContextReleaseRequest",
            "12-DLRRCMessageTransfer",
            "13-ULRRCMessageTransfer",
            "51-paging",

        ]
        self.e1ap_procedures = [
            "8-BearerContextSetupRequest",
            "8-BearerContextSetupResponse",
            "8-BearerContextSetupFailure",
            "9-BearerContextModificationRequest",
            "9-BearerContextModificationResponse",
            "9-BearerContextModificationFailure",
            "10-BearerContextModificationRequired",
            "10-BearerContextModificationConfirm",
            "11-BearerContextReleaseCommand",
            "11-BearerContextReleaseComplete",
            "12-BearerContextReleaseRequest",
            "13-BearerContextInactivityNotification",
        ]

        # self.rrc_dict = defaultdict(lambda: defaultdict(lambda: 'UnknownMessage'))

        self.rrc_dict = {'DL_CCCH_Message': {'c1': {'0': "rrcReject", '1': "rrcSetup"}
                                             },
                         'DL_DCCH_Message': {'c1': {"0": "rrcReconfiguration",
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
                         "PCCH_Message": {'c1': {"0": "paging"}
                                          },
                         "UL_CCCH_Message": {'c1': {"0": "rrcSetupRequest",
                                                    "1": "rrcResumeRequest",
                                                    "2": "rrcReestablishmentRequest",
                                                    "3": "rrcSystemInfoRequest",
                                                    }},
                         "UL-DCCH_Message": {'c1': {"0": "measurementReport",
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
                                                              "7": "mbsInterestIndication-r17",
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

        self.cause_radio_network_dict = {
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
        self.misc_code_to_desc = {
            '0': 'Controlprocessingoverload',
            '1': 'Notenoughuserplaneprocessingresources',
            '2': 'Hardwarefailure',
            '3': 'OMintervention',
            '4': 'Unspecified',
        }
        self.establishment_cause = {
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

        self.cause_code_to_desc = {
            '0': 'RadioNetworkLayerCause',
            '1': 'TransportLayerCause',
            '2': 'ProtocolCause',
            '3': 'MiscellaneousCause'
        }
        self.message_entity_map = {
            'rrcSetupRequest': 'NgNB-DU_NgNB-CUCP',
            'rrcSetup': 'NgNB_CUCP-NgNB_DU',
            'registrationRequest': 'NgNB-CUCP_NgAMF',
            'BearerContextSetupRequest': 'NgNB-CUCP_NgNB-CUUP',
            'BearerContextSetupResponse': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextSetupFailure': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextModificationRequest': 'NgNB-CUCP_NgNB-CUUP',
            'BearerContextModificationResponse': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextModificationFailure': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextModificationRequired': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextModificationConfirm': 'NgNB-CUCP_NgNB-CUUP',
            'BearerContextReleaseCommand': 'NgNB-CUCP_NgNB-CUUP',
            'BearerContextReleaseComplete': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextReleaseRequest': 'NgNB-CUUP_NgNB-CUCP',
            'BearerContextInactivityNotification': 'NgNB-CUUP_NgNB-CUCP',
            'UEContextSetupRequest': 'NgNB-CUCP_NgNB-DU',
            'UEContextSetupResponse': 'NgNB-DU_NgNB-CUCP',
            'UEContextSetupFailure': 'NgNB-CUCP_NgNB-DU',
            'UEContextReleaseCommand': 'NgNB-CUCP_NgNB-DU',
            'UEContextReleaseComplete': 'NgNB-DU_NgNB-CUCP',
            'UEContextModificationRequest': 'NgNB-CUCP_NgNB-DU',
            'UEContextModificationResponse': 'NgNB-DU_NgNB-CUCP',
            'UEContextModificationFailure': 'NgNB-DU_NgNB-CUCP',
            'UEContextModificationRequired': 'NgNB-DU_NgNB-CUCP',
            'UEContextModificationConfirm': 'NgNB-CUCP_NgNB-DU',
            'UEContextReleaseRequest': 'NgNB-DU_NgNB-CUCP',
            'ngapUEContextReleaseRequest': 'NgNB-CUCP_NgAMF',
            'ngapUEContextReleaseCommand': 'NgAMF_NgNB-CUCP',
            'ngapUEContextReleaseComplete': 'NgNB-CUCP_NgAMF',
            'DL-DCCH-Message': 'NgNB-CUCP_NgNB-DU',
            'UL-DCCH-Message': 'NgNB-DU_NgNB-CUCP',
            'DLRRCMessageTransfer': 'NgNB-CUCP_NgNB-DU',
            'ULRRCMessageTransfer': 'NgNB-DU_NgNB-CUCP',
            'serviceRequest': "NgNB-CUCP_NgAMF",
            'InitialULRRCMessageTransfer': "NgNB-DU_NgNB-CUCP",
            'InitialContextSetupRequest': 'NgAMF_NgNB-CUCP',
            'InitialContextSetupResponse': 'NgNB-CUCP_NgAMF',
            'InitialUEMessage': 'NgNB-CUCP_NgAMF',
            'InitialContextSetupFailure': "NgNB-CUCP_NgAMF",
            'PathSwitchRequest': 'NgNB-CUCP_NgAMF',
            'PathSwitchRequestAcknowledge': 'NgAMF-NgNB_CUCP',
            'PathSwitchRequestFailure': 'NgAMF_NgNB-CUCP',
            'Paging': '"NgAMF_NgNB-CUCP"',
            'HandoverFailure': "NgNB_CUCP-NgAMF",
            'HandoverCancelAcknowledge': 'NgAMF-NgNB_CUCP',
            'HandoverSuccess': '"NgAMF_NgNB-CUCP"',
            'HandoverRequest': "NgAMF_NgNB-CUCP",
            'HandoverRequestAcknowledge': "NgNB-CUCP_NgAMF",
            'HandoverRequired': 'NgNB-CUCP_NgAMF',
            'HandoverCommand': "NgAMF-NgNB_CUCP",
            'HandoverPreparationFailure': "NgAMF_NgNB-CUCP",
            'rrcReestablishmentRequest': "NgNB-CUCP_NgNB-DU",
            "rrcReestablishment": "NgNB-CUCP_NgNB-DU",
            "securityModeCommand": "NgNB-CUCP_NgNB-DU",
            "rrcResume": "NgNB-CUCP_NgNB-DU",
            "rrcRelease": "NgNB-CUCP_NgNB-DU",
            "dlInformationTransfer": "NgNB-CUCP_NgNB-DU",
            "ueCapabilityEnquiry": "NgNB-CUCP-NgNB_DU",
            "counterCheck": "NgNB-CUCP_NgNB-DU",
            "mobilityFromNRCommand": "NgNB-CUCP_NgNB-DU",
            "dlDedicatedMessageSegment-r16": "NgNB-CUCP_NgNB-DU",
            "ueInformationRequest-r16": "NgNB-CUCP_NgNB-DU",
            "dlInformationTransferMRDC-r16": "NgNB-CUCP_NgNB-DU",
            "loggedMeasurementConfiguration-r16": "NgNB-CUCP_NgNB-DU",
            "measurementReport": "NgNB-DU_NgNB-CUCP",
            "rrcReconfigurationComplete": "NgNB-DU_NgNB-CUCP",
            "rrcReconfiguration": "NgNB-CUCP_NgNB-DU",
            "rrcSetupComplete": "NgNB-DU_NgNB-CUCP",
            "rrcReestablishmentComplete": "NgNB-DU_NgNB-CUCP",
            "rrcResumeComplete": "NgNB-DU_NgNB-CUCP",
            "securityModeComplete": "NgNB-DU_NgNB-CUCP",
            "securityModeFailure": "NgNB-DU_NgNB-CUCP",
            "ulInformationTransfer": "NgNB-DU_NgNB-CUCP",
            "locationMeasurementIndication": "NgNB-DU_NgNB-CUCP",
            "ueCapabilityInformation": "NgNB-DU_NgNB-CUCP",
            "counterCheckResponse": "NgNB-DU_NgNB-CUCP",
            "ueAssistanceInformation": "NgNB-DU_NgNB-CUCP",
            "failureInformation": "NgNB-DU_NgNB-CUCP",
            "ulInformationTransferMRDC": "NgNB-DU_NgNB-CUCP",
            "scgFailureInformation": "NgNB-DU_NgNB-CUCP",
            "scgFailureInformationEUTRA": "NgNB-DU_NgNB-CUCP",
            "ulDedicatedMessageSegment-r16": "NgNB-DU_NgNB_CUCP",
            "dedicatedSIBRequest-r16": "NgNB-DU_NgNB-CUCP",
            "mcgFailureInformation-r16": "NgNB-DU_NgNB-CUCP",
            "ueInformationResponse-r16": "NgNB-DU_NgNB-CUCP",
            "sidelinkUEInformationNR-r16": "NgNB-DU_NgNB-CUCP",
            "ulInformationTransferIRAT-r16": "NgNB-DU_NgNB-CUCP",
            "iabOtherInformation-r16": "NgNB-DU_NgNB-CUCP",
            "spare9": "NgNB_DU-NgNB_CUCP",
            "spare8": "NgNB_DU-NgNB_CUCP",
            "spare7": "NgNB_DU-NgNB_CUCP",
            "spare6": "NgNB_DU-NgNB_CUCP",
            "spare5": "NgNB_DU-NgNB_CUCP",
            "spare4": "NgNB_DU-NgNB_CUCP",
            "spare3": "NgNB_DU-NgNB_CUCP",
            "spare2": "NgNB_DU-NgNB_CUCP",
            "spare1": "NgNB_DU-NgNB_CUCP",
            "rrcSystemInfoRequest": "NgNB_DU-NgNB_CUCP",
            "registrationReject": "NgAMF_NgNB-CUCP",
            "ngapregistrationReject": "NgCUCP_NgAMF",
            "identityRequest": "NgAMF_NgNB-CUCP",
            "deregistrationRequest(UEOriginating)": "NgNB-CUCP_NgAMF",
            "authenticationFailure": "NgNB-CUCP_NgAMF",
            "authenticationResult": "NgAMF_NgNB-CUCP",
            "NASNonDeliveryIndication": "NgNB-CUCP_NgAMF",
            "xnapHandoverRequest": "NgNB-CUCP_xnCUCP",
            "xnapHandoverRequestAcknowledge": "xnCUCP_NgNB-CUCP",
            "xnapSNStatusTransfer": "xnCUCP_NgNB-CUCP",
            "ngapUplinkNASTransport": "NgNB-CUCP_NgAMF",
            "xnapUEContextRelease": "xnCUCP_NgNB-CUCP",
        }
        self.ip_to_hostname = {}
        with open('hosts', 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    parts = line.split()
                    if len(parts) > 1 and not parts[0].startswith('127.'):
                        for ip in parts[1:]:
                            self.ip_to_hostname[parts[0]] = ip
        # self.hostname_to_ip = {v: k for k, v in self.ip_to_hostname.items()}

    # Processing all F1AP packets

    def process_f1ap(self, packet):

        layer_fields = packet.f1ap._all_fields
        frame_number = packet.frame_info.number
        frame_time = packet.sniff_timestamp
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        message_desc, src_node, dst_node = self.get_rrc_message_dec(layer_fields)
        procedurecode1 = layer_fields.get("f1ap.procedureCode")
        src_entity = f'{src_node}-{self.ip_to_hostname[src_ip]}_{src_ip}'
        dst_entity = f'{dst_node}-{self.ip_to_hostname[dst_ip]}_{dst_ip}'
        message_processing_map = {
            "rrcSetupRequest": self.process_rrc_setup_request,
            "UEContextSetupRequest": self.process_ue_context_setup_request,
            "UEContextSetupResponse": self.process_ue_context_setup_response,
            "UEContextModificationRequest": self.process_ue_context_setup_mod_request,
            "UEContextModificationResponse": self.process_ue_context_setup_mod_response,
            "UEContextReleaseCommand": self.process_ue_context_release_command,
            "UEContextReleaseComplete": self.process_ue_context_release_command,

        }

        if message_desc is not None and procedurecode1 is not None and procedurecode1 != '6':
            pack = self.packet_dict(packet)
 
            if procedurecode1 == '11':
                message_processing_map[message_desc](layer_fields, pack,
                                                     frame_number, frame_time, src_entity, dst_entity, message_desc)
            elif (procedurecode1 == '12' and message_desc is not None) or message_desc == "UEContextModificationConfirm":
                self.process_f1ap_dl_rrc_trfr(layer_fields, pack,
                                              frame_number, frame_time, src_entity, dst_entity, message_desc)
            elif (procedurecode1 == '13' and message_desc is not None):
                self.process_f1ap_ul_rrc_trfr(layer_fields, pack,
                                              frame_number, frame_time, src_entity, dst_entity, message_desc)
            elif procedurecode1 in ['5', '7']:
                 message_processing_map[message_desc](layer_fields, pack,
                                             frame_number, frame_time, src_entity, dst_entity, message_desc) 
            else:
                if procedurecode1 not in ['6']:
             

                    self.process_f1ap_ul_rrc_trfr(layer_fields, pack,
                                                  frame_number, frame_time, src_entity, dst_entity, message_desc)
        elif message_desc in message_processing_map or procedurecode1 == '6':
            # src_entity = f'{src_node}_{src_ip}'
            # dst_entity = f'{dst_node}_{dst_ip}'
            src_entity = f'{src_node}-{self.ip_to_hostname[src_ip]}_{src_ip}'
            dst_entity = f'{dst_node}-{self.ip_to_hostname[dst_ip]}_{dst_ip}'

            pack = self.packet_dict(packet)
            message_processing_map[message_desc](layer_fields, pack,
                                                 frame_number, frame_time, src_entity, dst_entity, message_desc)
        del packet
        del pack
        del layer_fields

    # Processing all E1AP packets
    def process_e1ap(self, packet):
        frame_number = packet.frame_info.number
        frame_time = packet.sniff_timestamp
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        layer_fields = packet.e1ap._all_fields
        e1ap_msg_desc = self.get_e1ap_message(layer_fields)
        e1ap_functions = {
            'BearerContextSetupRequest': self.process_bearer_context_setup,
            'BearerContextSetupResponse': self.process_bearer_context_resp,
            'BearerContextModificationRequest': self.process_bearer_context_mod_req,
            'BearerContextInactivityNotification': self.process_bearer_context_release_inact,
            'BearerContextReleaseCommand': self.process_e1ap_bearer_context_release_cmd,
            'BearerContextReleaseComplete': self.process_e1ap_bearer_context_release_cmd,
        }
        src_entity, dst_entity = self.message_entity_map.get(e1ap_msg_desc).split('_')
        # src_entity = f'{src_entity}_{src_ip}'
        # dst_entity = f'{dst_entity}_{dst_ip}'
        src_entity = f'{src_entity}-{self.ip_to_hostname[src_ip]}_{src_ip}'
        dst_entity = f'{dst_entity}-{self.ip_to_hostname[dst_ip]}_{dst_ip}'
        if e1ap_msg_desc in e1ap_functions:
            pack = self.packet_dict(packet)
            e1ap_functions[e1ap_msg_desc](layer_fields, pack, frame_number, frame_time,
                                          src_entity, dst_entity, e1ap_msg_desc)
        else:
            pack = self.packet_dict(packet)

            self.process_bearer_context_resp(layer_fields, pack, frame_number, frame_time,
                                             src_entity, dst_entity, e1ap_msg_desc)
        del packet
        del pack
        del layer_fields

    # Processing all NGAP procedures.
    def process_ngap(self, packet):
        frame_number = packet.frame_info.number
        frame_time = packet.sniff_timestamp
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        layer_fields = packet.ngap._all_fields
        ngap_msg_desc = self.get_ngap_message(layer_fields)
        ngaprel = ["UEContextReleaseRequest", "UEContextReleaseCommand", "UEContextReleaseComplete","UplinkNASTransport"]
        pack = self.packet_dict(packet)
        if ngap_msg_desc is not None:
            if ngap_msg_desc in ngaprel:
                ngap_msg_desc1 = f'ngap{ngap_msg_desc}'
                src_entity, dst_entity = self.message_entity_map[ngap_msg_desc1].split('_')
            else:
                src_entity, dst_entity = self.message_entity_map[ngap_msg_desc].split('_')
            # src_entity = f'{src_entity}_{src_ip}'
            # dst_entity = f'{dst_entity}_{dst_ip}'
            src_entity = f'{src_entity}-{self.ip_to_hostname[src_ip]}_{src_ip}'
            dst_entity = f'{dst_entity}-{self.ip_to_hostname[dst_ip]}_{dst_ip}'

            ngap_functions = {
                "registrationRequest": self.process_ngap_registration_request,
                "serviceRequest": self.process_ngap_registration_request,
                "InitialContextSetupRequest": self.process_ngap_initial_ctxt_req,
            }
            if ngap_msg_desc in ngap_functions:
                ngap_functions.get(ngap_msg_desc)(layer_fields, pack, frame_number, frame_time, src_entity, dst_entity,
                                                  ngap_msg_desc)
            else:

                self.process_ngap_registration_request(layer_fields, pack, frame_number, frame_time,
                                                       src_entity, dst_entity, ngap_msg_desc)
        del packet
        del pack
        del layer_fields
        # Processing all XNAP procedures.

    def process_xnap(self, packet):
        frame_number = packet.frame_info.number
        frame_time = packet.sniff_timestamp
        src_ip = packet.layers[1].src
        dst_ip = packet.layers[1].dst
        layer_fields = packet.xnap._all_fields

        xnap_msg_desc, src_entity, dst_entity = self.get_xnap_message(layer_fields)
        pack = self.packet_dict(packet)
        # src_entity = f'{src_entity}_{src_ip}'
        # dst_entity = f'{dst_entity}_{dst_ip}'
        src_entity = f'{src_entity}-{self.ip_to_hostname[src_ip]}_{src_ip}'
        dst_entity = f'{dst_entity}-{self.ip_to_hostname[dst_ip]}_{dst_ip}'
        xnap_functions = {
            "HandoverRequest": self.process_xnap_handover_request,
            "HandoverRequestAcknowledge": self.process_xnap_handover_request,
            "SNStatusTransfer": self.process_xnap_handover_request,
            "UEContextRelease": self.process_xnap_handover_request,
        }
        if xnap_msg_desc in xnap_functions:
            xnap_functions.get(xnap_msg_desc)(layer_fields, pack, frame_number, frame_time, src_entity, dst_entity,
                                              xnap_msg_desc)
        
        del packet
        del pack
        del layer_fields

    def packet_analyzer(self):
        # with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        #     future = executor.submit(self.packet_generator)
        #     future.result()

        #     while not self.packet_queue.empty():

        # Read and Filter packets
        self.fields_dict = {}

        with pyshark.FileCapture(self.pcap_file, display_filter='f1ap || e1ap || ngap || xnap') as packets:
            packets.set_debug()
            j = 1
            result = {}
            end_time = time.time()
            std = datetime.datetime.fromtimestamp(end_time)
            print("Start time: ", std.strftime('%Y-%m-%d %H:%M:%S'))
            for packet in packets:
                j = j + 1
                frame_number = packet.frame_info.number

                try:
                    if "f1ap" in packet:
                        self.process_f1ap(packet)

                    elif "e1ap" in packet:
                        self.process_e1ap(packet)
                    elif "ngap" in packet:
                        self.process_ngap(packet)
                    elif "xnap" in packet:

                        self.process_xnap(packet)

                except Exception as e:
                    pass
                    # print(f"Error processing packet: {e}")
        result = self.fields_dict
        del self.fields_dict
        end_time = time.time()
        edt = datetime.datetime.fromtimestamp(end_time)

        print("End time: ", edt.strftime('%Y-%m-%d %H:%M:%S'), "Number of packets:", j)
        print("total time; ", edt - std, (edt - std) / j)

        packets.close()
        return result

    def packet_dict(self, packet):
        # Extract all layers into a single dictionary
        # ip_layer = packet.ip._all_fields if 'IP' in packet else {}
        f1ap_layer = packet.f1ap._all_fields if 'F1AP' in packet else {}
        ngap_layer = packet.ngap._all_fields if 'NGAP' in packet else {}
        e1ap_layer = packet.e1ap._all_fields if 'E1AP' in packet else {}
        packet_dict = {**f1ap_layer, **ngap_layer, **e1ap_layer}
        return packet_dict

    def get_rrc_message_dec(self, layer_fields):
        c1_value = layer_fields.get('nr-rrc.c1')
        c2_value = layer_fields.get('nr-rrc.c2')
        f1ap_proc = layer_fields.get('f1ap.procedureCode')

        if (c1_value or c2_value) and f1ap_proc not in ["8","7"]:
            for key, value in self.rrc_dict.items():
                if key.replace("_", "-") in layer_fields.values():
                    c1_value = layer_fields.get('nr-rrc.c1')
                    c2_value = layer_fields.get('nr-rrc.c2')
                    if c1_value is not None:

                        if "UL" in key:
                            src_node, dst_node = "NgNB-DU", "NgNB-CUCP"
                        else:
                            src_node, dst_node = "NgNB-CUCP", "NgNB-DU"
    

                        return value['c1'].get(c1_value), src_node, dst_node

                    elif c2_value is not None:
                        if "UL" in key:
                            src_node, dst_node = "NgNB-DU", "NgNB-CUCP"
                        else:
                            dst_node, src_node = "NgNB-DU", "NgNB-CUCP"
         
                        return value['c2'].get(c2_value), src_node, dst_node
        else:
            if f1ap_proc:

                for f in self.f1ap_procedures:
                    if f1ap_proc in f:
                        f = f.split("-")[1]
                        if f in layer_fields.values():
                 
                            src_node, dst_node = self.message_entity_map.get(f).split('_')
               
                            return f, src_node, dst_node

    def get_ngap_message(self, layer_fields):
        mm_message_type = layer_fields.get('nas_5gs.mm.message_type', '').upper()
        sm_message_type = layer_fields.get('nas_5gs.sm.message_type', '').upper()
        n = layer_fields.get('ngap.procedureCode')

        if (mm_message_type or sm_message_type) and (mm_message_type != "0x44" and n not in ["19", "46"]):
            
            for key, value in self.ngap_nas_procedures.items():
                if mm_message_type == value.upper():
                    return key
                elif sm_message_type == value.upper():
                    return key
        else:
            if n is not None:
               for item in self.ngap_procedures:
                    if n in item:
                        item = item.split("-")[1]
                        if item in layer_fields.values():
                        
                            return item
                        
        return None

    def get_e1ap_message(self, layer_fields):
        e1ap_proc = layer_fields.get('e1ap.procedureCode')
        if e1ap_proc is not None:
            for e in self.e1ap_procedures:
                if e1ap_proc in e:
                    e = e.split("-")[1]
                    if e in layer_fields.values():
                
                        return e
                    
    def get_xnap_message(self, layer_fields):
        xnap_proc = layer_fields.get('xnap.procedureCode')
        if xnap_proc is not None:
            for item in self.xnap_procedures:
                if xnap_proc in item:
                    item = item.split("-")[1]
                    if item in layer_fields.values():
                        msg = 'xnap'+item
                        src_entity, dst_entity = self.message_entity_map[msg].split('_')
                        return item,src_entity,dst_entity
                    
    def process_rrc_setup_request(self, layer_fields, packet, frame_number, frame_time,
                                  src_entity, dst_entity, message):
        c_rnti = layer_fields.get('f1ap.C_RNTI')
        pci = layer_fields.get('nr-rrc.pdcch_DMRS_ScramblingID')
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        key = f"{c_rnti}_{gnb_du_ue_f1ap_id}"
        self.fields_dict.setdefault(key, {})
        self.fields_dict[key]["c_rnti"] = c_rnti
        self.fields_dict[key]["gnb_du_ue_f1ap_id"] = gnb_du_ue_f1ap_id
        self.fields_dict[key]["gnb_cu_ue_f1ap_id"] = None
        self.fields_dict[key]["gnb_cu_cp_ue_e1ap_id"] = None
        self.fields_dict[key]["gnb_cu_up_ue_e1ap_id"] = None
        self.fields_dict[key]["ran_ue_ngap_id"] = None
        self.fields_dict[key]["amf_ue_ngap_id"] = None
        self.fields_dict[key]["rrc_du"] = src_entity.split("_")[1]
        self.fields_dict[key][f"{message}_{frame_number}"] = {
            "src_node": f'{src_entity}',
            "dst_node": f'{dst_entity}',
            "packet": packet,
            "frame_time": frame_time,
        }
        self.fields_dict[key]["pci"] = f'{pci}'
        self.fields_dict[key]["pci"] = f'{pci}'
        self.update_status(key, frame_time, message)



    def process_ue_context_setup_request(self, layer_fields, packet, frame_number,
                                         frame_time,
                                         src_entity, dst_entity, message_desc):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        for value in self.fields_dict.values():
            if "gnb_du_ue_f1ap_id" in value and value["gnb_du_ue_f1ap_id"] == gnb_du_ue_f1ap_id \
                    and "gnb_cu_ue_f1ap_id" in value and value["gnb_cu_ue_f1ap_id"] == gnb_cu_ue_f1ap_id \
                    and value.get("rrcSetupRequest") == "Success":
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node": f'{src_entity}',
                    "dst_node": f'{dst_entity}',
                    "packet": packet,
                    "frame_time": frame_time,
                }

    def process_ue_context_setup_response(self, layer_fields, packet,  frame_number,
                                          frame_time, src_entity, dst_entity,message_dec):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        for value in self.fields_dict.values():
            if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value[
                "rrcSetupRequest"] == "Success":
                if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id == value[
                    "gnb_cu_ue_f1ap_id"]:
                    value[f"{message_dec}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }

    def process_ue_context_setup_mod_request(self, layer_fields, packet, frame_number,
                                             frame_time, src_entity, dst_entity,message_desc):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in self.fields_dict.items():
                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value[
                    "rrcSetupRequest"] == "Success":
                    if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"]:
                        value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_ue_context_setup_mod_response(self, layer_fields, packet, frame_number,
                                             frame_time, src_entity, dst_entity,message_desc):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in self.fields_dict.items():
                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value and value[
                    "rrcSetupRequest"] == "Success":
                    if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"]:
                 
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_ue_context_setup_failure(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                         frame_time, src_entity, dst_entity):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in fields_dict.items():
                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                    if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"]:
                        value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                        value[f"ueContextSetupResponse_{frame_number}"] = {
                            "src_node": f'{src_entity}_{src_ip}',
                            "dst_node": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_ue_context_setup_failure(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                         frame_time,
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
                            "src_node": f'{src_entity}_{src_ip}',
                            "dst_node": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_ue_context_release_command(self, layer_fields, packet,
                                           frame_number, frame_time, src_entity, dst_entity, message_desc):

        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in self.fields_dict.items():
                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                    if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"] and value.get("rrc_du") == dst_entity.split("_")[1]:
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }
                    elif gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"] and value.get("rrc_du") == src_entity.split("_")[1]:
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_ue_context_release_complete(self, layer_fields, fields_dict, packet, src_ip, dst_ip,
                                            frame_number, frame_time, src_entity, dst_entity):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in fields_dict.items():
                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value:
                    if gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] and gnb_cu_ue_f1ap_id in value[
                        "gnb_cu_ue_f1ap_id"]:
                        value[f"UEContextReleaseComplete_{frame_number}"] = {
                            "src_node": f'{src_entity}_{src_ip}',
                            "dst_node": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_f1ap_dl_rrc_trfr(self, layer_fields, packet,
                                 frame_number, frame_time, src_entity, dst_entity, message_desc):
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in self.fields_dict.items():
                try:
                    if gnb_du_ue_f1ap_id == value.get("gnb_du_ue_f1ap_id") and message_desc == "rrcSetup" and value.get(
                            "rrc_du") == dst_entity.split("_")[1]:
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,

                        }
                        value["gnb_cu_ue_f1ap_id"] = gnb_cu_ue_f1ap_id
                        self.update_status(key, frame_time, message_desc)
                    else:
                        if gnb_du_ue_f1ap_id == value.get("gnb_du_ue_f1ap_id") and gnb_cu_ue_f1ap_id in value.get(
                                "gnb_cu_ue_f1ap_id") and value.get("rrc_du") == dst_entity.split("_")[1]:
                            value[f"{message_desc}_{frame_number}"] = {
                                "src_node": f'{src_entity}',
                                "dst_node": f'{dst_entity}',
                                "packet": packet,
                                "frame_time": frame_time,
                            }
                            self.update_status(key, frame_time, message_desc)

                except KeyError:
                    pass

    def process_f1ap_ul_rrc_trfr(self, layer_fields, packet,
                                 frame_number, frame_time, src_entity, dst_entity, message_desc):
    
        gnb_du_ue_f1ap_id = layer_fields.get('f1ap.GNB_DU_UE_F1AP_ID')
        gnb_cu_ue_f1ap_id = layer_fields.get('f1ap.GNB_CU_UE_F1AP_ID')
        if gnb_cu_ue_f1ap_id and gnb_du_ue_f1ap_id:
            for key, value in self.fields_dict.items():

                if "gnb_du_ue_f1ap_id" in value and "gnb_cu_ue_f1ap_id" in value \
                        and gnb_du_ue_f1ap_id == value["gnb_du_ue_f1ap_id"] \
                        and gnb_cu_ue_f1ap_id in value["gnb_cu_ue_f1ap_id"] and value.get("rrc_du") == \
                        src_entity.split("_")[1]:
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    self.update_status(key, frame_time, message_desc)

    def is_success(self, key, message, t2, max_time_delta):
        m = message[:-9]

        value = self.fields_dict[key]
        last_matching_request = None
        for i in reversed(value.keys()):
            if (i.startswith(m) and "_" in i) and (
                    "figuration_" in i or "Request" in i or "Command" in i or "Required" in i):
                last_matching_request = i

                break
        t1 = value.get(last_matching_request)["frame_time"]

        t1 = datetime.datetime.fromtimestamp(float(t1))
        t1 = t1.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S-%f')
        t1 = datetime.datetime.strptime(t1, '%Y-%m-%d-%H-%M-%S-%f')

        time_diff = t2 - t1

        if time_diff <= max_time_delta:

            return "Success"
        else:

            return "Failure"

    def update_status(self, key, timestamp, message):
        frame_time = datetime.datetime.fromtimestamp(float(timestamp))
        t2 = frame_time.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d-%H-%M-%S-%f')
        t2 = datetime.datetime.strptime(t2, '%Y-%m-%d-%H-%M-%S-%f')
        try:
            rrc_setup = self.fields_dict[key].get("rrcSetupRequest") == "Success"

            if message == "rrcSetupRequest" and self.fields_dict[key].get("rrcSetupRequest") is None:
                self.fields_dict[key].update({"rrcSetupRequest": "Attempt"})
                return
            if message == "rrcSetup" and self.fields_dict[key] == "Attempt":
                self.fields_dict[key].update({"rrcSetupRequest": "Attempt"})

                return
            if message == "securityModeCommand" and rrc_setup:
                self.fields_dict[key].update({"securityModeCommand": "Attempt"})

                return
            elif message == "rrcResumeRequest":
                self.fields_dict[key].update({"rrcResumeRequest": "Attempt"})

                return
            elif message == "rrcReestablishmentRequest":
                self.fields_dict[key].update({"rrcReestablishmentRequest": "Attempt"})

                return
            elif message == "ueCapabilityEnquiry":
                self.fields_dict[key].update({"ueCapabilityEnquiry": "Attempt"})

                return
            elif message == "rrcReconfiguration":
                self.fields_dict[key].update({"rrcReconfiguration": "Attempt"})

                return
            elif message == "BearerContextSetupRequest":
                self.fields_dict[key].update({"BearerContextSetupRequest": "Attempt"})
                return
            elif message == "BearerContextModificationRequest":
                self.fields_dict[key].update({"BearerContextModificationRequest": "Attempt"})
                return
            elif (message == "registrationRequest" or message == "serviceRequest") and rrc_setup:
                self.fields_dict[key].update({"registrationRequest": "Attempt"})
                return
            elif (message == "InitialContextSetupRequest" and self.fields_dict[key].get(
                    "registrationRequest") == "Attempt") and rrc_setup:
                self.fields_dict[key].update({"InitialContextSetupRequest": "Attempt"})
                return
            elif (message == "HandoverRequest" and self.fields_dict[key].get(
                    "registrationRequest") == "Success") and rrc_setup:
                self.fields_dict[key].update({"HandoverRequest": "Attempt"})
                return

            max_time_delta = datetime.timedelta(seconds=3)
            result = self.is_success(key, message, t2, max_time_delta)

            reg_req_attempted = self.fields_dict[key].get("registrationRequest") == "Attempt"
            ho_req_attempted = self.fields_dict[key].get("HandoverRequest") == "Attempt"
            if result is not None:
                if message == "rrcSetupComplete" and self.fields_dict[key].get("rrcSetupRequest") == "Attempt":
                    self.fields_dict[key].update({"rrcSetupRequest": f'{result}'})
                    return
                if message == "securityModeComplete":
                    self.fields_dict[key].update({"securityModeCommand": f'{result}'})
                    return
                elif message == "rrcReestablishmentComplete":
                    self.fields_dict[key].update({"rrcReestablishmentRequest": f'{result}'})
                    return
                elif message == "ueInformationRequest-r16":
                    self.fields_dict[key].update({"ueInformationRequest-r16": f'{result}'})
                elif message == "ulInformationTransfer":
                    self.fields_dict[key].update({"ueInformationRequest-r16": f'{result}'})
                    return
                elif message == "ueCapabilityInformation":
                    self.fields_dict[key].update({"ueCapabilityEnquiry": f'{result}'})
                    return
                elif message == "rrcReconfigurationComplete":
                    self.fields_dict[key].update({"rrcReconfiguration": f'{result}'})
                    return
                elif message == "BearerContextSetupResponse":
                    self.fields_dict[key].update({"BearerContextSetupRequest": f'{result}'})
                    return
                elif message == "BearerContextModificationResponse":
                    self.fields_dict[key].update({"BearerContextModificationRequest": f'{result}'})
                    return
                elif message == "BearerContextSetupFailure":
                    self.fields_dict[key].update({"BearerContextSetupRequest": f'{result}'})
                    return
                elif message == "InitialContextSetupResponse" and reg_req_attempted:
                    self.fields_dict[key].update({"registrationRequest": f'{result}'})
                    self.fields_dict[key].update({"InitialContextSetupRequest": f'{result}'})
                    return
                elif message == "HandoverRequestAcknowledge" and ho_req_attempted:
                    self.fields_dict[key].update({"HandoverRequest": f'{result}'})
                 
                    return
        except Exception as e:
            pass
            #print(f"Error processing packet: {e}")

    def get_failure_reason(self, layer_fields):
        cause_code = layer_fields.get('f1ap.Cause')
        if cause_code in self.cause_code_to_desc:
            cause_desc = self.cause_code_to_desc[cause_code]
            misc_code = layer_fields.get('f1ap.misc')
            rn_code = layer_fields.get('f1ap.radioNetwork')
            if misc_code in self.misc_code_to_desc:
                misc_desc = self.misc_code_to_desc[misc_code]
            elif rn_code in self.cause_radio_network_dict:
                misc_desc = self.cause_radio_network_dict[rn_code]
            else:
                misc_desc = 'Unknown Misc'
        else:
            cause_desc = 'Unknown Code'
            misc_desc = 'Unknown Misc'
        failure_reason = cause_desc + '_' + misc_desc
        return failure_reason

    # Process E1AP messages

    def process_bearer_context_setup(self, layer_fields, packet, frame_number,
                                     frame_time, src_entity, dst_entity, message_desc):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gtp_teid = layer_fields.get("e1ap.gTP_TEID")
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in self.fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and value[
                    "rrcSetupRequest"] == "Success" and \
                        value.get("registrationRequest") == "Attempt" and gtp_teid == value.get('gTP_TEID'):
                    value["gnb_cu_cp_ue_e1ap_id"] = gnb_cu_cp_ue_e1ap_id
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    self.update_status(key, frame_time, "BearerContextSetupRequest")

    def process_bearer_context_resp(self, layer_fields, packet, frame_number,
                                    frame_time, src_entity, dst_entity, message_desc):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            ctxt_dst_ip = None
            for key, value in self.fields_dict.items():
                for i, j in self.fields_dict[key].items():
                    if "BearerContextSetupRequest_" in i or "BearerContextModificationRequest_" in i:
                        ctxt_dst_ip = str(j.get("dst_node").split("_")[1])

           
                if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and \
                        value.get("rrcSetupRequest") == "Success" and \
                        value.get("registrationRequest") != "Success" and ctxt_dst_ip == src_entity.split("_")[1]:
                    value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    self.update_status(key, frame_time, message_desc)
                if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and \
                        value.get("rrcSetupRequest") == "Success" and \
                        value.get("registrationRequest") == "Success" and ctxt_dst_ip == src_entity.split("_")[1] and \
                            value.get("BearerContextModificationRequest") == "Attempt":
                                value[f"{message_desc}_{frame_number}"] = {
                                                        "src_node": f'{src_entity}',
                                                        "dst_node": f'{dst_entity}',
                                                        "packet": packet,
                                                        "frame_time": frame_time,
                                }
                                self.update_status(key, frame_time, message_desc)

    def process_bearer_context_mod_req(self, layer_fields, packet, frame_number,
                                       frame_time,
                                       src_entity, dst_entity, message_desc):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in self.fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value.get('gnb_cu_cp_ue_e1ap_id') and gnb_cu_up_ue_e1ap_id == value.get(
                        'gnb_cu_up_ue_e1ap_id'):
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value.get(
                            "rrcSetupRequest") == "Success" and value.get(
                        "BearerContextSetupRequest") == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }
                        self.update_status(key, frame_time, message_desc)

    def process_e1ap_bearer_context_mod_res(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                            frame_time, src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextModificationResponse_{frame_number}"] = {
                            "src_node_ip": f'{src_entity}_{src_ip}',
                            "dst_node_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_e1ap_bearer_context_mod_fail(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                             frame_time, src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextModificationFailure_{frame_number}"] = {
                            "src_node_ip": f'{src_entity}_{src_ip}',
                            "dst_node_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_e1ap_bearer_context_mod_reqrd(self, layer_fields, fields_dict, packet, src_ip, dst_ip,
                                              frame_number, frame_time, src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextModificationRequired_{frame_number}"] = {
                            "src_node-src_ip": f'{src_entity}_{src_ip}',
                            "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_e1ap_bearer_context_mod_conf(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
                                             frame_time,
                                             src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextModificationConfirm_{frame_number}"] = {
                            "src_node-src_ip": f'{src_entity}_{src_ip}',
                            "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_e1ap_bearer_context_release_cmd(self, layer_fields, packet,
                                                frame_number,
                                                frame_time,
                                                src_entity, dst_entity, message_desc):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in self.fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"{message_desc}_{frame_number}"] = {
                            "src_node": f'{src_entity}',
                            "dst_node": f'{dst_entity}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_bearer_context_release_com(self, layer_fields, fields_dict, packet, src_ip, dst_ip,
                                           frame_number, frame_time, src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextReleaseComplete_{frame_number}"] = {
                            "src_node-src_ip": f'{src_entity}_{src_ip}',
                            "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_bearer_context_release_req(self, layer_fields, fields_dict, packet, src_ip, dst_ip,
                                           frame_number, frame_time, src_entity, dst_entity):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            for key, value in fields_dict.items():
                if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_cp_ue_e1ap_id"] and gnb_cu_up_ue_e1ap_id == value[
                    "gnb_cu_up_ue_e1ap_id"]:
                    if gnb_cu_cp_ue_e1ap_id == value["gnb_cu_ue_f1ap_id"] and value[
                        "rrcSetupRequest"] == "Success":
                        value["gnb_cu_up_ue_e1ap_id"] = gnb_cu_up_ue_e1ap_id
                        value[f"BearerContextReleaseRequest_{frame_number}"] = {
                            "src_node-src_ip": f'{src_entity}_{src_ip}',
                            "dst_node-dst_ip": f'{dst_entity}_{dst_ip}',
                            "packet": packet,
                            "frame_time": frame_time,
                        }

    def process_bearer_context_release_inact(self, layer_fields, packet,
                                             frame_number, frame_time, src_entity, dst_entity, message_desc):
        gnb_cu_cp_ue_e1ap_id = layer_fields['e1ap.GNB_CU_CP_UE_E1AP_ID']
        gnb_cu_up_ue_e1ap_id = layer_fields['e1ap.GNB_CU_UP_UE_E1AP_ID']
        if gnb_cu_cp_ue_e1ap_id:
            ctxt_dst_ip = None
            for key, value in self.fields_dict.items():
                for i, j in self.fields_dict[key].items():
                    if "BearerContextSetupRequest_" in i or "BearerContextModificationRequest_" in i:
                        ctxt_dst_ip = str(j.get("dst_node").split("_")[1])

                if gnb_cu_cp_ue_e1ap_id == value.get("gnb_cu_ue_f1ap_id") and \
                        value.get("rrcSetupRequest") == "Success" and \
                        value.get("registrationRequest") == "Success" and ctxt_dst_ip == src_entity.split("_")[1]:
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }

    # NGAP procedures

    def process_ngap_registration_request(self, layer_fields, packet, frame_number,
                                          frame_time, src_entity, dst_entity, message_desc):
        amf_ue_ngap_id = layer_fields.get("ngap.AMF_UE_NGAP_ID")
        ran_ue_ngap_id = layer_fields.get('ngap.RAN_UE_NGAP_ID')

        for key, value in self.fields_dict.items():
            if ran_ue_ngap_id == value.get("gnb_cu_ue_f1ap_id") and value.get(
                    "AMF_UE_NGAP_ID") is None and value.get(
                "rrcSetupRequest") == "Success" and message_desc in ["registrationRequest",
                                                                     "serviceRequest"] and \
                    f"{message_desc}_" not in value and value.get("amf_ue_ngap_id") is None and value.get(
                "registrationRequest") is None:
     

                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value["amf_ue_ngap_id"] = None
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node": f'{src_entity}',
                    "dst_node": f'{dst_entity}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                self.update_status(key, frame_time, message_desc)
            elif ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value.get("amf_ue_ngap_id") == amf_ue_ngap_id \
                    and value.get("registrationRequest") is not None:

                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value['amf_ue_ngap_id'] = amf_ue_ngap_id
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node": f'{src_entity}',
                    "dst_node": f'{dst_entity}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                self.update_status(key, frame_time, message_desc)
            elif ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value.get("amf_ue_ngap_id") == None and \
                    value.get("registrationRequest") == "Attempt":


                value["ran_ue_ngap_id"] = ran_ue_ngap_id
                value['amf_ue_ngap_id'] = amf_ue_ngap_id
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node": f'{src_entity}',
                    "dst_node": f'{dst_entity}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                self.update_status(key, frame_time, message_desc)

    def process_ngap_initial_ctxt_req(self, layer_fields, packet,
                                      frame_number,
                                      frame_time, src_entity, dst_entity, message_desc):
        ran_ue_ngap_id = layer_fields['ngap.RAN_UE_NGAP_ID']
        amf_ue_ngap_id = layer_fields['ngap.AMF_UE_NGAP_ID']

        if ran_ue_ngap_id:
            for key, value in self.fields_dict.items():
                if ran_ue_ngap_id == value.get("ran_ue_ngap_id") and value.get("amf_ue_ngap_id") == None and \
                        value.get("registrationRequest") == "Attempt":

                    value["ran_ue_ngap_id"] = ran_ue_ngap_id
                    value['amf_ue_ngap_id'] = amf_ue_ngap_id
                    value[f"{message_desc}_{frame_number}"] = {
                        "src_node": f'{src_entity}',
                        "dst_node": f'{dst_entity}',
                        "packet": packet,
                        "frame_time": frame_time,
                    }
                    if layer_fields.get('ngap.gTP_TEID'):
                        value["gTP_TEID"] = layer_fields.get('ngap.gTP_TEID')
                    self.update_status(key, frame_time, message_desc)

    def process_ngap_context_release_request(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
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

    def process_ngap_context_release_command(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
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

    def process_ngap_context_release_complete(self, layer_fields, fields_dict, packet, src_ip, dst_ip, frame_number,
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

    def process_ngap_initial_context_setup_failure(self, layer_fields, fields_dict, packet, src_ip, dst_ip,
                                                   frame_number, frame_time, src_entity, dst_entity):
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

    # XNAP Procedure calls

    def process_xnap_handover_request(self, layer_fields, packet, frame_number,
                                          frame_time, src_entity, dst_entity, message_desc):
     
        src_xnap_ran_ue_id = layer_fields.get("xnap.NG_RANnodeUEXnAPID")

        for key, value in self.fields_dict.items():
            if src_xnap_ran_ue_id == value.get("gnb_cu_ue_f1ap_id") and value.get(
                "registrationRequest") == "Success" and message_desc in "HandoverRequest" and value.get("dst_xnap_ran_ue_id") is None:
                value["src_xnap_ran_ue_id"] = src_xnap_ran_ue_id
                value["dst_xnap_ran_ue_id"] = None
                value[f"{message_desc}_{frame_number}"] = {
                    "src_node": f'{src_entity}',
                    "dst_node": f'{dst_entity}',
                    "packet": packet,
                    "frame_time": frame_time,
                }
                self.update_status(key,frame_time,message_desc)
            elif src_xnap_ran_ue_id == value.get("gnb_cu_ue_f1ap_id") and value.get(
                "HandoverRequest") == "Attempt" :
                for i, j in self.fields_dict[key].items():
                        if "HandoverRequest_" in i:
                            ho_dst_ip = str(j.get("dst_node").split("_")[1])
                            if ho_dst_ip == src_entity.split("_")[1]:
                                
                                value[f"{message_desc}_{frame_number}"] = {
                                    "src_node": f'{src_entity}',
                                    "dst_node": f'{dst_entity}',
                                    "packet": packet,
                                    "frame_time": frame_time,
                                }
                                self.update_status(key,frame_time,message_desc)
            else:
 
                for i, j in self.fields_dict[key].items():
                        if "HandoverRequest_" in i:
                                                        
                            value[f"{message_desc}_{frame_number}"] = {
                                    "src_node": f'{src_entity}',
                                    "dst_node": f'{dst_entity}',
                                    "packet": packet,
                                    "frame_time": frame_time,
                                }
                               
                

