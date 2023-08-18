import datetime
import time
from multiprocessing import Pool

import numpy as np
import pandas as pd
import pyshark

# Open the pcap file for reading

# Create an empty list to store the extracted data
data = []
rrc_dict = {'DL_CCCH_Message': {'c1': {'0': "rrcReject", '1': "rrcSetup"}
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

f1ap_procedures = [
    "5-UEContextSetupRequest",
    "7-UEContextModificationRequest",
    "5-UEContextSetupResponse",
    "5-UEContextSetupFailure",
    "7-UEContextModificationResponse",
    "6-UEContextReleaseCommand",
    "6-UEContextReleaseComplete",
    "7-UEContextModificationFailure",
    "8-UEContextModificationRequired",
    "8-UEContextModificationConfirm",
    "10-UEContextReleaseRequest",
    "12-DLRRCMessageTransfer",
    "13-ULRRCMessageTransfer",
    "18-Paging",
]
message_entity_map = {
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

e1ap_procedures = [
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
ngap_nas_procedures = {
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
ngap_procedures = [
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
    "24-Paging"
]
xnap_procedures = [
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


def get_rrc_message_dec(layer_fields):
    c1_value = layer_fields.get('nr-rrc.c1')
    c2_value = layer_fields.get('nr-rrc.c2')
    f1ap_proc = layer_fields.get('f1ap.procedureCode')
    if (c1_value or c2_value) and f1ap_proc not in [8, 7]:
        for key, value in rrc_dict.items():
            if key.replace("_", "-") in layer_fields.values():
                c1_value = layer_fields.get('nr-rrc.c1')
                c2_value = layer_fields.get('nr-rrc.c2')
                if c1_value is not None:
                    if "UL" in key:
                        src_node, dst_node = "NgNB-DU", "NgNB-CUCP"
                    else:
                        src_node, dst_node = "NgNB-CUCP", "NgNB-DU"
                    return value['c1'].get(c1_value)

                elif c2_value is not None:
                    if "UL" in key:
                        src_node, dst_node = "NgNB-DU", "NgNB-CUCP"
                    else:
                        dst_node, src_node = "NgNB-DU", "NgNB-CUCP"
                    return value['c2'].get(c2_value)
    else:
        if f1ap_proc:
            for f in f1ap_procedures:
                if f1ap_proc in f:
                    f = f.split("-")[1]
                    if f in layer_fields.values():
                        src_node, dst_node = message_entity_map.get(f).split('_')
                        return f, src_node, dst_node


def get_e1ap_message(layer_fields):
    e1ap_proc = layer_fields.get('e1ap.procedureCode')
    if e1ap_proc is not None:
        for e in e1ap_procedures:
            if e1ap_proc in e:
                e = e.split("-")[1]
                if e in layer_fields.values():
                    return e


def get_ngap_message(layer_fields):
    mm_message_type = layer_fields.get('nas_5gs.mm.message_type', '').upper()
    sm_message_type = layer_fields.get('nas_5gs.sm.message_type', '').upper()
    n = layer_fields.get('ngap.procedureCode')

    if (mm_message_type or sm_message_type) and (mm_message_type != "0x44" and n not in ["19", "46"]):

        for key, value in ngap_nas_procedures.items():
            if mm_message_type == value.upper():
                return key
            elif sm_message_type == value.upper():
                return key
    else:
        if n is not None:
            for item in ngap_procedures:
                if n in item:
                    item = item.split("-")[1]
                    if item in layer_fields.values():
                        return item

    return None


def packet_dict(packet):
    # Extract all layers into a single dictionary
    f1ap_layer = packet.f1ap._all_fields if 'F1AP' in packet else {}
    ngap_layer = packet.ngap._all_fields if 'NGAP' in packet else {}
    e1ap_layer = packet.e1ap._all_fields if 'E1AP' in packet else {}
    packet_dict = {**f1ap_layer, **ngap_layer, **e1ap_layer}
    return packet_dict


def process_packet(packet):
    fno = int(packet.frame_info.number)
    time = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
    src_ip = packet.ip.src
    dst_ip = packet.ip.dst
    interface = ""
    c_rnti = ""
    du_f1ap_id = ""
    cu_f1ap_id = ""
    cp_e1ap_id = ""
    up_e1ap_id = ""
    info = ""
    message = ""
    proto = ""
    ran_ngap_id = ""
    amf_ngap_id = ""
    # Check if the packet is an F1AP packet
    if 'f1ap' in packet:
        pkt = packet.f1ap._all_fields
        # Do something with decoded RRC message
        msg = get_rrc_message_dec(pkt)

        try:
            # extract the required fields from the packet
            c_rnti = pkt.get('f1ap.C_RNTI')
            du_f1ap_id = pkt.get('f1ap.GNB_DU_UE_F1AP_ID')
            cu_f1ap_id = pkt.get('f1ap.GNB_CU_UE_F1AP_ID')
            pci = pkt.get('nr_rrc.pdcch_DMRS_ScramblingID')
            proto = "F1AP"
            message = str(msg)
            info = f'"{str(pkt)}"'
        except AttributeError:
            # ignore packets that don't have the required fields
            pass
    elif 'e1ap' in packet:
        pkt = packet.e1ap._all_fields
        msg = get_e1ap_message(pkt)
        try:
            cp_e1ap_id = pkt.get('e1ap.GNB_CU_CP_UE_E1AP_ID')
            up_e1ap_id = pkt.get('e1ap.GNB_CU_UP_UE_E1AP_ID')
            procedure_code = pkt.get('e1ap.procedureCode')
            info = f'"{str(pkt)}"'
            proto = "E1AP"
            message = str(msg)
        except AttributeError:
            # ignore packets that don't have the required fields
            pass
    elif 'ngap' in packet:
        pkt = packet.ngap._all_fields
        # Do something with decoded RRC message
        msg = get_ngap_message(pkt)

        try:
            # extract the required fields from the packet
            ran_ngap_id = pkt.get('ngap.RAN_UE_NGAP_ID')
            amf_ngap_id = pkt.get('ngap.AMF_UE_NGAP_ID')
            proto = "NGAP"
            message = str(msg)
            info = f'"{str(pkt)}"'
        except AttributeError:
            # ignore packets that don't have the required fields
            pass
    return [fno, proto, message, src_ip, dst_ip, time, c_rnti, du_f1ap_id, cu_f1ap_id, cp_e1ap_id, up_e1ap_id,
            ran_ngap_id, amf_ngap_id, info]


def write_output(data):
    with open('output_file.csv', 'a') as f:
        f.write(','.join(map(str, data)) + '\n')


def process_capture(packet):
    data = process_packet(packet)
    write_output(data)


def read_csv_df(csvfile):
    df = pd.read_csv(csvfile)


if __name__ == '__main__':
    pool = Pool(processes=5)
    capture = pyshark.FileCapture("cucp10-227-195-180-pcap86", display_filter="f1ap || e1ap|| ngap")
    start_time = time.time()
    dt = datetime.datetime.fromtimestamp(start_time)
    print("Start time: ", dt.strftime('%Y-%m-%d %H:%M:%S'))
    j = 1
    for packet in capture:
        j = j + 1
        pool.apply(process_capture, args=(packet,))

    pool.close()
    pool.join()
    print("Number of packets processed:", j)
    end_time = time.time()
    edt = datetime.datetime.fromtimestamp(end_time)
    print("End time: ", edt.strftime('%Y-%m-%d %H:%M:%S'))

    df = pd.read_csv('output_file.csv', delimiter=',', header=None,
                     names=['fno', 'proto', 'message', 'src_ip', 'dst_ip', 'c_rnti', 'du_f1ap_id', 'cu_f1ap_id',
                            'cp_e1ap_id', 'up_e1ap_id', 'ran_ngap_id', 'amf_ngap_id', 'info'])
    pd.set_option('display.max_columns', None)
    pd.set_option('display.max_rows', None)

    df = df.replace({np.nan: None})
    df['cp_e1ap_id'] = df['cp_e1ap_id'].astype("Int64")

    df_end_time = time.time()
    edf = datetime.datetime.fromtimestamp(df_end_time)
    print("Df End time: ", edf.strftime('%Y-%m-%d %H:%M:%S'))
