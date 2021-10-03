#/usr/local/bin/python3

import os
import collections
import sys
import json
import numpy as np
import time
import binascii
import OpenSSL


def readpcap(pcap_file):
    output = os.popen("tshark -nnnr %s -Y 'tcp.flags.syn == 1 or tcp.flags.fin == 1 or tcp.flags.reset == 1 or tls' -T ek"%pcap_file).read().strip()
    pcap_list = []
    for i in output.split('\n'):
        if 'layers' in i:
            pcap_list.append(i)
    return pcap_list

def defind_ini_dic(flow):
    ini_dic = collections.OrderedDict()
    ini_dic['client_applicationdata_interval_average'] = None
    ini_dic['client_applicationdata_interval_mini'] = None
    ini_dic['client_applicationdata_interval_standard_deviation'] = None
    ini_dic['client_applicationdata_interval_list']  = []
    ini_dic['client_applicationdata_interval_max'] = None
    ini_dic['client_applicationdata_length_average'] = None
    ini_dic['client_applicationdata_length_standard_deviation'] = None
    ini_dic['client_applicationdata_length_list'] = []
    ini_dic['client_applicationdata_length_mini'] = None
    ini_dic['client_applicationdata_length_max'] = None
    ini_dic['client_cipher_suites'] = None
    ini_dic['client_cipher_suites_length'] = None
    ini_dic['client_compression'] = None
    ini_dic['client_ec_point_format'] = None
    ini_dic['client_elliptical_curve'] = None
    ini_dic['client_fin'] = None
    ini_dic['client_hello_length'] = None
    ini_dic['client_hello_byte_random'] = None
    ini_dic['client_hello_time_random'] = None
    ini_dic['client_inner_tls_version'] = None
    ini_dic['client_ip'] = flow.split('_')[0].split(":")[0]
    ini_dic['client_key_length'] = None
    ini_dic['client_outer_tls_version'] = None
    ini_dic['client_packets'] = 0
    ini_dic['client_port'] = flow.split('_')[0].split(":")[1]
    ini_dic['client_reset'] = None
    ini_dic['client_tls_reuse'] = None
    ini_dic['client_sni'] = None
    ini_dic['client_tls_extenson'] = None
    ini_dic['client_tls_encrypted_alert'] = None
    ini_dic["tls_tls_handshake_epms_len"] = None
    ini_dic['client_tot_bytes'] = 0
    ini_dic['client_tcp_option'] = None

    ini_dic['server_tcp_option'] = None
    ini_dic['server_applicationdata_interval_average'] = None
    ini_dic['server_applicationdata_interval_standard_deviation'] = None
    ini_dic['server_applicationdata_interval_mini'] = None
    ini_dic['server_applicationdata_interval_list'] = []
    ini_dic['server_applicationdata_interval_max'] = None
    ini_dic['server_applicationdata_length_average'] = None
    ini_dic['server_applicationdata_length_standard_deviation'] = None
    ini_dic['server_applicationdata_length_mini'] = None
    ini_dic['server_applicationdata_length_list'] = []
    ini_dic['server_applicationdata_length_max'] = None
    ini_dic['server_ca_wellknown'] = None
    ini_dic['server_cert_algorithm'] = None
    ini_dic['server_cert_algorithmIdentifier'] = None
    ini_dic['server_cert_expired'] = None
    ini_dic['server_cert_issuer'] = None
    ini_dic['server_cert_number'] = None
    ini_dic['server_cert_self_signed'] = None
    ini_dic['server_cert_subject'] = None
    ini_dic['server_certificates_length'] = None
    ini_dic['server_cipher_suites'] = None
    ini_dic['server_compression'] = None
    ini_dic['server_ec_point_format'] = None
    ini_dic['server_elliptical_curve'] = None
    ini_dic['server_tls_extenson'] = None
    ini_dic['server_tls_encrypted_alert'] = None    
    ini_dic['server_fin'] = None
    ini_dic['server_hello_length'] = None
    ini_dic['server_hello_byte_random'] = None
    ini_dic['server_hello_time_random'] = None
    ini_dic['server_ip'] = flow.split('_')[1].split(":")[0]
    ini_dic['server_packets'] = 0
    #ini_dic['server_pkcs1_publicexponentserver'] = None
    ini_dic['server_policyidentifier'] = None
    ini_dic['server_port'] = flow.split('_')[1].split(":")[1]
    ini_dic['server_reset'] = None
    ini_dic['server_tls_encrypted_alert'] = None
    ini_dic['server_tot_bytes'] = 0
    ini_dic['server_x509af_extension_id'] = None
    ini_dic['server_x509af_extensions'] = None
    ini_dic['server_x509af_serialNumber'] = None
    ini_dic['server_x509af_utctime'] = None
    ini_dic['server_x509ce_keypurposeids'] = None
    ini_dic['server_x509ce_keyusage'] = None
    ini_dic['server_x509sat_countryname'] = None
    return ini_dic


def check_cert(epoch_time, cert_file):
    top1000 = open('top1000.txt').read().strip().split('\n')
    crt_data =  open(cert_file).read()
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, crt_data)
    certIssue = cert.get_issuer()
    issuer = certIssue.commonName
    certSubject = cert.get_subject()
    subject = certSubject.get_components()[0][1].decode('utf-8')
    not_before = cert.get_notBefore().decode("UTF-8").strip("Z")
    timearray = time.strptime(not_before, "%Y%m%d%H%M%S")
    not_before = int(time.mktime(timearray))
    not_after = cert.get_notAfter().decode("UTF-8").strip("Z")
    timearray = time.strptime(not_after, "%Y%m%d%H%M%S")
    not_after = int(time.mktime(timearray))
    if epoch_time > not_before and epoch_time < not_after:
        expired = False
    else:
        expired = True
    output = os.popen('openssl verify -CAfile %s -CApath %s %s'%(cert_file, cert_file, cert_file)).read()
    if 'OK' in output:
        self_signed = True
    else:
        self_signed = False
    if any(i.lower() in subject.lower() for i in top1000):
        wellknown = True
    else:
        wellknown = False
    return issuer, subject, expired, self_signed, wellknown




def cert_parse(flow_dic, pkt, role, app_data_time_dic, flow, tls):
    flow_dic['server_cert_algorithm'] = tls["x509af_x509af_algorithm_id"]
    flow_dic['server_x509ce_keyusage'] = tls["x509ce_x509ce_KeyUsage"]
    flow_dic['server_x509ce_keypurposeids'] = tls["x509ce_x509ce_KeyPurposeId"]
    flow_dic['server_x509sat_countryname'] = tls["x509sat_x509sat_CountryName"]
    flow_dic['server_x509af_utctime'] = tls["x509af_x509af_utcTime"]
    flow_dic['server_x509af_serialNumber'] = tls["x509af_x509af_serialNumber"]
    flow_dic['server_x509af_extension_id'] = tls["x509af_x509af_extension_id"]
    flow_dic['server_cert_number'] = len(tls["tls_tls_handshake_certificate"])
    flow_dic['server_certificates_length'] = tls["tls_tls_handshake_certificates_length"]
    flow_dic['server_policyidentifier'] = tls["x509ce_x509ce_policyIdentifier"]
    epoch_time = int(pkt['layers']['frame']["frame_frame_time_epoch"].split('.')[0])
    issuer_list = []
    subject_list = []
    expired_list = []
    self_signed_list = []
    wellknown_list = []
    #os.popen('rm cert.der cert.crt -f 2>/dev/null')
    for der_hex in tls["tls_tls_handshake_certificate"]:
        der_file = binascii.unhexlify(der_hex.replace(':', ''))
        with open('cert.der', 'wb') as f:
            f.write(der_file)
        os.popen('openssl x509 -inform DER -in cert.der -out cert.crt').read()
        issuer, subject, expired, self_signed, wellknown = check_cert(epoch_time, 'cert.crt')
        issuer_list.append(issuer)
        if '.' in subject:
            subject_list.append(subject)
        expired_list.append(expired)
        self_signed_list.append(self_signed)
        wellknown_list.append(wellknown)
        #os.popen('rm cert.der cert.crt')
    flow_dic['server_cert_issuer'] = issuer_list
    flow_dic['server_cert_subject'] = subject_list
    if any(i == True for i in expired_list):
        flow_dic['server_cert_expired'] = True
    else:
        flow_dic['server_cert_expired'] = False
    if len(tls["tls_tls_handshake_certificate"]) == 1 and True in self_signed_list:
        flow_dic['server_cert_self_signed'] = True
    else:
        flow_dic['server_cert_self_signed'] = False
    if any(i == True for i in wellknown_list):
        flow_dic['server_ca_wellknown'] = True
    return flow_dic

def tls_parse(flow_dic, pkt, role, app_data_time_dic, flow, tls):
    #tls handshake
    if 'tls_tls_record_content_type' in tls:
        if tls['tls_tls_record_content_type'] == '21':
            flow_dic[role + '_tls_encrypted_alert'] = True
        #could be single client hello or client key exchange change spec    
        elif '22' in tls['tls_tls_record_content_type']:
            #client hello
            if 'tls_tls_handshake_type' in tls:
                if tls['tls_tls_handshake_type'] == '1' or tls['tls_tls_handshake_type'] == '2':
                    flow_dic[role + '_outer_tls_version'] = tls["tls_tls_record_version"]
                    flow_dic[role + '_inner_tls_version'] = tls["tls_tls_handshake_version"]
                    if role == 'client':
                        if tls["tls_tls_handshake_session_id_length"] == '0':
                            flow_dic[role + '_tls_reuse'] = False
                        else:
                            flow_dic[role + '_tls_reuse'] = True
                    if "tls_tls_handshake_cipher_suites_length" in tls:
                        flow_dic[role + '_cipher_suites_length'] = tls["tls_tls_handshake_cipher_suites_length"]
                    if "tls_tls_handshake_ciphersuite" in tls:    
                        flow_dic[role + '_cipher_suites'] = tls["tls_tls_handshake_ciphersuite"]
                    if "tls_tls_handshake_extensions_server_name" in tls:
                        flow_dic[role + '_sni'] = tls["tls_tls_handshake_extensions_server_name"]
                    if "tls_tls_handshake_extension_type" in tls:
                        flow_dic[role + '_tls_extenson'] = tls["tls_tls_handshake_extension_type"]
                    if "tls_tls_handshake_comp_method" in tls:
                        flow_dic[role + '_compression'] = tls["tls_tls_handshake_comp_method"]
                    if "tls_tls_handshake_extensions_ec_point_format" in tls:
                        flow_dic[role + '_ec_point_format'] = tls["tls_tls_handshake_extensions_ec_point_format"]
                    if "tls_tls_handshake_extensions_ec_point_formats_length" in tls:
                        flow_dic[role + '_elliptical_curve'] = tls["tls_tls_handshake_extensions_ec_point_formats_length"]
                    flow_dic[role + '_hello_length'] = tls["tls_tls_handshake_length"]

                    random_bytes = tls['tls_tls_handshake_random_bytes']
                    first_4_random_time = int('0x' + ''.join(random_bytes.split(":")[:4]), 16)
                    epoch_time = int(pkt['layers']['frame']["frame_frame_time_epoch"].split('.')[0])
                    if first_4_random_time > epoch_time + 86400 or first_4_random_time < epoch_time - 86400:
                        flow_dic[role + '_hello_byte_random'] = True
                    else:
                        flow_dic[role + '_hello_byte_random'] = False

                    random_time = tls["tls_tls_handshake_random_time"].split('.')[0].replace('T', ' ')
                    timearray = time.strptime(random_time, "%Y-%m-%d %H:%M:%S")
                    timestamp = int(time.mktime(timearray))
                    if timestamp > epoch_time + 86400 or timestamp < epoch_time - 86400:
                        flow_dic[role + '_hello_time_random'] = True
                    else:
                        flow_dic[role + '_hello_time_random'] = False                        

                if tls['tls_tls_handshake_type'] == '16':
                    if 'tls_tls_handshake_client_point_len' in tls:
                        flow_dic["client_key_length"] = tls['tls_tls_handshake_client_point_len']
                    if "tls_tls_handshake_epms_len" in tls:
                        flow_dic["tls_tls_handshake_epms_len"] = tls["tls_tls_handshake_epms_len"]
    #ssl handshake
    elif "tls_tls_record_version" in tls:
        flow_dic[role + '_inner_tls_version'] = tls["tls_tls_handshake_version"]
        if "tls_tls_handshake_cipherspec" in tls:    
            flow_dic[role + '_cipher_suites'] = tls["tls_tls_handshake_cipherspec"]
        if "tls_tls_handshake_cipher_spec_len" in tls:
            flow_dic[role + '_cipher_suites_length'] = tls["tls_tls_handshake_cipher_spec_len"]
    if 'tls_tls_app_data' in tls:
        flow_dic[role + '_applicationdata_length_list'].append(int(tls["tls_tls_record_length"]))
        curr_time = float(pkt["layers"]['frame']["frame_frame_time_relative"])
        if app_data_time_dic[flow][role] != None:
            flow_dic[role + '_applicationdata_interval_list'].append(curr_time - app_data_time_dic[flow][role])
        app_data_time_dic[flow][role] = curr_time  
    if "tls_tls_handshake_certificate" in tls:
        flow_dic = cert_parse(flow_dic, pkt, role, app_data_time_dic, flow, tls)
    return flow_dic


def parse_pcap(pcap_file):
    pcap_list = readpcap(pcap_file)
    pcap_parse_dict = {}
    app_data_time_dic = {}
    for p in pcap_list:
        pkt = json.loads(p)
        srcport = pkt['layers']['tcp']['tcp_tcp_srcport']
        dstport = pkt['layers']['tcp']['tcp_tcp_dstport']
        srcip = pkt['layers']['ip']['ip_ip_src']
        dstip = pkt['layers']['ip']['ip_ip_dst']
        if dstport == '443':
            flow = srcip + ":" + srcport + '_' + dstip + ":" + dstport 
            role = 'client'
        else: 
            flow = dstip + ":" + dstport + '_' + srcip + ":" + srcport 
            role = 'server'
        #print(flow)
        if not flow in pcap_parse_dict:
            pcap_parse_dict[flow] = defind_ini_dic(flow)
            app_data_time_dic[flow] = {}
            app_data_time_dic[flow]['client'] = None
            app_data_time_dic[flow]['server'] = None
        if role == 'client':
            pcap_parse_dict[flow]['client_packets'] += 1
            pcap_parse_dict[flow]['client_tot_bytes'] += int(pkt['layers']['tcp']['tcp_tcp_len'])
        else: 
            #print('!!! %s'%pcap_parse_dict[flow])
            pcap_parse_dict[flow]['server_packets'] += 1
            pcap_parse_dict[flow]['server_tot_bytes'] += int(pkt['layers']['tcp']['tcp_tcp_len'])
        #syn packet find tcp options    
        if pkt['layers']['tcp']['tcp_tcp_flags_syn']:
            if role == 'client':
                pcap_parse_dict[flow]['client_tcp_option'] = pkt['layers']['tcp']['tcp_tcp_options']
            else: 
                pcap_parse_dict[flow]['server_tcp_option'] = pkt['layers']['tcp']['tcp_tcp_options']
        #reset packet update client / server reset flag
        elif pkt['layers']['tcp']['tcp_tcp_flags_reset']:
            if role == 'client':
                pcap_parse_dict[flow]['client_reset'] = True
            else: 
                pcap_parse_dict[flow]['server_reset'] = True
        # fin packet update client/server fin flag
        elif pkt['layers']['tcp']['tcp_tcp_flags_fin']:
            if role == 'client':
                pcap_parse_dict[flow]['client_fin'] = True
            else: 
                pcap_parse_dict[flow]['server_fin'] = True
        elif 'tls' in pkt['layers']:
            #print('frame number %s, role %s'%(pkt['layers']['frame']["frame_frame_number"], role))
            flow_dic = pcap_parse_dict[flow]
            if isinstance(pkt['layers']['tls'], list):
                for tls in pkt['layers']['tls']:
                    pcap_parse_dict[flow] = tls_parse(flow_dic, pkt, role, app_data_time_dic, flow, tls)
            else:
                tls = pkt['layers']['tls']
                pcap_parse_dict[flow] = tls_parse(flow_dic, pkt, role, app_data_time_dic, flow, tls)

    return pcap_parse_dict

def calulation(stats_list):
    max_value = max(stats_list)
    min_value = min(stats_list)
    avr_value = np.mean(stats_list)
    stardard_divation = np.std(stats_list)
    return max_value, min_value, avr_value, stardard_divation

def dic_statstic(flow_dic):
    flow_dic_remove_list = ["server_port", 
    "client_port", 
    "client_ip", 
    "server_applicationdata_length_list", 
    "client_applicationdata_length_list",
    "server_applicationdata_interval_list",
    "client_applicationdata_interval_list"]
    for flow in flow_dic.keys():
        if len(flow_dic[flow]['client_applicationdata_length_list']) > 1:
            flow_dic[flow]['client_applicationdata_length_max'], flow_dic[flow]['client_applicationdata_length_mini'], flow_dic[flow]['client_applicationdata_length_average'], flow_dic[flow]['client_applicationdata_length_standard_deviation'] = calulation(flow_dic[flow]['client_applicationdata_length_list'])
        if len(flow_dic[flow]['client_applicationdata_interval_list']) > 1:
            flow_dic[flow]['client_applicationdata_interval_max'], flow_dic[flow]['client_applicationdata_interval_mini'], flow_dic[flow]['client_applicationdata_interval_average'], flow_dic[flow]['client_applicationdata_interval_standard_deviation'] = calulation(flow_dic[flow]['client_applicationdata_interval_list'])
        if len(flow_dic[flow]['server_applicationdata_interval_list']) > 1:
            flow_dic[flow]['server_applicationdata_interval_max'], flow_dic[flow]['server_applicationdata_interval_mini'], flow_dic[flow]['server_applicationdata_interval_average'], flow_dic[flow]['server_applicationdata_interval_standard_deviation'] = calulation(flow_dic[flow]['server_applicationdata_interval_list'])
        if len(flow_dic[flow]['server_applicationdata_length_list']) > 1:
            flow_dic[flow]['server_applicationdata_length_max'], flow_dic[flow]['server_applicationdata_length_mini'], flow_dic[flow]['server_applicationdata_length_average'], flow_dic[flow]['server_applicationdata_length_standard_deviation'] = calulation(flow_dic[flow]['server_applicationdata_length_list'])
        
        for i in list(flow_dic[flow].keys()):
            if i in flow_dic_remove_list:
                del flow_dic[flow][i]
            elif isinstance(flow_dic[flow][i], list):
                flow_dic[flow][i] = "_".join(flow_dic[flow][i])

    return flow_dic

def main():
    pcap_parse_dict = parse_pcap(sys.argv[1])
    pcap_parse_dict = dic_statstic(pcap_parse_dict)
    return pcap_parse_dict

if __name__ == "__main__":
    pcap_parse_dict = main()
    print(json.dumps(pcap_parse_dict))

