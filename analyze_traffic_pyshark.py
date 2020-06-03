#!/usr/bin/python
# -*- coding: utf-8 -*-

import csv
from optparse import OptionParser
import os
from plot_traffic import print_results, messages
import pyshark
import sys
from time import time

dict_ips = dict()       # Dictionary of messages by ip pairs
dict_pcs = dict()       # Dictionary of messages by point code pairs
dict_gts = dict()       # Dictionary of messages by global title pairs
dict_nodes = dict()     # Dictionary of messages by node name pairs
nodes_csv = dict()      # Contents of nodes.csv file

# (from nodes.csv file)

SSN = {'0': 'Not used / Unknown',
       '1': 'SCCP MG',
       '3': 'Unknown',
       '6': 'HLR',
       '7': 'VLR',
       '8': 'MSC',
       '9': 'EIR',
       '10': 'is allocated for evolution (possible Authentication Centre)',
       '142': 'RANAP',
       '143': 'RNSAP',
       '145': 'GMLC',
       '146': 'CAP',
       '147': 'gsmSCF',
       '148': 'SIWF',
       '149': 'SGSN',
       '150': 'GGSN',
       '232': 'CNAM',
       '241': 'INAP',
       '247': 'LNP',
       '248': '800 number translation(AIN0.1)',
       '251': 'MSC',
       '252': 'SMLC',
       '253': 'BSS O&M',
       '254': 'BSSAP'
       }


def counter(*args):
    packets_array.append(args[0])


def count_packets():
    cap = pyshark.FileCapture('http.cap', keep_packets=False)
    cap.apply_on_packets(counter, timeout=10000)
    return len(packets_array)


def count_message(dictio, key, op_id, i):
    """

    """
    # Combine couples of endpoints: (t1, t2) and (t2, t1) are considered the same key
    qey = (key[1], key[0])
    key = qey if qey in dictio else key

    if key not in dictio:
        dictio[key] = dict()

    # Create a new counter for the given couple of endpoints and message type if it does not exist yet
    if op_id not in dictio[key]:
        dictio[key][op_id] = [0, 0]

    # Count new message
    try:
        dictio[key][op_id][i] += 1
    except KeyError:
        print('KeyError, keys: {},{}'.format(key, op_id))


def process_packet_gsm_map(*args):
    """

    """
    pkt = args[0]

    src_host = ''
    dst_host = ''
    mtp3_opc = ''
    mtp3_dpc = ''
    calling_digits = ''
    called_digits = ''

    for layer in pkt.layers:
        if layer.layer_name == 'ip':
            try:
                src_host = layer.src_host
                dst_host = layer.dst_host
                print('Source host: {}, Destination host: {}'.format(src_host, dst_host))
            except AttributeError as e:
                pass
        if layer.layer_name == 'm3ua':
            try:
                mtp3_opc = layer.mtp3_opc
                mtp3_dpc = layer.mtp3_dpc
                print('\tOPC: {}, DPC: {}'.format(mtp3_opc, mtp3_dpc))
            except AttributeError as e:
                pass
        elif layer.layer_name == 'sccp':
            try:
                calling_digits = layer.calling_digits
                calling_ssn = layer.calling_ssn
                called_digits = layer.called_digits
                called_ssn = layer.called_ssn
                print('\t\tCalling party: {}, Called party: {}'.format(calling_digits, called_digits))
            except AttributeError as e:
                pass
        elif layer.layer_name == 'tcap':
            pass
        elif layer.layer_name == 'gsm_map':
            try:
                if hasattr(layer, 'gsm_old_invoke_element'):
                    msg = 'query'
                    i = 1
                elif hasattr(layer, 'gsm_old_returnresultlast_element'):
                    msg = 'answer'
                    i = 0
                elif hasattr(layer, 'gsm_old_returnerror_element'):
                    msg = 'error'
                    i = 0
                else:
                    msg = 'unknown'
                try:
                    op_id = int(layer.gsm_old_localvalue)
                    opc = '{}-{}'.format(mtp3_opc, SSN[calling_ssn])
                    dpc = '{}-{}'.format(mtp3_dpc, SSN[called_ssn])
                    count_message(dict_ips, (src_host, dst_host), op_id, i)
                    count_message(dict_pcs, (opc, dpc), op_id, i)
                    count_message(dict_gts, (calling_digits, called_digits), op_id, i)
                except KeyError as e:
                    print(e)
            except AttributeError as e:
                pass
        else:
            pass


def process_packet_diameter(*args):
    """

    """
    pkt = args[0]

    src_host = ''
    dst_host = ''
    src_node = ''
    dst_node = ''

    for layer in pkt.layers:

        if layer.layer_name == 'ip':
            try:
                src_host = layer.src_host
                dst_host = layer.dst_host
                print('Source host: {}, Destination host: {}'.format(src_host, dst_host))
                try:
                    src_node = nodes_csv[src_host]
                except KeyError as e:
                    src_node = src_host
                try:
                    dst_node = nodes_csv[dst_host]
                except KeyError as e:
                    dst_node = dst_host
                print('Source node: {}, Destination node: {}'.format(src_node, dst_node))
            except AttributeError as e:
                pass

        elif layer.layer_name == 'diameter':

            cmd_code = int(layer.cmd_code)

            # Determine command
            try:
                if messages['diameter'][cmd_code] == 'Session-Termination':
                    msg = 'Session-Termination'
                elif messages['diameter'][cmd_code] == 'Spending-Limit':
                    msg = 'Spending-Limit'
                elif messages['diameter'][cmd_code] == 'Spending-Status-Notification':
                    msg = 'Spending-Status-Notification'
            except KeyError as e:
                msg = 'Unknown'
                print('Unknown command code: {}'.format(e))

            print(msg)

            # Determine direction (request/answer)
            flags = bytearray(layer.flags.encode())
            extract_int = int.from_bytes(flags[8:10], "big")
            # 'R' bit set in the Command Flags means request, cleared means answer
            r_bit = extract_int >> 8 & 1

            # Add to count
            count_message(dict_ips, (src_host, dst_host), cmd_code, r_bit)
            count_message(dict_nodes, (src_node, dst_node), cmd_code, r_bit)

        else:
            pass


def process_pcap(fname, proto, port):
    """
    Process pcap file
    :param fname: Input pcap file name
    :param proto: Protocol to analyze
    :param port: TCP/UDP Port used by this protocol
    :return:
    """
    # global packets_array

    # print('Opening {}...'.format(fname))
    
    if proto == 'gsm_map':
        filtered_cap = pyshark.FileCapture(fname, display_filter='gsm_map', only_summaries=False)
        filtered_cap.apply_on_packets(process_packet_gsm_map, timeout=10000)
        print_results(dict_ips, proto, '{}-{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'ips'))
        print_results(dict_pcs, proto, '{}-{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'point-codes'))
        # print_results(dict_gts, proto)

    elif proto == 'diameter':

        if port:
            decode_as = {'tcp.port=={}'.format(port): 'diameter'}
            filtered_cap = pyshark.FileCapture(fname, decode_as=decode_as, display_filter='diameter', only_summaries=False)
        else:
            filtered_cap = pyshark.FileCapture(fname, display_filter='diameter', only_summaries=False)

        filtered_cap.apply_on_packets(process_packet_diameter, timeout=10000)
        print_results(dict_ips, proto, '{}-{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'ips'))
        print_results(dict_nodes, proto, '{}-{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'nodes'))

        # print("Hello")
    
    # print('Number of packets: {}...'.format(len(packets_array)))


def parse_options(argv):
    """
    Parse received arguments
    :param argv: List of received arguments
    :return: List of options after parsing
    """
    parser = OptionParser(usage="usage: %prog -f inputfile", version="%prog 0.1")
    parser.add_option("-f", "--inputfile", dest="ifile", help="Input pcap file/s", default=None)
    parser.add_option("-n", "--nodesfile", dest="nodes", help="Input nodes.csv file", default="nodes.csv")
    parser.add_option("-p", "--port", dest="port", help="Port", default=None)
    parser.add_option("-t", "--protocol", dest="proto", help="Protocol to analyze (gtp, gsm_map...)", default='gsm_map')
    options, unused_args = parser.parse_args(argv)

    errmsg = ''

    # PENDING: Check input file exists and looks like a pcap file

    # Check nodes file exists
    if options.nodes:
        # Check nodes file exists
        if os.path.isfile(options.nodes):
            with open(options.nodes, 'r') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';', quoting=csv.QUOTE_NONE)
                for row in reader:
                    nodes_csv[row['ip-address']] = row['network-element-name']
                    # DEBUG
                    # print(row['ip-address'], row['network-element-name'])
        else:
            errmsg += 'Input file {0} cannot be found\n'.format(options.nodes)

    if errmsg:
        print(errmsg)
        parser.print_help()
        sys.exit(2)

    return options


def main(argv):
    """
    Main function to open up a pcap file or read input from a port and print out the packets
    :param argv: list of arguments (program name not included)
    :return: None
    """

    # Store current time
    ts = time()

    # Parse arguments
    options = parse_options(argv)

    print('Processing file {0}...'.format(options.ifile))

    process_pcap(options.ifile, options.proto, options.port)

    # if options.ifile:
    #     with open(options.ifile, 'rb') as f:
    #         pcap = dpkt.pcap.Reader(f)
    #         base = os.path.splitext(os.path.basename(options.ifile))[0]
    #         process_pcap(pcap, base)

    print('...Finished')

    # Print time taken to process all packets
    print('It took {} seconds'.format(time() - ts))


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
