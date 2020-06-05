#!/usr/bin/python
# -*- coding: utf-8 -*-

# from collections import Counter
import csv
from optparse import OptionParser
import os
from plot_traffic import print_results, applications, messages, Parties
import pyshark
import sys
from time import time

dict_ips = dict()
dict_pcs = dict()       # Dictionary of messages by point code pairs
dict_gts = dict()       # Dictionary of messages by global title pairs
dict_nodes = dict()     # Dictionary of messages by node name pairs
nodes_csv = dict()      # Contents of nodes.csv file
list_unknown_apps = list()   # List of unknown application ids
list_unknown_msgs = list()   # List of unknown code messages

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


def count_message(dictio, parties, op_id, i, app_id=None, ports=None):
    """
    Add message to the count by key (parties)
    :param dictio: Dictionary to contain all series
    :param parties: Pair of parties exchanging the messages
    :param op_id: Operation id of the message
    :param i: Request/Answer
    :param app_id: Application id
    :ports: Pair of TCP ports exchanging the messages
    """
    # Combine couples of endpoints: (t1, t2) and (t2, t1) are considered the same key
    # qey = (key[1], key[0])
    qey = Parties(parties.b, parties.a)
    key = qey if qey in dictio else parties

    if key not in dictio:
        # dictio[key] = dict()
        dictio[key] = {'app_id': app_id,
                       'ports': list(),
                       'messages': dict()}

    # Create a new counter for the given couple of endpoints and message type if it does not exist yet
    if op_id not in dictio[key]['messages']:
        # dictio[key][op_id] = [0, 0, list()]
        dictio[key]['messages'][op_id] = [0, 0]

    # Count new message
    try:
        dictio[key]['messages'][op_id][i] += 1
    except KeyError:
        print('KeyError, keys: {},{}'.format(key, op_id))
        
    # Add ports to list
    if ports:
        try:
            # dictio[key][op_id][2].append(ports.a)
            # dictio[key][op_id][2].append(ports.b)
            dictio[key]['ports'].append(ports.a)
            dictio[key]['ports'].append(ports.b)
        except KeyError:
            print('KeyError, keys: {},{}'.format(key, op_id))


def process_packet_gsm_map(*args):
    """
    TO-DO: Extract application id and ports and use these data when invoking count_message()
    Also review use of SSNs and Point Codes
    """
    pkt = args[0]

    ips = Parties(None, None)
    ports = Parties(None, None)
    pointcodes = Parties(None, None)
    digits = Parties(None, None)
    ssns = Parties(None, None)

    for layer in pkt.layers:
        if layer.layer_name == 'ip':
            try:
                ips = Parties(layer.src_host, layer.dst_host)
                # print('Source host: {}, Destination host: {}'.format(src_host, dst_host))
            except AttributeError as e:
                pass
        elif layer.layer_name == 'tcp':
            try:
                ports = Parties(layer.srcport, layer.dstport)
            except AttributeError as e:
                pass
        elif layer.layer_name == 'm3ua':
            try:
                pointcodes = Parties(layer.mtp3_opc, layer.mtp3_dpc)
                # print('\tOPC: {}, DPC: {}'.format(mtp3_opc, mtp3_dpc))
            except AttributeError as e:
                pass
        elif layer.layer_name == 'sccp':
            try:
                digits = Parties(layer.calling_digits, layer.called_digits)
                ssns = Parties(layer.calling_ssn, layer.called_ssn)
                # print('\t\tCalling party: {}, Called party: {}'.format(calling_digits, called_digits))
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
                    opc = '{}-{}'.format(pointcodes.a, SSN[ssns.a])
                    dpc = '{}-{}'.format(pointcodes.b, SSN[ssns.b])
                    count_message(dict_ips, ips, op_id, i, ports=ports)
                    count_message(dict_pcs, pointcodes, op_id, i)
                    count_message(dict_gts, digits, op_id, i)
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

    ips = Parties(None, None)
    ports = Parties(None, None)
    nodes = Parties(None, None)

    for layer in pkt.layers:

        if layer.layer_name == 'ip':
            try:
                ips = Parties(layer.src_host, layer.dst_host)
                # print('Source host: {}, Destination host: {}'.format(src_host, dst_host))
                try:
                    src_node = nodes_csv[ips.a]
                except KeyError as e:
                    # src_node = src_host
                    src_node = ips.a
                try:
                    dst_node = nodes_csv[ips.b]
                except KeyError as e:
                    dst_node = ips.b

                nodes = Parties(src_node, dst_node)

                # print('Source node: {}, Destination node: {}'.format(src_node, dst_node))
            except AttributeError as e:
                pass

        elif layer.layer_name == 'tcp':

            try:
                ports = Parties(layer.srcport, layer.dstport)
            except AttributeError as e:
                pass

        elif layer.layer_name == 'diameter':

            # Determine application (i.e. interface, one of: Gx, Gy, S6a/Sd, Sy...)
            app_id = int(layer.applicationid)
            
            try:
                app = applications[app_id]
            except KeyError as e:
                app = 'Unknown'
                if e.args[0] not in list_unknown_apps:
                    list_unknown_apps.append(e.args[0])
                    print('Unknown application id: {}'.format(e.args[0]))

            # Determine command
            cmd_code = int(layer.cmd_code)
            
            try:
                msg = messages['diameter'][cmd_code]
            except KeyError as e:
                msg = 'Unknown'
                if e.args[0] not in list_unknown_msgs:
                    list_unknown_msgs.append(e.args[0])
                    print('Unknown command code: {}'.format(e.args[0]))

            # print(msg)

            # Determine direction (request/answer)
            flags = bytearray(layer.flags.encode())
            extract_int = int.from_bytes(flags[8:10], "big")
            r_bit = extract_int >> 8 & 1    # 'R' bit set in the Command Flags means request, cleared means answer

            # Add to count
            count_message(dict_ips, ips, cmd_code, r_bit, app_id=app_id, ports=ports)
            count_message(dict_nodes, nodes, cmd_code, r_bit, app_id=app_id, ports=ports)

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
        print_results(dict_ips, proto, '{}_{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'ips'))
        print_results(dict_pcs, proto, '{}_{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'point-codes'))
        # print_results(dict_gts, proto)

    elif proto == 'diameter':

        if port:
            decode_as = {'tcp.port=={}'.format(port): 'diameter'}
            filtered_cap = pyshark.FileCapture(fname, decode_as=decode_as, display_filter='diameter', only_summaries=False)
        else:
            filtered_cap = pyshark.FileCapture(fname, display_filter='diameter', only_summaries=False)

        filtered_cap.apply_on_packets(process_packet_diameter, timeout=10000)
        print_results(dict_ips, proto, '{}_{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'ips'))
        print_results(dict_nodes, proto, '{}_{}.pdf'.format(os.path.splitext(os.path.basename(fname))[0], 'nodes'))

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

    print('...Finished')

    # Print time taken to process all packets
    print('It took {} seconds'.format(time() - ts))


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
