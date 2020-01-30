from optparse import OptionParser
import os
from plot_traffic import print_results
import pyshark
import sys
from time import time

# packets_array = []
dict_ips = dict()   # Dictionary of messages by ip pairs
dict_pcs = dict()   # Dictionary of messages by point code pairs
dict_gts = dict()   # Dictionary of messages by global title pairs


# def counter(*args):
#     packets_array.append(args[0])


# def count_packets():
#     cap = pyshark.FileCapture('http.cap', keep_packets=False)
#     cap.apply_on_packets(counter, timeout=10000)
#     return len(packets_array)

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
                called_digits = layer.called_digits
                print('\t\tCalling party: {}, Called party: {}'.format(calling_digits, called_digits))
            except AttributeError as e:
                pass
        elif layer.layer_name == 'tcap':
            pass
        elif layer.layer_name == 'gsm_map':
            try:
                if hasattr(layer, 'gsm_old_invoke_element'):
                    msg = 'query'
                    i = 0
                elif hasattr(layer, 'gsm_old_returnresultlast_element'):
                    msg = 'answer'
                    i = 1
                elif hasattr(layer, 'gsm_old_returnerror_element'):
                    msg = 'error'
                    i = 1
                else:
                    msg = 'unknown'
                    # i = -1
                try:
                    op_id = int(layer.gsm_old_localvalue)
                    count_message(dict_ips, (src_host, dst_host), op_id, i)
                    count_message(dict_pcs, (mtp3_opc, mtp3_dpc), op_id, i)
                    count_message(dict_gts, (calling_digits, called_digits), op_id, i)
                    # count_message(dict_ips, '{}-{}'.format(src_host, dst_host), op_id, i)
                    # count_message(dict_pcs, '{}-{}'.format(mtp3_opc, mtp3_dpc), op_id, i)
                    # count_message(dict_gts, '{}-{}'.format(calling_digits, called_digits), op_id, i)
                    # print('\t\t\tOperation: {}, {}'.format(messages['MAP'][op_id], msg))
                except KeyError as e:
                    print(e)
            except AttributeError as e:
                pass
        else:
            pass


def process_pcap(fname, proto):
    """
    Process pcap file
    :param fname: Input pcap file name
    :param proto: Protocol to analyze
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
    
    # print('Number of packets: {}...'.format(len(packets_array)))


def parse_options(argv):
    """
    Parse received arguments
    :param argv: List of received arguments
    :return: List of options after parsing
    """
    parser = OptionParser(usage="usage: %prog -f inputfile", version="%prog 0.1")
    parser.add_option("-f", "--inputfile", dest="ifile", help="Input pcap file/s", default=None)
    parser.add_option("-p", "--protocol", dest="proto", help="Protocol to analyze (gtp, gsm_map...)", default='gsm_map')
    options, unused_args = parser.parse_args(argv)

    errmsg = ''

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

    process_pcap(options.ifile, options.proto)

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
