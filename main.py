#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Use PyShark to read pcap files or traffic and analyze them
"""
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from multiprocessing import Process, JoinableQueue, cpu_count
import numpy as np
from optparse import OptionParser
import os
import pyshark
import socket
import struct
import sys
from time import time
reload(sys)
sys.setdefaultencoding('utf8')

dict_nodes = {}

messages = {'gtp': {1: {16: 'CreatePDPContextRequest', 17: 'CreatePDPContextResponse',
                        18: 'UpdatePDPContextRequest', 19: 'UpdatePDPContextResponse',
                        20: 'DeletePDPContextRequest', 21: 'DeletePDPContextResponse'},
                    2: {32: 'CreateSessionRequest', 33: 'CreateSessionResponse',
                        34: 'ModifyBearerRequest', 35: 'ModifyBearerResponse',
                        36: 'DeleteSessionRequest', 37: 'DeleteSessionResponse'}}}

labels = []

# Create the list of GTP messages
for v in messages['gtp'].keys():
    for i, m in enumerate(messages['gtp'][v]):
        if i % 2:
            labels.append(messages['gtp'][v][m][:-8])


class Analyzer(Process):

    # def __init__(self, vlan_id, packets_queue, dict_results):
    def __init__(self, vlan_id, packets_queue, results_queue):
        Process.__init__(self)
        self.name = 'Process-{0}'.format(vlan_id)
        self.vlan_id = int(vlan_id)
        self.packets_queue = packets_queue
        self.results_queue = results_queue
        self.sum_values = {}
        self.dict = {}

    # def print_barchar(self):
    #
    #     global labels, messages
    #
    #     # Compute the number of messages of each type
    #     for k in self.dict.keys():
    #         for m in self.dict[k]:
    #             if m not in self.sum_values.keys():
    #                 self.sum_values[m] = 0
    #             self.sum_values[m] += self.dict[k][m]
    #
    #     requests = []
    #     responses = []
    #
    #     for v in messages['gtp'].keys():
    #         for i, m in enumerate(messages['gtp'][v]):
    #             if i % 2:
    #                 responses.append(self.sum_values[(v, m)] if (v, m) in self.sum_values.keys() else 0)
    #             else:
    #                 requests.append(self.sum_values[(v, m)] if (v, m) in self.sum_values.keys() else 0)
    #
    #     # This is for plotting purpose
    #     ind = np.arange(len(labels))  # the x locations for the groups
    #     width = 0.35  # the width of the bars
    #
    #     fig, ax = plt.subplots()
    #     rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    #     rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')
    #
    #     # Add some text for labels, title and custom x-axis tick labels, etc.
    #     ax.set_ylabel('No of Messages')
    #     ax.set_title('Number of messages - VLAN id {0}'.format(self.vlan_id))
    #     ax.set_xticks(ind)
    #     ax.set_xticklabels(labels, rotation=45)
    #     ax.legend()
    #
    #     autolabel(ax, rects1, "left")
    #     autolabel(ax, rects2, "right")
    #
    #     plt.show()

    def run(self):

        while True:

            packet = self.packets_queue.get()

            if packet is None:
                # Poison pill means shutdown
                print '%s: Exiting' % self.name
                self.packets_queue.task_done()
                d = {self.vlan_id: self.dict}
                # self.print_barchar()
                self.results_queue.put(d)
                break

            if packet.gtp_message in messages['gtp'][packet.gtp_version].keys():

                # Create a new dictionary for the couple (ip src, ip dst) if it does not exist yet
                ips = (packet.src_ip, packet.dst_ip)
                if ips not in self.dict.keys():
                    self.dict[ips] = {}

                # Create a new counter for the given couple of ips and message type if it does not exist yet
                msg = (packet.gtp_version, packet.gtp_message)
                if msg not in self.dict[ips].keys():
                    self.dict[ips][msg] = 0

                # Count new message
                try:
                    self.dict[ips][msg] += 1
                    print 'Packet #{0} processed'.format(packet.num)
                except KeyError:
                    print 'KeyError, keys: {0},{1}'.format(self.vlan_id, ips, msg)

            # Signal task completed
            self.packets_queue.task_done()

        # DEBUG
        # dict_results = self.dict

        return


class Packet(object):

    def __init__(self, pkt):

        try:
            self.num = int(pkt.number)
            self.vlan_id = int(pkt.layers[1].id)
            self.src_ip = ip2int(pkt.ip.src)
            self.dst_ip = ip2int(pkt.ip.dst)
            gtp = pkt.layers[4]
            try:
                self.gtp_version = int(gtp.version)
            except AttributeError:
                self.gtp_version = 1
            self.gtp_message = int(gtp.message) if self.gtp_version == 1 else int(gtp.message_type)

        except KeyError as e:
            return 'KeyError: {0}'.format(e)

    def __call__(self):
        # return '%s * %s = %s' % (self.gtp_version, self.gtp_message, self.gtp_version * self.gtp_message)
        return '%s, %s, %s, %s' % (self.src_ip, self.dst_ip, self.gtp_version, self.gtp_message)

    # def __str__(self):
    #     # return '%s * %s' % (self.gtp_version, self.gtp_message)
    #     return '%s, %s' % (self.gtp_version, self.gtp_message)

    def num(self):
        return self.num

    def vlan_id(self):
        return self.vlan_id

    def src_ip(self):
        return self.src_ip

    def dst_ip(self):
        return self.dst_ip

    def gtp_version(self):
        return self.gtp_version

    def gtp_message(self):
        return self.gtp_message


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def autolabel(ax, rects, xpos='center'):
    """
    Attach a text label above each bar in *rects*, displaying its height.

    *xpos* indicates which side to place the text w.r.t. the center of
    the bar. It can be one of the following {'center', 'right', 'left'}.
    """

    xpos = xpos.lower()  # normalize the case of the parameter
    ha = {'center': 'center', 'right': 'left', 'left': 'right'}
    offset = {'center': 0.5, 'right': 0.57, 'left': 0.43}  # x_txt = x + w*off

    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()*offset[xpos], 1.01*height,
                '{}'.format(height), ha=ha[xpos], va='bottom')


def create_barchart_vlan(vlan_id, results):
    """
    Creates a plot of type bar chart to display number of messages by VLAN
    :param vlan_id: 
    :param results: 
    :return: Figure 
    """

    global labels, messages

    sum_values = {}

    # Compute the number of messages of each type
    for k in results.keys():
        for m in results[k].keys():
            if m not in sum_values.keys():
                sum_values[m] = 0
            sum_values[m] += results[k][m]

    requests = []
    responses = []

    for v in messages['gtp'].keys():
        for i, m in enumerate(messages['gtp'][v]):
            if i % 2:
                responses.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
            else:
                requests.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)

    # This is for plotting purpose
    ind = np.arange(len(labels))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = vlan_id
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('VLAN id {0}'.format(vlan_id))
    ax.set_xticks(ind)
    ax.set_xticklabels(labels, rotation=45)
    ax.legend()

    autolabel(ax, rects1, "left")
    autolabel(ax, rects2, "right")
    
    # plt.show()
    
    return fig


def create_barchart_sum(sum_values):

    global labels, messages

    requests = []
    responses = []

    for v in messages['gtp'].keys():
        for i, m in enumerate(messages['gtp'][v]):
            if i % 2:
                responses.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
            else:
                requests.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)

    # This is for plotting purpose
    ind = np.arange(len(labels))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = "Sum Total"
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('Sum total')
    ax.set_xticks(ind)
    ax.set_xticklabels(labels, rotation=45)
    ax.legend()

    autolabel(ax, rects1, "left")
    autolabel(ax, rects2, "right")

    # plt.show()


def print_results(results, base):
    """
    Prints results from dictionaries stored in a JoinableQueue
    :param results: Object of type JoinableQueue
    :param base: Base name of the file being processed
    :return:
    """
    global dict_nodes
    overall_values = {}
    global labels

    # The PDF document
    pdf_pages = PdfPages('{0}.pdf'.format(base))

    while not results.empty():
        d = results.get()
        for v in d.keys():
            print "VLAN id {0}".format(v)
            pdf_pages.savefig(create_barchart_vlan(v, d[v]))
            plt.close()
            for i in d[v].keys():
                src = int2ip(i[0])
                dst = int2ip(i[1])
                if src in dict_nodes.keys():
                    src = dict_nodes[src]
                if dst in dict_nodes.keys():
                    dst = dict_nodes[dst]
                print "\t{0}-{1}".format(src, dst)
                for m in d[v][i]:
                    print "\t\t{0}: {1}".format(messages['gtp'][m[0]][m[1]], d[v][i][m])
                    if m not in overall_values.keys():
                        overall_values[m] = 0
                    overall_values[m] += d[v][i][m]

    pdf_pages.savefig(create_barchart_sum(overall_values))
    plt.close()
    # Write the PDF document to the disk
    pdf_pages.close()


def process_pcap(pcap, base):
    """
    Process a pcap file
    :param pcap: pcap file as read by pyshark module
    :param base: base name of the file being processed
    :return: None
    """
    # Establish communication queues
    tasks = {}
    packets_to_process = {}
    results = JoinableQueue()

    for pkt in pcap:

        try:

            # Obtain VLAN id
            vlan_id = pkt.layers[1].id

            # Create queues for the corresponding VLAN if they do not exist
            if vlan_id not in packets_to_process.keys():
                packets_to_process[vlan_id] = JoinableQueue()

            # Create and start tasks for the corresponding VLAN if they do not exist
            if vlan_id not in tasks.keys():
                print 'Creating Analyzer for VLAN id {0}'.format(vlan_id)
                # results[vlan_id] = m.dict()
                tasks[vlan_id] = Analyzer(vlan_id, packets_to_process[vlan_id], results)
                tasks[vlan_id].start()

            # # Add package to queue for the corresponding VLAN
            # if gtp.version == '1':
            #     packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message)))
            # elif gtp.version == '2':
            #     packets_to_process[vlan_id].put(Packet(int(gtp.version), int(gtp.message_type)))

            packets_to_process[vlan_id].put(Packet(pkt))

        except AttributeError as e:
            print 'AttributeError: {0}'.format(e)

        except KeyError as e:
            print 'KeyError: {0}'.format(e)

    # Add a poison pill for each consumer
    for i in tasks.keys():
        packets_to_process[i].put(None)

    # Wait for all of the tasks to finish
    for i in tasks.keys():
        packets_to_process[i].join()

    results.task_done()

    # Print results
    print_results(results, base)


def parse_options(argv):
    """
    Parse received arguments
    :param argv: List of received arguments
    :return: List of options after parsing
    """
    parser = OptionParser(usage="usage: %prog filename.json [-i input_dir] [-o output_dir]", version="%prog 0.1")
    parser.add_option("-n", "--nodesfile", dest="nodes", help="Input nodes.csv file", default="nodes.csv")
    parser.add_option("-i", "--inputport", dest="iport", help="Input port/s", default=None)
    parser.add_option("-f", "--inputfile", dest="ifile", help="Input pcap file/s", default=None)

    options, unused_args = parser.parse_args(argv)

    errmsg = ''
    global dict_nodes

    if options.iport is None and options.ifile is None:
        parser.print_help()
        sys.exit(2)

    if options.nodes:
        # Check nodes file exists
        if os.path.isfile(options.nodes):
            with open(options.nodes, 'rb') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=';', quoting=csv.QUOTE_NONE)
                for row in reader:
                    dict_nodes[row['ip-address']] = row['network-element-name']
                    # DEBUG
                    # print(row['ip-address'], row['network-element-name'])
        else:
            errmsg += 'Input file {0} cannot be found\n'.format(options.nodes)

    if errmsg:
        print errmsg
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

    # Determine the number of tasks that can be run in parallel
    # num_proc = cpu_count()

    if options.ifile:
        cap = pyshark.FileCapture(options.ifile)
        base = os.path.splitext(os.path.basename(options.ifile))[0]
        process_pcap(cap, base)

    print('...Finished')

    # Print time taken to process all packets
    print('It took {0}'.format(time() - ts))


""" Entry point """
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
