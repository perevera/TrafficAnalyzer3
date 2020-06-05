# -*- coding: utf-8 -*-
# !/usr/bin/env python

# import datetime
from collections import namedtuple, Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np

Parties = namedtuple('Parties', 'a b')

applications = {4: 'Gy',
                16777238: 'Gx',
                16777251: 'S6a/Sd',
                16777302: 'Sy'}

messages = {'gtp': {1: 'EchoRequest', 2: 'EchoResponse',
                    16: 'CreatePDPContextRequest', 17: 'CreatePDPContextResponse',
                    18: 'UpdatePDPContextRequest', 19: 'UpdatePDPContextResponse',
                    20: 'DeletePDPContextRequest', 21: 'DeletePDPContextResponse'},
            'gtpv2': {32: 'CreateSessionRequest', 33: 'CreateSessionResponse',
                      34: 'ModifyBearerRequest', 35: 'ModifyBearerResponse',
                      36: 'DeleteSessionRequest', 37: 'DeleteSessionResponse',
                      170: 'ReleaseAccessBearersRequest', 171: 'ReleaseAccessBearersResponse'},
            'diameter': {258: 'RAR/RAA',
                         272: 'CCR/CCA',
                         274: 'ASR/ASA',
                         275: 'STR/STA',
                         280: 'DWR/DWA',
                         316: 'ULR/ULA',
                         317: 'CLR/CLA',
                         318: 'AIR/AIA',
                         319: 'IDR/IDA',
                         320: 'DSR/DSA',
                         321: 'PUR/PUA',
                         322: 'RSR/RSA',
                         323: 'NOR/NOA',
                         324: 'ECR/ECA',
                         325: 'MIR/MIA',
                         326: 'QAR/QAA',
                         327: 'QIR/QIA',
                         328: 'CUR/CUA',
                         329: 'ISR/ISA',
                         330: 'NCR/NCA',
                         8388635: 'SLR/SLA',
                         8388636: 'SNR/SNA',
                         8388637: 'TSR/TSA',
                         8388638: 'UVR/UVA',
                         8388639: 'DAR/DAA',
                         8388640: 'DNR/DNA',
                         8388641: 'SIR/SIA',
                         8388642: 'CVR/CVA',
                         8388643: 'DTR/DTA',
                         8388644: 'DRR/DRA',
                         8388645: 'OFR/OFA',
                         8388646: 'TFR/TFA',
                         8388647: 'SRR/SRA',
                         8388648: 'ALR/ALA',
                         8388649: 'RDR/RDA'},
            's1ap': {9: 'InitialContextSetupRequest', 3: 'InitialContextSetupRequest'},
            'gsm_map': {2: 'updateLocation', 3: 'cancelLocation', 7: 'insertSubscriberData',
                        8: 'deleteSubscriberData', 23: 'updateGprsLocation', 43: 'checkIMEI',
                        45: 'sendRoutingInfoForSM', 56: 'sendAuthenticationInfo'}}


def autolabel(ax, rects, xpos='center'):
    """
    Attach a text label above each bar in *rects*, displaying its height.
    *xpos* indicates which side to place the text w.r.t. the center of
    the bar. It can be one of the following {'center', 'right', 'left'}.
    :param ax: Axes object
    :param rects: List of bars
    :param xpos:
    """
    xpos = xpos.lower()  # normalize the case of the parameter
    ha = {'center': 'center', 'right': 'left', 'left': 'right'}
    offset = {'center': 0.5, 'right': 0.57, 'left': 0.43}  # x_txt = x + w*off

    for rect in rects:
        height = rect.get_height()
        if height > 0:
            ax.text(rect.get_x() + rect.get_width() * offset[xpos], 1.01 * height, '{}'.format(height), ha=ha[xpos], va='bottom', size=6)


def create_barchart(dictio, k, proto):
    """
    Creates a plot of type bar chart to display number of messages
    :param dictio: dictionary containing all data
    :param k: key for each chart, this is the couple of parties
    :proto: protocol
    :return: Figure
    """
    global messages

    # sum_values = {}

    # Create the list of messages for the given protocol
    labels = []

    requests = []
    responses = []
    x_axis = []

    for m in messages[proto]:
        if m in dictio[k]['messages']:
            requests.append(dictio[k]['messages'][m][1])
            responses.append(dictio[k]['messages'][m][0])
            x_axis.append(m)
            labels.append(messages[proto][m])

    # Determine the most frequent port
    c1 = Counter(dictio[k]['ports'])
    port = c1.most_common(1)[0][0]

    # Determine the application
    try:
        app_name = applications[dictio[k]['app_id']]
    except KeyError as e:
        app_name = 'Unknown: {}'.format(e.args[0])

    # This is for plotting purpose
    ind = np.arange(len(x_axis))  # the x locations for the groups
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots()
    fig.suptitle = proto
    rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
    rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('Number of messages')
    ax.set_title('{} - {} | {} | {}'.format(k.a, k.b, port, app_name))
    ax.set_xticks(ind)
    ax.set_xticklabels(labels, rotation=35)
    ax.legend()

    autolabel(ax, rects1, 'center')
    autolabel(ax, rects2, 'center')

    # plt.show()

    return fig


# def create_barchart_sum(sum_values):
#
#     global labels_gtp, messages
#
#     requests = []
#     responses = []
#
#     for v in messages['gtp'].keys():
#         for i, m in enumerate(messages['gtp'][v]):
#             if i % 2:
#                 responses.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
#             else:
#                 requests.append(sum_values[(v, m)] if (v, m) in sum_values.keys() else 0)
#
#     # This is for plotting purpose
#     ind = np.arange(len(labels_gtp))  # the x locations for the groups
#     width = 0.35  # the width of the bars
#
#     fig, ax = plt.subplots()
#     fig.suptitle = "Sum Total"
#     rects1 = ax.bar(ind - width / 2, requests, width, color='SkyBlue', label='Requests')
#     rects2 = ax.bar(ind + width / 2, responses, width, color='IndianRed', label='Responses')
#
#     # Add some text for labels_gtp, title and custom x-axis tick labels_gtp, etc.
#     ax.set_ylabel('Number of messages')
#     ax.set_title('Sum total')
#     ax.set_xticks(ind)
#     ax.set_xticklabels(labels_gtp, rotation=45)
#     ax.legend()
#
#     autolabel(ax, rects1, "left")
#     autolabel(ax, rects2, "right")
#
#     # plt.show()


def print_results(dictio, proto, fname):
    """
    Prints results from dictionary
    :param dictio: Dictionary of messages
    :param proto: Protocol
    :param fname: Output file name
    :return:
    """
    overall_values = {}

    # curr_dt = datetime.datetime.now()
    # curr_dt_str = curr_dt.strftime('%Y%m%d%H%M%S')

    # The PDF document
    pdf_pages = PdfPages(fname)
        
    for k in dictio:
        # print('Parties: {}'.format(k))
        pdf_pages.savefig(create_barchart(dictio, k, proto))
        plt.close()
        # # Compute overall values
        # for m in dictio[k]:
        #     print("\t\t{}: {}".format(messages[proto][m[0]][m[1]], d[v][i][m]))
        #     if m not in overall_values.keys():
        #         overall_values[m] = 0
        #     overall_values[m] += d[v][i][m]

    # pdf_pages.savefig(create_barchart_sum(overall_values))
    # plt.close()

    # Write the PDF document to the disk
    pdf_pages.close()
