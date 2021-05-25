# This file is part of NetPlier, a tool for binary protocol reverse engineering.
# Copyright (C) 2021 Yapeng Ye

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

import argparse
import sys
import os
import logging
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
#logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

from netplier import NetPlier
from processing import Processing
from alignment import Alignment
from clustering import Clustering

if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', required=True, dest='filepath_input', help='filepath of input trace')
    parser.add_argument('-t', '--type', dest='protocol_type', help='type of the protocol (for generating the ground truth): \
        dhcp, dnp3, icmp, modbus, ntp, smb, smb2, tftp, zeroaccess')
    parser.add_argument('-o', '--output_dir', dest='output_dir', default='tmp_netplier/', help='output directory')
    parser.add_argument('-l', '--layer', dest='layer', default=5, type=int, help='the layer of the protocol')
    parser.add_argument('-m', '--mafft', dest='mafft_mode', default='ginsi', help='the mode of mafft: [ginsi, linsi, einsi]')
    parser.add_argument('-mt', '--multithread', dest='multithread', default=False, action='store_true', help='run mafft with multi threads')

    args = parser.parse_args()

    p = Processing(filepath=args.filepath_input, protocol_type=args.protocol_type, layer=args.layer)
    # p.print_dataset_info()
    
    mode = args.mafft_mode
    if args.protocol_type in['dnp3']: # tftp
        mode = 'linsi'
    netplier = NetPlier(messages=p.messages, direction_list=p.direction_list, output_dir=args.output_dir, mode=mode, multithread=args.multithread)
    fid_inferred = netplier.execute()
    
    # Clustering
    messages_aligned = Alignment.get_messages_aligned(netplier.messages, os.path.join(netplier.output_dir, Alignment.FILENAME_OUTPUT_ONELINE))
    messages_request, messages_response = Processing.divide_msgs_by_directionlist(netplier.messages, netplier.direction_list)
    messages_request_aligned, messages_response_aligned = Processing.divide_msgs_by_directionlist(messages_aligned, netplier.direction_list)

    clustering = Clustering(fields=netplier.fields, protocol_type=args.protocol_type)
    clustering_result_request_true = clustering.cluster_by_kw_true(messages_request)
    clustering_result_response_true = clustering.cluster_by_kw_true(messages_response)
    clustering_result_request_netplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_request_aligned)
    clustering_result_response_netplier = clustering.cluster_by_kw_inferred(fid_inferred, messages_response_aligned)
    clustering.evaluation([clustering_result_request_true, clustering_result_response_true], [clustering_result_request_netplier, clustering_result_response_netplier])
    
