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

import numpy as np
from sklearn import metrics
import logging
import struct

class Clustering:
    def __init__(self, fields, protocol_type):
        self.fields = fields
        self.protocol_type = protocol_type
        
    def evaluation(self, clustering_result_true, clustering_result_method):
        print("[++++++++] Evaluate Clustering results")
        results_list = list()
        labels_true_list, labels_method_list = list(), list()
        for test_id in [0, 1]:
            results_true = clustering_result_true[test_id]
            if len(results_true) == 0:
                logging.error("The groundtruth could not be empty when evaluating clustering results")
                return

            dict_kwtoi = dict()
            for i,kw in enumerate(sorted(set(results_true), key=results_true.index)):
                dict_kwtoi[kw] = i
            labels_true = [dict_kwtoi[kw] for kw in results_true]
            labels_true_list.append(labels_true)

            
            results_method = clustering_result_method[test_id]
            dict_kwtoi = dict()
            for i,kw in enumerate(sorted(set(results_method), key=results_method.index)):
                dict_kwtoi[kw] = i
            labels_method = [dict_kwtoi[kw] for kw in results_method]
            labels_method_list.append(labels_method)

            h = metrics.homogeneity_score(labels_true, labels_method)
            c = metrics.completeness_score(labels_true, labels_method)
            v = metrics.v_measure_score(labels_true, labels_method) 
            
            test_direction = "Request" if test_id == 0 else "Response"
            print("{}:\nHomogeneity score: {:.8}\nCompleteness score: {:.8}\nV-measure score: {:.8}".format(test_direction, h, c, v))
            results_list.append([h, c, v])
        # total
        labels_true_request, labels_true_response = labels_true_list
        labels_method_request, labels_method_response = labels_method_list
        labels_true_total = labels_true_request + [kw + np.max(labels_true_request) + 1 for kw in labels_true_response]
        labels_method_total = labels_method_request + [kw + np.max(labels_method_request) + 1 for kw in labels_method_response]
        h = metrics.homogeneity_score(labels_true_total, labels_method_total)
        c = metrics.completeness_score(labels_true_total, labels_method_total)
        v = metrics.v_measure_score(labels_true_total, labels_method_total)
        print("Total:\nHomogeneity score: {:.8}\nCompleteness score: {:.8}\nV-measure score: {:.8}".format(h, c, v))
        results_list.append([h, c, v])

    def cluster_by_kw_true(self, messages):
        print("[++++++++] Cluster by True Keyword")
        results = list()

        if not self.protocol_type:
            logging.error("The protocol_type (-t) is required for computing the true clustering")
            return results
        
        for message in messages:
            kw = self.get_true_keyword(message)
            results.append(kw)
        
        return results

    def get_true_keyword(self, message):
        if self.protocol_type == "dhcp":
            kw = message.data[242:243]
        elif self.protocol_type == "dnp3":
            kw = message.data[12:13]
        elif self.protocol_type == "ftp":
            kw = re.split(" |-|\r|\n", message.data.decode())[0]
        elif self.protocol_type == "icmp":
            kw = message.data[0:2]
        elif self.protocol_type == "modbus":
            kw = message.data[7:8]
        elif self.protocol_type == "ntp":
            kw = message.data[0] & 0x07
        elif self.protocol_type == "smb":
            kw = message.data[4+4]
        elif self.protocol_type == "smb2":
            kw = struct.unpack("<H", message.data[4+12:4+12+2])[0]
        elif self.protocol_type == "tftp":
            kw = message.data[0:2]
        elif self.protocol_type == "zeroaccess":
            kw = message.data[4:8]
        else:
            logging.error("The protocol_type is unknown")

        if type(kw).__name__ == "bytes":
            kw = str(kw.hex())
        
        return kw

    def cluster_by_kw_inferred(self, fid_inferred_list, messages):
        print("[++++++++] Cluster by Inferred Keyword")
        results = [list() for message in messages]
        for fid_inferred in fid_inferred_list:
            il, ir = 0, 0
            for i in range(fid_inferred):
                il += self.fields[i].domain.dataType.size[1] // 8
            ir = il + (self.fields[fid_inferred].domain.dataType.size[1] // 8)

            for j in range(len(messages)):
                results[j].append(messages[j].data[il:ir])
        results = [''.join(result) for result in results]

        return results
