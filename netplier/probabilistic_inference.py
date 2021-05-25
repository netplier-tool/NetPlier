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

from sklearn import preprocessing
import numpy as np
import copy
import logging

from factor_graph import MyFactorGraph

class ProbabilisticInference:
    P_K2M, P_M2K = 0.8, 0.6 #0.8, 0.6
    P_K2R, P_R2K = 0.9, 0.6
    P_K2S, P_S2K = 0.9, 0.6 #0.9, 0.7
    P_K2D, P_D2K = 0.9, 0.6
    P_K2V, P_V2K = 0.9, 0.6

    BONUS_VALUE_X2K = 0.2

    def __init__(self, pairs_p, pairs_size):
        self.pairs_p = pairs_p # observation prob
        self.pairs_size = pairs_size

    # inference
    def execute(self, fid_list = None):
        print("[++++++++] Infer the keyword")

        # update fid_list if it is specified
        if fid_list == None:
            fid_list = list(pairs_p.keys())
        else:
            fid_list = [fid for fid in fid_list if fid in self.pairs_p]
        logging.debug("fid_list: {}".format(fid_list)) #debug
        
        # compute implication probabilities
        self.p_implication = dict()
        for fid in self.pairs_p.keys():
            self.p_implication[fid] = self.compute_p_implication(self.pairs_p[fid], self.pairs_size[fid])
            #self.p_implication[fid] = self.compute_p_implication_weighted(self.pairs_p[fid], self.pairs_size[fid])
        
        p_observation = copy.deepcopy(self.pairs_p)
        #self.print_p_lists(fid_list, p_observation)

        # normalize observation prob
        p_observation = self.normalize_p_observation(p_observation)
        #self.print_p_lists(fid_list, p_observation)

        # adjust observation/implication probabilities by cluster size
        logging.debug('[++++] Add bonus by size')
        # test_id: 0: m, 1: r, 2: s, 3: d, 4: v
        for fid in p_observation.keys():
            for test_id in [0, 1, 2]:
                p_observation[fid][test_id] = self.add_bonus_value(p_observation[fid][test_id], self.pairs_size[fid], 0.2)
                #self.p_implication[fid][1][test_id] = self.add_bonus_value(self.p_implication[fid][1][test_id], self.pairs_size[fid], ProbabilisticInference.BONUS_VALUE_X2K)
        # self.print_p_lists(fid_list, p_observation)

        # deal with p < 0
        p_observation = self.update_invalid_p(p_observation)
        # self.print_p_lists(fid_list, p_observation, self.p_implication)

        # TEST: Extend the number of factors to the number of msgs
        #P_lists_dict =  PadPLists(P_lists_dict, dict_sn_msgnum, fid_list)

        # factor graph
        fg_result = dict()
        for fid in fid_list:
            pk_list = list() 
            fg = MyFactorGraph(p_observation=p_observation, p_implication=self.p_implication)
            # can test different constraints together
            # test type (m/r/s/d/v): 0: k2x & x2k, 1: k2x, 2: x2k, -1: not test
            pk_list.append(fg.compute_pk([0,0,0,0,0], fid)) #kv:mrsdv, vk: mrsdv

            ## Weighted Ave
            '''
            p_list_q_weighted, p_list_s_weighted, p_list_g_weighted = p_lists_dict_weighted[fid]
            p_lists_weighted = [p_list_q_weighted, p_list_s_weighted, p_list_d, p_list_v, p_list_g_weighted]
            pk_list.append(factorgraph.compute_pk([0,0,0,0,0], p_lists_weighted, p_values_const_dict[fid]))
            '''
            fg_result[fid] = pk_list

        logging.debug("\n[++++] Final Result")
        pk_list_size = len(list(fg_result.values())[0]) # num of different test
        for i in range(pk_list_size):
            result = dict()
            for fid in fg_result:
                result[fid] = fg_result[fid][i]
            logging.debug(sorted(result.items(), key=lambda x:x[1], reverse=True))

        return self.get_fid_inferred(fg_result)

    def print_p_lists(self, fid_list, p_observation, p_implication = None):
        for fid in fid_list:
            print("\nField {}".format(fid))
            print("Num of messages: {}".format(self.pairs_size[fid]))
            p_lists = p_observation[fid]
            if p_implication == None:
                print("M: {0[0]}\nR: {0[1]}\nS: {0[2]}\nD: {0[3]}\nV: {0[4]}".format(p_lists))
            else:
                print("M: {} {}".format(p_lists[0], p_implication[fid][1][0]))
                print("R: {} {}".format(p_lists[1], p_implication[fid][1][1]))
                print("S: {} {}".format(p_lists[2], p_implication[fid][1][2]))
                print("D: {} {}".format(p_lists[3], p_implication[fid][1][3]))
                print("V: {} {}".format(p_lists[4], p_implication[fid][1][4]))

    # weighted
    def add_bonus_value(self, p_list, size_list, bonus_value):
        size_sum = sum(size_list)
        #p_list = [p + bonus_value * (s / size_sum) for p,s in list(zip(p_list, size_list))]
        result = list()
        for p,s in list(zip(p_list, size_list)):
            if p > 0:
                result.append(p + bonus_value * (s / size_sum))
            else:
                result.append(p)

        return result

    def weight_by_size_(self, p_initial, size_list):
        size_sum = sum(size_list)
        p_list = [p_initial + 0.2 * (size / size_sum)  for size in size_list]

        return p_list

    # output: p_ktox, p_xtok (x: m/r/s/d/v)
    def compute_p_implication_weighted(self, p_lists, size_list):
        p_m, p_r, p_s, p_d, p_v = p_lists

        # k->x
        p_ktom = [ProbabilisticInference.P_K2M] * len(p_m)
        p_ktor = [ProbabilisticInference.P_K2R] * len(p_r)
        p_ktos = [ProbabilisticInference.P_K2S] * len(p_s)
        p_ktod = [ProbabilisticInference.P_K2D] * len(p_d)
        p_ktov = [ProbabilisticInference.P_K2V] * len(p_v)

        # x->k
        p_mtok = [ProbabilisticInference.P_M2K] * len(p_m)
        p_mtok = self.add_bonus_value(p_mtok, size_list, ProbabilisticInference.BONUS_VALUE_X2K)
        #p_mtok = self.weight_by_size_(ProbabilisticInference.P_M2K, size_list)

        p_rtok = [ProbabilisticInference.P_R2K] * len(p_r) # TODO: check weighted
        p_rtok = self.add_bonus_value(p_rtok, size_list, ProbabilisticInference.BONUS_VALUE_X2K)

        p_stok = [ProbabilisticInference.P_S2K] * len(p_s)
        p_stok = self.add_bonus_value(p_stok, size_list, ProbabilisticInference.BONUS_VALUE_X2K)
        #p_stok = self.weight_by_size_(ProbabilisticInference.P_S2K, size_list)
        
        p_dtok = [ProbabilisticInference.P_D2K] * len(p_d)
        p_vtok = [ProbabilisticInference.P_V2K] * len(p_v)

        p_ktox = [p_ktom, p_ktor, p_ktos, p_ktod, p_ktov]
        p_xtok = [p_mtok, p_rtok, p_stok, p_dtok, p_vtok]
        p_implication = [p_ktox, p_xtok]
        
        return p_implication

    # output: p_ktox, p_xtok (x: m/r/s/d/v)
    def compute_p_implication(self, p_lists, size_list):
        p_m, p_r, p_s, p_d, p_v = p_lists

        p_ktom = [ProbabilisticInference.P_K2M] * len(p_m)
        p_ktor = [ProbabilisticInference.P_K2R] * len(p_r)
        p_ktos = [ProbabilisticInference.P_K2S] * len(p_s)
        p_ktod = [ProbabilisticInference.P_K2D] * len(p_d)
        p_ktov = [ProbabilisticInference.P_K2V] * len(p_v)


        p_mtok = [ProbabilisticInference.P_M2K] * len(p_m)
        p_rtok = [ProbabilisticInference.P_R2K] * len(p_r)
        p_stok = [ProbabilisticInference.P_S2K] * len(p_s)
        p_dtok = [ProbabilisticInference.P_D2K] * len(p_d)
        p_vtok = [ProbabilisticInference.P_V2K] * len(p_v)

        p_ktox = [p_ktom, p_ktor, p_ktos, p_ktod, p_ktov]
        p_xtok = [p_mtok, p_rtok, p_stok, p_dtok, p_vtok]
        p_implication = [p_ktox, p_xtok]

        return p_implication

    #### Normalization and Standardization
    def normalize_p_observation(self, p_observation):
        logging.debug("\n[++++] Normalize P_lists")

        observation_id = [0, 1, 2, 3] # 0: m, 1: r, 2: s, 3: d, 4: v
        for test_id in observation_id:
            p_list_total = list()
            for fid in p_observation:
                p_list_total += p_observation[fid][test_id]

            # remove -1
            p_list_total = [p for p in p_list_total if p >= 0]
            if len(p_list_total) == 0:
                continue

            # TODO: compute the balance value automatically
            # TODO: compute the boundary value automatically
            if test_id in [0]: # ms
                #if len(p_list_total) > 1:
                #    p_list_total = self.standardize(p_list_total)
                #p_list_total = self.normalize_max_min(p_list_total)

                p_list_total_min = np.min(p_list_total)
                p_list_total_max = np.max(p_list_total)
                if p_list_total_min != p_list_total_max:
                    p_list_total = self.normalize_range(p_list_total, p_list_total_min, p_list_total_max, 0.2, 0.80) #[0.1, 0.95]
                else:
                    p_balance = MyFactorGraph.compute_fg_threshold(ProbabilisticInference.P_K2M, ProbabilisticInference.P_M2K)
                    p_list_total = [p_balance for p in p_list_total]
                    #p_list_total = [0.5 for p in p_list_total]
            elif test_id in [1]: # rc
                p_list_total_min = np.min(p_list_total)
                p_list_total_max = np.max(p_list_total)
                if p_list_total_min != p_list_total_max:
                    #p_list_total = self.normalize_range(p_list_total, p_list_total_min, p_list_total_max, 0.2, 0.8)
                    p_list_total = self.normalize_range(p_list_total, 0, 1, 0.2, 0.8)
                else:
                    p_balance = MyFactorGraph.compute_fg_threshold(ProbabilisticInference.P_K2R, ProbabilisticInference.P_R2K)
                    p_list_total = [p_balance for p in p_list_total]
                    #p_list_total = [0.5 for p in p_list_total]
            elif test_id in [2]: # structure
                #if len(p_list_total) > 1:
                #    p_list_total = self.standardize(p_list_total)

                p_list_total_min = np.min(p_list_total)
                p_list_total_max = np.max(p_list_total)
                if p_list_total_min != p_list_total_max:
                    #p_list_total = self.normalize_range(p_list_total, p_list_total_min, p_list_total_max, 0.2, 0.8)
                    p_list_total = self.normalize_range(p_list_total, 0, 1, 0.2, 0.8)
                else:
                    p_balance = MyFactorGraph.compute_fg_threshold(ProbabilisticInference.P_K2S, ProbabilisticInference.P_S2K)
                    p_list_total = [p_balance for p in p_list_total]
                    #p_list_total = [0.5 for p in p_list_total]
            elif test_id in [3]: # d
                p_list_total_min = np.min(p_list_total)
                p_list_total_max = np.max(p_list_total)
                if p_list_total_min != p_list_total_max:
                    #p_list_total = self.normalize_range(p_list_total, p_list_total_min, p_list_total_max, 0.1, 0.75)
                    p_list_total = self.normalize_range(p_list_total, 0, 1, 0.1, 0.75)
                else:
                    p_list_total = [0.95 for p in p_list_total]
            # print(p_list_total)

            # write back to p_observation (with -1)
            count = 0
            for fid in p_observation:
                for i,p in enumerate(p_observation[fid][test_id]):
                    if p >= 0:
                        p_observation[fid][test_id][i] = p_list_total[count]
                        count += 1
                    #else:
                    #    p_observation[fid][test_id][i] = -1
                        '''
                        # TODO: for rc, replace 01
                        if test_id == 1:
                            p_observation[fid][test_id][i] = -1
                        else:
                            p_observation[fid][test_id][i] = 0.7272 #-1
                        '''
            '''
                p_list_len = len(p_observation[fid][test_id])
                p_observation[fid][test_id] = p_list_total[count:count+P_list_len]
                count += p_list_len
            #print("total: {}, count: {}".format(len(p_list_total), count))
            '''

        return p_observation

    def normalize_max_min(self, p_list):
        # Min-Max Normalization
        """#method 1: use numpy
        #p_list_n = (p_list - np.min(p_list)) / (np.max(p_list) - np.min(p_list))
        #print(p_list_n)
        """
        #method 2: use sklearn.preprocessing.minmax_scale()
        p_list_n = preprocessing.minmax_scale(p_list)

        """#method 3:
        '''
        x = np.array(p_list)
        x = x.reshape(-1,1)
        minmax_scaler = preprocessing.MinMaxScaler()
        minmax_scaler.fit(x)
        p_list_n = minmax_scaler.transform(x)
        print(p_list_n)
        """
        # print(p_list_n)

        return p_list_n

    #range1: original; range2: target
    def normalize_range(self, p_list, min1, max1, min2, max2):
        p_list = [min2 + (p - min1)*(max2 - min2)/(max1 - min1) for p in p_list]
        
        return p_list

    # standardization
    def standardize(self, p_list):
        # zero-score
        
        """ method 1: use numpy
        #p_list_s = (p_list - np.mean(p_list)) / np.std(p_list)
        """

        # method 2: use sklearn.preprocessing.scale()
        p_list_s = preprocessing.scale(p_list)

        """method 3: use sklearn.preprocessing.StandardScaler()
        x = np.array(p_list)
        x = x.reshape(-1,1)
        std_scaler = preprocessing.StandardScaler()
        scaler.fit(x)
        p_list_s = scaler.transform(x)
        #or scaler.fit_transform(x)
        """

        #print(p_list_s)

        return p_list_s

    def update_invalid_p(self, p_observation):
        logging.debug("[++++] Update invalid p")
        for fid, p_lists in p_observation.items():
            # test_id: 0: m, 1: r, 2: s, 3: d, 4: v
            
            # TODO: only need to check ms. others could not be invalid
            for test_id in [0]:
                p_balance = MyFactorGraph.compute_fg_threshold(ProbabilisticInference.P_K2M, ProbabilisticInference.P_M2K)
                for i, p in enumerate(p_lists[test_id]):
                    if p < 0: 
                        p_lists[test_id][i] = p_balance if p < -1.5 else 0.4 #0.7272


            # for r, remove -1 (the messages that have no request/response)
            # also update the num of p in p_implication
            for test_id in [1]:
                #i_filter = [i for i in range(len(p_lists[test_id])) if p_lists[test_id][i] > 0]
                i_filter = [i for i in range(len(p_lists[test_id])) if p_lists[test_id][i] >0 and self.pairs_size[fid][i] > 1]
                p_r = [p_lists[test_id][i] for i in i_filter]
                q_ktox_list_weighted_new = [self.p_implication[fid][0][test_id][i] for i in i_filter]
                q_xtok_list_weighted_new = [self.p_implication[fid][1][test_id][i] for i in i_filter]

                p_observation[fid][test_id] = p_r
                #self.p_implication[fid][0][test_id] = q_ktov_list_const_new
                #self.p_implication[fid][1][test_id] = q_vtok_list_const_new
                self.p_implication[fid][0][test_id] = q_ktox_list_weighted_new
                self.p_implication[fid][1][test_id] = q_xtok_list_weighted_new

            # TODO: no need. could not be invalid
            for test_id in [2, 3]:
                for i, p in enumerate(p_lists[test_id]):
                    if p < 0:
                        # TODO: compute the balance value automatically
                        p_lists[test_id][i] = 0.4 #0.7272

            # TODO
            for test_id in [4]:
                for i,p in enumerate(p_lists[test_id]):
                    if p < 0:
                        p_balance = MyFactorGraph.compute_fg_threshold(ProbabilisticInference.P_K2V, ProbabilisticInference.P_V2K)
                        p_lists[test_id][i] = p_balance - 0.45 #0.2
                    else:
                        p_lists[test_id][i] = 0.95 # TODO: remove it// 0.95

        return p_observation

    # TODO: add algorithms to infer the fid from fg results
    def get_fid_inferred(self, fg_result, max_num=1, precision=0.01):
        result = dict()
        for fid in fg_result:
            result[fid] = fg_result[fid][0] # only use the first test
        result_sorted = sorted(result.items(), key=lambda x:x[1], reverse=True)
        fid_inferred = [result_sorted[0][0]]
        for i in range(1, len(result_sorted)):
            if result_sorted[i][1] - result_sorted[0][1]< precision:
                fid_inferred.append(result_sorted[i][0])
        fid_inferred = [int(fid.split("-")[0]) for fid in fid_inferred[:max_num]]
        #print(fid_inferred)

        return fid_inferred