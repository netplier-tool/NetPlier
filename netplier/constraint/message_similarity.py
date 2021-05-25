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

import logging

class MessageSimilarity:

    def __init__(self, messages):
        self.messages = messages
        self.similarity_matrix = list()

    def compute_similarity_matrix(self):
        print("[++++] Compute matrix of similarity scores")
        scoreslist = list()
        for i in range(len(self.messages)):
            initial_scores_list = [-1 for i in range(len(self.messages))]
            scoreslist.append(initial_scores_list)

        # use the MSA result is quick, but less accurate
        for i in range(len(self.messages)):
            for j in range(i, len(self.messages)):
                if j == i:
                    score = 100.0
                    scoreslist[i][j] = score
                else:
                    score = self.compute_similarity_scores_by_alignment(self.messages[i].data, self.messages[j].data)
                    scoreslist[i][j] = score
                    scoreslist[j][i] = score 
        
        self.similarity_matrix = scoreslist
        
    def compute_similarity_scores_by_alignment(self, msgdata1, msgdata2):
        if len(msgdata1) != len(msgdata2):
            logging.error("The two compared messages don't have same length.")
            return -2
        # TODO: use NW to get more accurate score
        result = [1 for i in range(len(msgdata1)) if msgdata1[i]==msgdata2[i]]
        score = sum(result)/len(msgdata1)
        return score

    # compute p_m
    def compute_constraint_message_similarity(self, symbols):
        logging.debug("[+] Compute observation probabilities of message similarity")
        sn_list = [str(s.name) for s in symbols.values()]

        inner_inter_scores = self.compute_inner_inter_scores(symbols)
        symbol_m = self.compute_similarity_constraints(inner_inter_scores)

        p_m = list()
        for s in sn_list:
            if symbol_m[s] > 0: #!= -1:
                p_m.append(symbol_m[s])
                #p_m.append(dict_scores_test[s] * dict_sn_msgnum_test[s] / msgnum_total_test)
            elif len(sn_list) == 1: # no inter scores 
                p_m.append(-2)
            else: # no inner scores
                p_m.append(-1) # TODO: may not need it

        return p_m

    # compute Inner/Inter scores
    # inner_inter_scores: {symbol_name: [num of msgs, inner scores, inter scores]}
    def compute_inner_inter_scores(self, symbols):
        logging.debug("[+] Compute Inner/Inter Scores")

        dict_mid_i = dict()
        for i,message in enumerate(self.messages):
            dict_mid_i[message.id] = i

        inner_inter_scores = dict()

        for s in symbols.values():
            sn = str(s.name)

            #0: message num
            #1: inner scores list
            #2: inter scores list
            inner_inter_scores[sn] = list()
            # TODO: message num is not used
            
            mi_list = [dict_mid_i[message.id] for message in s.messages]
            inner_inter_scores[sn].append(mi_list) #0: message num
            
            inner_score_list, inter_score_list = list(), list()
            for i in range(len(mi_list)):
                for j in range(i + 1, len(mi_list)):
                    inner_score_list.append(self.similarity_matrix[mi_list[i]][mi_list[j]])
            for i in mi_list:
                for j in range(len(self.messages)):
                    if j not in mi_list:
                        inter_score_list.append(self.similarity_matrix[i][j])
            
            inner_inter_scores[sn].append(sorted(inner_score_list, reverse=True))
            inner_inter_scores[sn].append(sorted(inter_score_list, reverse=True))
            
        return inner_inter_scores

    # compute similarity constraints of each cluster
    # symbol_m: {symbol_name: list of p_m}
    def compute_similarity_constraints(self, inner_inter_scores):
        symbol_m = {}
        for key,values in inner_inter_scores.items():
            symbol_m[key] = 1 - self.compute_eer(values[1], values[2])
        return symbol_m

    # compute eer
    def compute_eer(self, inner_scores, inter_scores):
        #tfnmr = stat_scores(inner_score_list)
        #tfmr = stat_scores(inter_score_list)
        if len(inner_scores) == 0 or len(inter_scores) == 0:
            return 1 # 0.05

        t_fnmr_list = self.compute_fnmrs(inner_scores)
        t_fmr_list = self.compute_fmrs(inter_scores)

        tfnmrlist = [x[0] for x in t_fnmr_list]
        fnmrlist = [x[1] for x in t_fnmr_list]
        tfmrlist = [x[0] for x in t_fmr_list]
        fmrlist = [x[1] for x in t_fmr_list]

        ifnmr = 0
        ifmr = 0
        fnmr1 = 0.0
        fnmr2 = 0.0
        fmr1 = 1.0
        fmr2 = 1.0
        tfnmr1 = 0.0
        tfnmr2 = 0.0
        tfmr1 = 0.0
        tfmr2 = 0.0
        while True:
            if fmr2 <= fnmr2:
                break
            if  tfmr2 < tfnmr2:
                ifmr += 1
                tfmr1 = tfmr2
                fmr1 = fmr2
                tfmr2 = tfmrlist[ifmr]
                fmr2 = fmrlist[ifmr]
            elif tfmr2 > tfnmr2:
                ifnmr += 1
                tfnmr1 = tfnmr2
                fnmr1 = fnmr2
                tfnmr2 = tfnmrlist[ifnmr]
                fnmr2 = fnmrlist[ifnmr]
            else:
                ifmr += 1
                tfmr1 = tfmr2
                fmr1 = fmr2
                tfmr2 = tfmrlist[ifmr]
                fmr2 = fmrlist[ifmr]

                ifnmr += 1
                tfnmr1 = tfnmr2
                fnmr1 = fnmr2
                tfnmr2 = tfnmrlist[ifnmr]
                fnmr2 = fnmrlist[ifnmr]
        #print("FMR: t1=%s,fmr=%s; t2=%s,fmr=%s" % (tfmr1,fmr1,tfmr2,fmr2))
        #print("FNMR: t1=%s,fnmr=%s; t2=%s,fnmr=%s" % (tfnmr1,fnmr1,tfnmr2,fnmr2))
        
        if fmr2 == fnmr2:
            eer = fmr2
            t = min(tfmr2,tfnmr2)
            #print("EER: %s, t: %s" %(eer,t))
        else:
            l = max(fnmr1,fmr2)
            h = min(fnmr2,fmr1)
            eer = (l+h)/2
            t1 = max(tfmr1,tfnmr1)
            t2 = min(tfmr2,tfnmr2)
            t = (t1+t2)/2
            #print("l=%s, h=%s; t1=%s, t2=%s" %(l,h,t1,t2))
            #print("EER: %s, t: %s" %(eer,t))
        return eer

    # ouput: list of [t, fnmr]
    # when computing fnmr, only consider scores > t (not >= t)
    def compute_fnmrs(self, scores):
        scores.sort()
        numGM = len(scores)
        t_fnmr_list = list()

        # first one: [0, 0]
        result = [0, 0]
        t_fnmr_list.append(result)
        
        t = -1
        for i in range(0, numGM):
            if scores[i] > t :
                if (t != -1):
                    fnmr = i / numGM #i-1+1 / numGM
                    result = [t, fnmr]
                    t_fnmr_list.append(result)
                t = scores[i]
        result = [scores[i], 1]
        t_fnmr_list.append(result)

        # last one: [1, 1]
        result = [1, 1]
        t_fnmr_list.append(result)

        return t_fnmr_list

    # output: list of [t, fmr]
    # when computing fmr, only consider scores > t
    def compute_fmrs(self, scores):
        scores.sort()
        numIM = len(scores)
        t_fmr_list = list()

        # first one: [0, 1]
        result = [0, 1]
        t_fmr_list.append(result)
        
        t = -1
        for i in range(0, numIM):
            if scores[i] > t :
                if (t != -1):
                    fmr = (numIM - i) / numIM 
                    result = [t, fmr]
                    t_fmr_list.append(result)
                t = scores[i]
        result = [scores[i], 0]
        t_fmr_list.append(result)

        # last one: [1, 0]
        result = [1, 0]
        t_fmr_list.append(result)

        return t_fmr_list
