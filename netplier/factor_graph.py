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

from pgmpy.models import FactorGraph
from pgmpy.factors.discrete import DiscreteFactor
from pgmpy.inference import BeliefPropagation

class MyFactorGraph:

    def __init__(self, p_observation, p_implication):
        self.p_observation = p_observation
        self.p_implication = p_implication

    # Compute Pk
    # type_list: 0: k2x & x2k, 1: k2x, 2: x2k, -1: not test
    def compute_pk(self, type_list, fid):
        assert len(type_list) == 5, print("ComputePk Error: number of type_list should be 5")

        constraint_name = ['m', 'r', 's', 'd', 'v']
        '''
        m, r, s, d, v = type_list
        p_m, p_r, p_s, p_d, p_v = self.p_observation
        p_ktox, p_xtok = self.p_implication
        p_ktom, p_ktor, p_ktos, p_ktod, p_ktov = p_ktox
        p_mtok, p_rtok, p_stok, p_dtok, p_vtok = p_xtok
        '''
        fg = FactorGraph()
        fg.add_node('k')

        for i in range(len(type_list)):
            if type_list[i] == 0:
                fg = self.add_constraints_k2x_x2k(fg, self.p_observation[fid][i], self.p_implication[fid][0][i], self.p_implication[fid][1][i], constraint_name[i])
            elif type_list[i] == 1:
                fg = self.add_constraints_k2x(fg, self.p_observation[fid][i], self.p_implication[fid][0][i], constraint_name[i])
            elif type_list[i] == 2:
                fg = self.add_constraints_x2k(fg, self.p_observation[fid][i], self.p_implication[fid][1][i], constraint_name[i])
        '''
        if m == 0:
            fg = add_constraints_kv_vk(fg, p_m, p_ktom, p_mtok, 'm')
        elif m == 1:
            fg = add_constraints_kv(fg, p_m, p_mtok, 'm')
        elif m == 2:
            fg = add_constraints_vk(fg, p_m, p_mtok, 'm')

        if r == 0:
            fg = add_constraints_kv_vk(fg, p_r, p_ktor, p_rtok, 'r')
        elif r == 1:
            fg = add_constraints_kv(fg, p_r, p_ktor, 'r')
        elif r == 2:
            fg = add_constraints_vk(fg, p_r, p_rtok, 'r')

        if s == 0:
            fg = add_constraints_kv_vk(fg, p_s, p_ktos, p_stok, 's')
        elif s == 1:
            fg = add_constraints_kv(fg, p_s, p_ktos, 's')
        elif s == 2:
            fg = add_constraints_vk(fg, p_s, p_stok, 's')

        if d == 0:
            fg = add_constraints_kv_vk(fg, p_d, p_ktod, p_dtok, 'd')
        elif d == 1:
            fg = add_constraints_kv(fg, p_d, p_ktod, 'd')
        elif d == 2:
            fg = add_constraints_vk(fg, p_d, p_dtok, 'd')

        if v == 0:
            fg = add_constraints_kv_vk(fg, p_v, p_ktov, p_vtok, 'v')
        elif v == 1:
            fg = add_constraints_kv(fg, p_v, p_ktov, 'v')
        elif v == 2:
            fg = add_constraints_vk(fg, p_v, p_vtok, 'v')
        '''

        bp = BeliefPropagation(fg)

        #result = bp.query(variables=['k'])['k']
        #result = bp.query(variables=['k'], joint=False)['k']
        result = bp.query(variables=['k'])
        result.normalize()
        #print(result)

        return result.values[1]

    # Addd Constraints
    # k -> x
    def add_constraints_k2x(self, fg, p_x, p_ktox, x_name):
        for i in range(len(p_x)):
            p1 = p_x[i]
            p2 = p_ktox[i]
            x = '%s%d' % (x_name, i)
            fg.add_node(x)
            phi1 = DiscreteFactor([x], [2], [1 - p1, p1])
            phi2 = DiscreteFactor(['k', x], [2, 2], [p2, p2, 1 - p2, p2])
            fg.add_factors(phi1, phi2)
            fg.add_edges_from([(x, phi1), (x, phi2), ('k', phi2)])
        return fg

    # x -> k
    def add_constraints_x2k(self, fg, p_x, p_xtok, x_name):
        for i in range(len(p_x)):
            p1 = p_x[i]
            p3 = p_xtok[i]
            x = '%s%d' % (x_name, i)
            fg.add_node(x)
            phi1 = DiscreteFactor([x], [2], [1 - p1, p1])
            phi3 = DiscreteFactor(['k', x], [2, 2], [p3, 1 - p3, p3, p3])
            fg.add_factors(phi1, phi3)
            fg.add_edges_from([(x, phi1), (x, phi3), ('k', phi3)])
        return fg

    # k -> x & x -> k
    def add_constraints_k2x_x2k(self, fg, p_x, p_ktox, p_xtok, x_name):
        for i in range(len(p_x)):
            p1 = p_x[i]
            p2 = p_ktox[i]
            p3 = p_xtok[i]
            x = '%s%d' % (x_name, i)
            fg.add_node(x)
            phi1 = DiscreteFactor([x], [2], [1 - p1, p1])
            phi2 = DiscreteFactor(['k', x], [2, 2], [p2, p2, 1 - p2, p2])
            phi3 = DiscreteFactor(['k', x], [2, 2], [p3, 1 - p3, p3, p3])
            fg.add_factors(phi1, phi2, phi3)
            fg.add_edges_from([(x, phi1), (x, phi2), ('k', phi2), (x, phi3), ('k', phi3)])
        return fg

    # Compute the balance value for differnt p_kv/p_vk
    @staticmethod
    def compute_fg_threshold(p_kv, p_vk):
        p_t = (2 * p_kv * p_vk - p_vk) / (4 * p_kv * p_vk - p_kv - p_vk)
        return p_t
