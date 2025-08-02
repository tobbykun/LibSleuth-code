import collections
import math
import multiprocessing
import os
from concurrent import futures
from queue import PriorityQueue
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import time
from collections import Counter


def initial_filter(waitlinglist, candidates, basics_tpl, basics_apk, fuzzy_sig_mappings_v1_apk,
                   fuzzy_sig_mappings_v2_apk):
    candidates_s = set(candidates)
    new_candidates = {}
    notes = {}
    for idx in waitlinglist:
        basic_tpl = basics_tpl[idx]
        if basic_tpl[0]:  # sc is std
            fuzzy_sig = basic_tpl[1]
            if fuzzy_sig in notes and notes[fuzzy_sig]:
                new_candidates[idx] = notes[fuzzy_sig]
            else:
                if fuzzy_sig in fuzzy_sig_mappings_v1_apk:
                    # candidates_t = candidates_s.intersection(fuzzy_sig_mappings_v1_apk[fuzzy_sig])
                    candidates_t = candidates_s & fuzzy_sig_mappings_v1_apk[fuzzy_sig]
                    new_candidates[idx] = candidates_t
                    notes[fuzzy_sig] = candidates_t
                else:
                    notes[fuzzy_sig] = None
        else:
            fuzzy_sig = basic_tpl[2]
            if fuzzy_sig in notes and notes[fuzzy_sig]:
                new_candidates[idx] = notes[fuzzy_sig]
            else:
                if fuzzy_sig in fuzzy_sig_mappings_v2_apk:
                    # candidates_t = candidates_s.intersection(fuzzy_sig_mappings_v2_apk[fuzzy_sig])
                    candidates_t = candidates_s & fuzzy_sig_mappings_v2_apk[fuzzy_sig]
                    new_candidates[idx] = candidates_t
                    notes[fuzzy_sig] = candidates_t
                else:
                    notes[fuzzy_sig] = None
    return new_candidates


def corse_filter(candidates, args_tpl, args_apk, strings_tpl, strings_apk, fields_tpl, fields_apk, apis_tpl, apis_apk,
                 id2method_tpl, id2method_apk, id2construct_tpl):
    filtered_candidates = {}
    all_tasks = [(element, candidates_list, args_tpl[element], strings_tpl[element], fields_tpl[element],
                  apis_tpl[element], id2construct_tpl[element]) for element, candidates_list in candidates.items()]

    if len(all_tasks) > 500:
        num_threads = 2
        half_id = len(all_tasks) // 2
        batches = [all_tasks[:half_id], all_tasks[half_id:]]

        with ThreadPoolExecutor(num_threads) as executor:
            futures = {executor.submit(compare_corse, batch, args_apk, strings_apk, fields_apk, apis_apk): batch for
                       batch in
                       batches}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    for element, result in results.items():
                        if result:
                            filtered_candidates[element] = result
                except Exception as e:
                    print(f"Error processing batch: error: {e}")
    else:
        results = compare_corse(all_tasks, args_apk, strings_apk, fields_apk, apis_apk)
        for element, result in results.items():
            if result:
                filtered_candidates[element] = result
    return filtered_candidates


def compare_corse(batch, args_apk, strings_apk, fields_apk, apis_apk):
    batch_results = {}
    for element, candidates, args_tpl, strings_tpl, fields_tpl, apis_tpl, id2construct_tpl in batch:

        arg_slices_tpl, arg_slices_totol_len_tpl, arg_slices_totol_set_tpl = args_tpl
        strs_len_tpl, strs_xrefs_tpl = strings_tpl
        fds_tpl, fnum_tpl = fields_tpl
        is_construct = id2construct_tpl
        as_tpl, as_num_tpl = apis_tpl
        suc_list = []

        for idy in candidates:

            api_score = 0
            api_threhold = 0.5
            if as_num_tpl:

                as_apk, as_num_apk = apis_apk[idy]

                if as_num_tpl * 0.8 > as_num_apk:
                    continue

                v = set()
                for i in as_tpl:

                    ori_a_sig_tpl, nom_a_sig_tpl, nom_a_sig_noac_tpl, a_sc_tpl, a_xrefs_tpl, a_calltype_tpl = i
                    a_sc_name_tpl, a_sc_num_tpl = a_sc_tpl

                    la = len(a_xrefs_tpl)

                    best_match = None

                    for idt, j in enumerate(as_apk):
                        if idt in v:
                            continue
                        if ori_a_sig_tpl == j[0]:
                            v.add(idt)
                            best_match = idt
                            api_score += 1
                            if la:
                                api_score += len(a_xrefs_tpl & j[4]) / la
                            else:
                                api_score += 1
                    if best_match is not None:
                        continue

                    max_match = -1
                    match_xref_len = -1
                    for idt, j in enumerate(as_apk):
                        if idt in v:
                            continue

                        call_type_f = True
                        a_calltype_apk = j[5]
                        if a_calltype_apk and a_calltype_tpl:
                            if a_calltype_apk != a_calltype_tpl:
                                call_type_f = False

                        if (nom_a_sig_tpl == j[1] or nom_a_sig_noac_tpl == j[2]) and call_type_f:

                            a_sc_name_apk, a_sc_num_apk = j[3]

                            if a_sc_name_apk and a_sc_name_tpl and a_sc_name_tpl != a_sc_name_apk:
                                continue
                            if a_sc_num_apk < a_sc_num_tpl:
                                continue

                            a_xrefs_apk = j[4]
                            l_intersection_t = len(a_xrefs_tpl & a_xrefs_apk)
                            if l_intersection_t > max_match:
                                max_match = l_intersection_t
                                best_match = idt
                                match_xref_len = len(a_xrefs_apk)
                            elif l_intersection_t == max_match:
                                xref_len = len(a_xrefs_apk)
                                if match_xref_len > xref_len:
                                    max_match = l_intersection_t
                                    best_match = idt
                                    match_xref_len = xref_len
                    if best_match is not None:
                        v.add(best_match)
                        api_score += 1 + (max_match / la if la else 1)

                if api_score < 2 * as_num_tpl * api_threhold:
                    continue


            f_score = 0
            f_threhold = 0.5
            if fnum_tpl:

                fds_apk, fnum_apk = fields_apk[idy]

                if not is_construct:
                    if fnum_tpl * 0.8 > fnum_apk:
                        continue

                v = set()
                for i in fds_tpl:

                    ori_f_sig_tpl, nom_f_sig_tpl, fsc_tpl, fd_xref_tpl = i

                    fsc_name_tpl, fsc_num_tpl = fsc_tpl

                    lf = len(fd_xref_tpl)

                    best_match = None
                    for idt, j in enumerate(fds_apk):
                        if idt in v:
                            continue
                        if ori_f_sig_tpl == j[0]:
                            v.add(idt)
                            best_match = idt
                            f_score += 1
                            if lf:
                                f_score += len(fd_xref_tpl & j[3]) / lf
                            else:
                                f_score += 1
                    if best_match is not None:
                        continue

                    max_match = -1
                    match_xref_len = -1
                    for idt, j in enumerate(fds_apk):
                        if idt in v:
                            continue
                        if nom_f_sig_tpl == j[1]:

                            fsc_name_apk, fsc_num_apk = j[2]

                            if fsc_name_apk and fsc_name_tpl and fsc_name_tpl != fsc_name_apk:
                                continue
                            if fsc_num_apk < fsc_num_tpl:
                                continue

                            fd_xref_apk = j[3]
                            l_intersection_t = len(fd_xref_tpl & fd_xref_apk)
                            if l_intersection_t > max_match:
                                max_match = l_intersection_t
                                best_match = idt
                                match_xref_len = len(fd_xref_apk)
                            elif l_intersection_t == max_match:
                                xref_len = len(fd_xref_apk)
                                if match_xref_len > xref_len:
                                    max_match = l_intersection_t
                                    best_match = idt
                                    match_xref_len = xref_len
                    if best_match is not None:
                        v.add(best_match)
                        f_score += 1 + (max_match / lf if lf else 1)

                if f_score < 2 * fnum_tpl * f_threhold:
                    continue

            if strs_len_tpl:

                strs_len_apk, strs_xrefs_apk = strings_apk[idy]

                if strs_len_tpl > strs_len_apk:
                    continue

                if strs_xrefs_tpl:
                    flag = False
                    for x in strs_xrefs_tpl:
                        if x in strs_xrefs_apk:
                            flag = True
                            break
                    if not flag:
                        continue
            arg_threhold = 0.2
            scores_arg = 0
            if arg_slices_tpl:

                arg_slices_apk, arg_slices_totol_len_apk, arg_slices_totol_set_apk = args_apk[idy]
                l_intersection_totol = len(arg_slices_totol_set_tpl & arg_slices_totol_set_apk)
                if l_intersection_totol < 0.2 * len(arg_slices_totol_set_tpl):
                    continue

                for i, a in enumerate(arg_slices_tpl):
                    scores_arg += len(a & arg_slices_apk[i])

                if scores_arg < arg_slices_totol_len_tpl * arg_threhold:
                    continue

            suc_list.append(idy)
        if suc_list:
            batch_results[element] = suc_list
    return batch_results


distance_note = {}

def bbs_compare(bbhashs_tpl, bbhashs_3gram_tpl, bbhashs_apk, bbhashs_3gram_apk):
    bb_ratio = 0.6
    b2b = {}
    bbnames_tpl = bbhashs_tpl.keys()
    bbnames_apk = list(bbhashs_apk.keys())
    #  加权sim
    sim_score = 0
    totol_len = 0
    potentials = []

    bbnames_tpl = sorted(bbnames_tpl, key=lambda item: bbhashs_tpl[item][1], reverse=True)

    for bbname_tpl in bbnames_tpl:

        best_match = None
        best_sim = 0
        best_len = 0
        best_type_is1 = None

        bb_ops_tpl, len_bb_tpl = bbhashs_tpl[bbname_tpl]

        totol_len += len_bb_tpl
        for bbname_apk in bbnames_apk:

            bb_ops_apk, len_bb_apk = bbhashs_apk[bbname_apk]
            len_intersection = len(bb_ops_tpl & bb_ops_apk)

            sim_1gram_tpl = len_intersection / len_bb_tpl
            if sim_1gram_tpl > bb_ratio:
                sim_1gram_apk = len_intersection / len_bb_apk
                sim_1gram = sim_1gram_tpl + sim_1gram_apk
                bb_ops_tpl3, len_bb_tpl3 = bbhashs_3gram_tpl[bbname_tpl]
                bb_ops_apk3, len_bb_apk3 = bbhashs_3gram_apk[bbname_apk]
                len_intersection_3gram = len(bb_ops_tpl3 & bb_ops_apk3)
                sim_3gram_tpl = len_intersection_3gram / len_bb_tpl3
                sim_3gram_apk = len_intersection_3gram / len_bb_apk3
                sim_3gram = sim_3gram_tpl + sim_3gram_apk

                if sim_1gram >= sim_3gram:
                    if sim_1gram > best_sim:
                        best_match = bbname_apk
                        best_sim = sim_1gram
                        best_len = sim_1gram_apk
                        best_type_is1 = True

                    elif sim_1gram == best_sim and sim_1gram_apk > best_len:
                        best_match = bbname_apk
                        best_len = sim_1gram_apk
                        best_type_is1 = True

                else:
                    if sim_3gram > best_sim:
                        best_match = bbname_apk
                        best_sim = sim_3gram
                        best_len = sim_3gram_apk
                        best_type_is1 = False

                    elif sim_3gram == best_sim and sim_3gram_apk > best_len:
                        best_match = bbname_apk
                        best_len = sim_3gram_apk
                        best_type_is1 = False


        if best_match:
            b2b[bbname_tpl] = best_match
            bbnames_apk.remove(best_match)
            sim_score += best_sim * len_bb_tpl
            if best_type_is1 and best_len < 0.5:
                potentials.append(best_match)
        else:
            for potential in potentials:
                bb_ops_apk, len_bb_apk = bbhashs_apk[potential]
                len_intersection = len(bb_ops_tpl & bb_ops_apk)

                sim_1gram_tpl = len_intersection / len_bb_tpl
                if sim_1gram_tpl > bb_ratio:
                    sim_1gram_apk = len_intersection / len_bb_apk
                    # sim_1gram = 0.5 * sim_1gram_tpl + 0.5 * sim_1gram_apk
                    sim_1gram = sim_1gram_tpl + sim_1gram_apk

                    if sim_1gram > best_sim:
                        best_match = potential
                        best_sim = sim_1gram
                        best_len = sim_1gram_apk
                    elif sim_1gram == best_sim and sim_1gram_apk > best_len:
                        best_match = potential
                        best_len = sim_1gram_apk
            if best_match:
                b2b[bbname_tpl] = best_match

    return b2b, sim_score / totol_len if totol_len else 0, totol_len


def find_rank(dictionary, key):
    items = sorted(list(set(dictionary.values())), reverse=True)
    target_value = dictionary[key]
    rank = 1
    for i, value in enumerate(items, start=1):
        if value == target_value:
            rank = i
            break
    return rank


def fine_filter(candidates, bbcfgs_tpl, bbcfgs_apk, id2method_tpl, id2method_apk, smalls_tpl):
    filtered_candidates = {}
    sim_notes = {}
    candidates = dict(sorted(candidates.items(), key=lambda item: len(item[1])))
    all_tasks = [(element, candidates_list, bbcfgs_tpl[element]) for element, candidates_list in candidates.items()]

    if len(all_tasks) > 500:
        num_threads = 2
        half_id = len(all_tasks) // 2
        batches = [all_tasks[:half_id], all_tasks[half_id:]]

        with ThreadPoolExecutor(num_threads) as executor:
            futures = {executor.submit(compare_fine, batch, bbcfgs_apk): batch for batch in
                       batches}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    cs, sims = results
                    sim_notes.update(sims)
                    for element, sucs in cs.items():
                        if sucs:
                            filtered_candidates[element] = sucs
                except Exception as e:
                    print(f"Error processing batch: error: {e}")
    else:
        cs, sims = compare_fine(all_tasks, bbcfgs_apk)
        sim_notes.update(sims)
        for element, sucs in cs.items():
            if sucs:
                filtered_candidates[element] = sucs
    return filtered_candidates, sim_notes


def compare_fine(batch, bbcfgs_apk):

    fine_ratio = 0.6
    new_candidates = {}
    sims_note = {}

    for idx, candidates, bbcfgs_tpl in batch:

        bbcfg_tpl = bbcfgs_tpl
        totol_ops_tpl = bbcfg_tpl[0]
        bbhashs_tpl = bbcfg_tpl[1]
        bbhashs_3gram_tpl = bbcfg_tpl[2]
        len_totol_ops_tpl = len(totol_ops_tpl)

        best_matchs = None
        m2sim = {}

        for idy in candidates:

            bbcfg_apk = bbcfgs_apk[idy]
            totol_ops_apk = bbcfg_apk[0]
            bbhashs_apk = bbcfg_apk[1]
            bbhashs_3gram_apk = bbcfg_apk[2]

            sim1 = len(totol_ops_tpl & totol_ops_apk) / len_totol_ops_tpl if len_totol_ops_tpl else 1
            if sim1 < 0.6:
                continue

            b2b, sim2, totol_len = bbs_compare(bbhashs_tpl, bbhashs_3gram_tpl, bbhashs_apk, bbhashs_3gram_apk)
            sim = 0.5 * sim1 + 0.5 * sim2

            if totol_len and sim < fine_ratio:
                continue
            else:
                if best_matchs is None:
                    best_matchs = []
                best_matchs.append(idy)
                m2sim[idy] = sim
        if best_matchs:
            sim_set = set()
            for mt in best_matchs:
                sim_ = m2sim[mt]
                sims_note[(idx, mt)] = sim_
                sim_set.add(sim_)
            top_k = 10
            if len(sim_set) > top_k:
                sim_set = list(sim_set)
                sim_set.sort(reverse=True)
                bias = sim_set[top_k - 1]
                best_matchs_t = []
                for mt in best_matchs:
                    if m2sim[mt] >= bias:
                        best_matchs_t.append(mt)
                best_matchs = best_matchs_t
            best_matchs = sorted(best_matchs, key=lambda x: len(bbcfgs_apk[x][0]))
            new_candidates[idx] = best_matchs
    return new_candidates, sims_note

def match_validate(candidates, sims_note, id2method_apk, id2method_tpl, smalls_tpl):
    sim_score = 0
    cls2m_apk = {}
    m2cls_apk = {}
    for i, j in enumerate(id2method_apk):
        cls = j[:j.find(":")]
        if cls not in cls2m_apk:
            cls2m_apk[cls] = []
        cls2m_apk[cls].append(i)
        m2cls_apk[i] = cls

    cls2m_tpl = {}
    m2cls_tpl = {}
    clss_tpl = set()
    for i, j in enumerate(id2method_tpl):
        if i in candidates:
            cls = j[:j.find(":")]
            if cls not in cls2m_tpl:
                cls2m_tpl[cls] = []
            cls2m_tpl[cls].append(i)
            m2cls_tpl[i] = cls
            clss_tpl.add(cls)
    clss_tpl = sorted(clss_tpl, key=lambda x: len(set(cls2m_tpl[x]) & smalls_tpl))

    v = set()
    candidates_t = {}

    is_abstract = -1 in smalls_tpl
    if is_abstract:
        package_dict = {}

    for cls in clss_tpl:
        clst = {}

        xs = {}
        ys = {}

        cls_sims = {}
        best_cls = None

        for m in cls2m_tpl[cls]:
            for j in candidates[m]:
                cls_t = m2cls_apk[j]
                if cls_t in v:
                    continue
                if cls_t not in clst:
                    clst[cls_t] = []
                    cls_sims[cls_t] = 0

                    xs[cls_t] = set()
                    ys[cls_t] = set()

                if m in xs[cls_t] or j in ys[cls_t]:
                    continue

                clst[cls_t].append((m, j))
                cls_sims[cls_t] += sims_note[(m, j)]

                xs[cls_t].add(m)
                ys[cls_t].add(j)

        if cls_sims:
            cls_sims = dict(sorted(cls_sims.items(), key=lambda item: item[1], reverse=True))
            best_sim = -1
            for cls_t, _sim in cls_sims.items():
                if _sim > best_sim:
                    best_sim = _sim
                    best_cls = cls_t
                elif _sim == best_sim:
                    if len(cls2m_apk[cls_t]) < len(cls2m_apk[best_cls]):
                        best_cls = cls_t
                    elif is_abstract and len(cls2m_apk[cls_t]) == len(cls2m_apk[best_cls]) and package_dict:
                        if max(package_dict, key=package_dict.get) in cls_t:
                            best_cls = cls_t
                else:
                    break
        r1 = 0.75
        r2 = 0.4
        if is_abstract:
            r1 = 1
            r2 = 1
        p = 0
        if p:
            if best_cls:
                len_bestclst = len(clst[best_cls])
                bestl = len(cls2m_apk[best_cls])
                clsl = len(cls2m_tpl[cls])
                print(cls)
                print(best_cls)
                print(clsl, cls2m_tpl[cls])
                print(bestl, cls2m_apk[best_cls])
                print(len_bestclst, clst[best_cls])
                print((len_bestclst >= math.floor(bestl * r1) and len_bestclst >= math.floor(r2 * clsl)) or (
                            len_bestclst >= math.floor(r1 * clsl) and len_bestclst >= math.floor(r2 * bestl)))
                print()
            else:
                print("no best", cls)
                print(len(cls2m_tpl[cls]), cls2m_tpl[cls])
                print()

        if best_cls:
            len_bestclst = len(clst[best_cls])
            bestl = len(cls2m_apk[best_cls])
            clsl = len(cls2m_tpl[cls])
            if (len_bestclst >= math.floor(bestl * r1) and len_bestclst >= math.floor(r2 * clsl)) or (
                    len_bestclst >= math.floor(r1 * clsl) and len_bestclst >= math.floor(r2 * bestl)):
                v.add(best_cls)
                if is_abstract:
                    package_name = best_cls[:best_cls.rfind("/")]
                    if package_name not in package_dict:
                        package_dict[package_name] = 0
                    package_dict[package_name] += 1
                for x, y in clst[best_cls]:
                    candidates_t[x] = y
                    if x not in smalls_tpl:
                        sim_score += sims_note[(x, y)]
    if is_abstract and package_dict:
        max_key = max(package_dict, key=package_dict.get)
        candidates_tmp = {}
        for x, y in candidates_t.items():
            if max_key in id2method_apk[y]:
                candidates_tmp[x] = y
            else:
                sim_score -= sims_note[(x, y)]
        candidates_t = candidates_tmp

    return candidates_t, sim_score


def cg_match(matches, cg_tpl, cg_apk, smalls_tpl, smalls_apk, id2method_apk, method2id_tpl, sigs, basics_apk):
    q1 = []
    q2 = []
    nom_cnt = 0
    for i, j in matches.items():
        if i not in smalls_tpl:
            nom_cnt += 1
            q1.append(j)
            q2.append(i)
    cg_sim = 0
    cg = set()
    smalls = set()
    while True:
        if not q1:
            break
        node = q1.pop()
        if node in cg or node in smalls:
            continue

        is_small = node in smalls_apk
        if is_small:
            smalls.add(node)
        hasno_nexts = (node in cg_apk and not cg_apk[node]) or node not in cg_apk
        if is_small and hasno_nexts:
            continue
        if not is_small:
            cg.add(node)
            if node in matches.values():
                cg_sim += 1
        if not hasno_nexts:
            for x in cg_apk[node]:
                if x not in cg:
                    xx = basics_apk[x]
                    if xx[2] in sigs or xx[1] in sigs:
                        q1.append(x)
    cg_size1 = len(cg)
    cg_score_apk = cg_sim / cg_size1 if cg_size1 else 0

    cg_sim = 0
    cg = set()
    smalls = set()
    while True:
        if not q2:
            break
        node = q2.pop()
        if node in cg or node in smalls:
            continue
        is_small = node in smalls_tpl
        if is_small:
            smalls.add(node)
        hasno_nexts = (node in cg_tpl and not cg_tpl[node]) or node not in cg_tpl
        if is_small and hasno_nexts:
            continue
        if not is_small:
            cg.add(node)
            if node in matches:
                cg_sim += 1
        if not hasno_nexts:
            q2.extend([x for x in cg_tpl[node] if x not in cg])
    cg_size2 = len(cg)
    cg_score_tpl = cg_sim / cg_size2 if cg_size2 else 0


    return cg_score_apk, cg_score_tpl, 0 if -1 in smalls_tpl else nom_cnt, cg_size1, cg_size2


def detect(args_apk, args_tpl):
    method_signatures_apk, method2id_apk, id2method_apk, id2construct_apk, features_apk, cg_apk, fuzzy_sig_mappings_v1_apk, fuzzy_sig_mappings_v2_apk, smalls_apk = args_apk
    method_signatures_tpl, method2id_tpl, id2method_tpl, id2construct_tpl, features_tpl, cg_tpl, fuzzy_sig_mappings_v1_tpl, fuzzy_sig_mappings_v2_tpl, smalls_tpl = args_tpl

    id_len_tpl = len(id2method_tpl)
    id_len_apk = len(id2method_apk)
    matches = {}

    matches_t = set()
    ms_matches = method_signatures_tpl & method_signatures_apk
    for m in ms_matches:
        matches[method2id_tpl[m]] = method2id_apk[m]
        matches_t.add(method2id_apk[m])

    waitlinglist = [x for x in range(id_len_tpl) if x not in matches]
    candidates = [x for x in range(id_len_apk) if x not in matches_t]

    candidates = initial_filter(waitlinglist, candidates, features_tpl["basics"], features_apk["basics"],
                                fuzzy_sig_mappings_v1_apk, fuzzy_sig_mappings_v2_apk)

    candidates = corse_filter(candidates, features_tpl["args"], features_apk["args"],
                              features_tpl["strings"], features_apk["strings"],
                              features_tpl["fields"], features_apk["fields"],
                              features_tpl["apis"], features_apk["apis"],
                              id2method_tpl, id2method_apk, id2construct_tpl)

    for i, j in matches.items():
        candidates[i] = [j]

    candidates, sims_note = fine_filter(candidates, features_tpl["bbcfgs"], features_apk["bbcfgs"], id2method_tpl,
                                        id2method_apk, smalls_tpl)

    matches, sim_score = match_validate(candidates, sims_note, id2method_apk, id2method_tpl, smalls_tpl)

    sigs = set()
    for _, s1, s2 in features_tpl["basics"]:
        sigs.add(s1)
        sigs.add(s2)
    cg_sim_apk, cg_sim_tpl, nomalnums_in_matches, cg_size1, cg_size2 = cg_match(matches, cg_tpl, cg_apk, smalls_tpl,
                                                                                smalls_apk, id2method_apk,
                                                                                method2id_tpl, sigs,
                                                                                features_apk["basics"])

    return matches, sim_score, cg_sim_apk, cg_sim_tpl, cg_size1, cg_size2, nomalnums_in_matches



