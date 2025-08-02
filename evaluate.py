import os
import pickle
import time
from concurrent import futures
from detect import detect
from collections import Counter

# AS1
apk_cg_sim_ratio = 0.6
nom_sim_ratio = 0.25
# AS2
apk_cg_sim_ratio = 0.55
nom_sim_ratio = 0.25


def find_independent_sets(sets, threshold):
    all_elements = []
    for s in sets.values():
        all_elements.extend(s)
    element_count = Counter(all_elements)

    check_set = {}
    independent_sets = []
    chose_m = set()
    for k, v in sets.items():
        independent_elements = [x for x in v if element_count[x] == 1]
        independent_ratio = len(independent_elements) / len(v) if len(v) else 0
        if independent_ratio >= threshold:
            independent_sets.append(k)
            chose_m.update(sets[k])
        else:
            check_set[k] = independent_ratio
    check_set = sorted(check_set, key=lambda x: check_set[x], reverse=True)
    for k in check_set:
        v = sets[k]
        cd_num = 0
        for x in v:
            if x in chose_m:
                cd_num += 1
        cd_ratio = cd_num / len(v) if len(v) else 1
        if cd_ratio <= 1 - threshold:
            # print(3)
            independent_sets.append(k)
            chose_m.update(sets[k])
    return independent_sets


def findname(s):
    for i in range(len(s) - 1, -1, -1):
        if s[i].isdigit() and (i - 3 >= 0) and (s[i - 1] == '.' or s[i - 1] == '-') and (
                s[i - 2].isalpha() or s[i - 3].isalpha() or (
                s[i - 2].isdigit() and s[i - 3].isdigit() and s[i - 4] == 'v') or (
                        s[i - 2].isdigit() and i >= 7 and s[i - 7:i - 4] == "jsr")):
            return s[:i - 1], s[i:]
    return (s, 0)


def get_final_match(detect_res):
    detect_res = dict(sorted(detect_res.items(), key=lambda x: x[1][0], reverse=True))

    tpls = {}
    for x in detect_res:
        tpl_name = findname(x)[0]
        if tpl_name not in tpls:
            tpls[tpl_name] = set()
        tpls[tpl_name].add(x)
    final_match = {}
    for tpl, _tpls in tpls.items():
        best_match = []
        max_score = -1
        max_nom_sim = -1
        max_nomnum = -1
        max_allnum = -1
        max_all_sim = -1
        for x, y in detect_res.items():
            if x in _tpls:
                score = y[0]
                nom_sim = y[1]
                nomnum = y[2]
                all_sim = y[3]
                allnum = y[4]
                if score < 0.99 * max_score and abs(score - max_score) > 2:
                    break
                if nomnum > 0.99 * max_nomnum or abs(nomnum - max_nomnum) <= 2:
                    if nom_sim > 0.99 * max_nom_sim:
                        if allnum > max_allnum and max_all_sim <= 0.99 and allnum - max_allnum > 1:
                            max_nom_sim = nom_sim
                            max_score = score
                            max_nomnum = nomnum
                            max_allnum = allnum
                            max_all_sim = all_sim
                            best_match = [x]
                            continue
                        elif round(score, 4) == round(max_score, 4) and (
                                allnum >= 0.99 * max_allnum and max_allnum >= 0.99 * allnum):  # need all ==？
                            best_match.append(x)
                            continue
                        if nom_sim - max_nom_sim > 0.3 and all_sim - max_all_sim > 0.3:
                            best_match = [x]
                            continue
        final_match[best_match[0]] = best_match
    return final_match


def evaluate(apk_features, lib_features, gt_file, apks, out):
    global nom_sim_ratio
    global apk_cg_sim_ratio
    gt = {}
    with open(gt_file, "r") as f:
        for l in f.readlines():
            l = l.strip()
            t = l.split(":")
            gt[t[0]] = []
            for lib in t[1].split(","):
                if lib:
                    gt[t[0]].append(lib)

    f_a_t = 0
    d_t = 0
    f = open(f"./log-{out}.txt", "w")
    f.close()
    f = open(f"./ans-{out}.txt", "w")
    f.close()
    with open(f"./log-{out}.txt", "a") as f:
        f.write("get lib feature...")
    st = time.time()
    libs_f = {}
    for file in os.listdir(lib_features):
        with open(os.path.join(lib_features, file), 'rb') as f:
            libs_f[file[:-4]] = pickle.load(f)
    f_l_t = time.time() - st
    with open(f"./log-{out}.txt", "a") as f:
        f.write("features lib cost avg: " + str(round(f_l_t / len(libs_f), 4)) + "s\n")
        f.write("\napk...\n")
    cnt = 0
    apk_cnt = 0
    apk_len = 0
    totol_gt = 0
    totol_ans = 0
    correct = 0
    jds = 0
    zhs = 0

    for apk_file in os.listdir(apk_features):

        if apk_file[:-4] not in apks:
            continue

        apk_cnt += 1
        with open(f"./log-{out}.txt", "a") as f:
            f.write(apk_file + " :   ")
        print(apk_file, end='   ')
        st = time.time()
        with open(os.path.join(apk_features, apk_file), 'rb') as f:
            apk_f = pickle.load(f)
        tmp = time.time() - st
        with open(f"./log-{out}.txt", "a") as f:
            f.write(str(round(tmp, 4)) + "s\n")
        print(round(tmp, 4), "s")
        f_a_t += tmp
        apk_len += 1
        id2method_apk = apk_f[2]
        with open(f"./ans-{out}.txt", "a") as f:
            f.write(apk_file + "...   " + str(len(id2method_apk)) + "\n")
        print(apk_file, len(id2method_apk))
        detect_res = {}
        gts = set()
        t2m = {}

        collected_results = {}
        slows = set()
        sss = time.time()
        for tpl_, args_tpl in libs_f.items():
            if len(args_tpl[8]) >= 1000:
                slows.add(tpl_)
            else:
                collected_results[tpl_[:-4]] = detect(apk_f, args_tpl)
        slows = sorted(slows, key=lambda item: len(libs_f[item][8]), reverse=True)
        if slows:
            with futures.ProcessPoolExecutor(
                    max_workers=min(len(slows), 16)) as executor:
                tasks = {executor.submit(detect, apk_f, value): key for key, value in libs_f.items() if key in slows}
                for future in futures.as_completed(tasks):
                    key = tasks[future]
                    try:
                        result = future.result()
                        collected_results[key[:-4]] = result
                    except Exception as exc:
                        with open(f"./log-{out}.txt", "a") as f:
                            f.write(f'{key} generated an exception: {exc}\n')
                        print(f'{key} generated an exception: {exc}')
        dtime = time.time() - sss
        d_t += dtime

        with open(f"./log-{out}.txt", "a") as f:
            f.write(str(dtime) + '\n')

        for tpl_, result in collected_results.items():
            cnt += 1
            res, score, cg_sim_apk, cg_sim_tpl, cg_size_apk, cg_size_tpl, nomalnums_in_matches = result
            is_gt = False
            for x in gt:
                if x[:-4] in apk_file:
                    if tpl_ in gt[x]:
                        is_gt = True
                        gts.add(tpl_)
                        break
            id2method_tpl = libs_f[tpl_ + ".dex"][2]
            smalls_tpl = libs_f[tpl_ + ".dex"][8]

            matched_all_num = len(res)
            tpl_all_num = len(id2method_tpl)
            matched_all_sim = matched_all_num / tpl_all_num  # *
            is_abstract = -1 in smalls_tpl

            _apk_cg_sim_ratio = apk_cg_sim_ratio
            tpl_cg_sim_ratio = 0.65
            _nom_sim_ratio = nom_sim_ratio

            if is_abstract:
                tpl_nom_num = 0
            else:
                tpl_nom_num = tpl_all_num - len(smalls_tpl)

            if tpl_nom_num == 0:
                matched_nom_sim = 0
            else:
                matched_nom_sim = nomalnums_in_matches / tpl_nom_num  # *

            if is_abstract:
                apk_cg_sim_ratio = 1.0
                tpl_cg_sim_ratio = 1.0
                nom_sim_ratio = 1.0
                cg_sim_apk = 1.0
                matched_nom_sim = matched_all_sim
                nomalnums_in_matches = matched_all_num
            else:
                if tpl_nom_num == 0:
                    nom_sim_ratio = 0.8
                    matched_nom_sim = matched_all_sim

            with open(f"./ans-{out}.txt", "a") as f:
                f.write("###" + tpl_ + (" !!!" if is_gt else " ...") + "  " + str(is_abstract) + "\n")
                f.write(
                    "ratio:" + str(nom_sim_ratio) + "  " + str(apk_cg_sim_ratio) + "  " + str(tpl_cg_sim_ratio) + "\n")
                f.write("\t\tmatch:  " + str(round(matched_all_sim, 4)) + " = " + str(matched_all_num) + "/" + str(
                    tpl_all_num) + "\n")
                f.write(
                    "\t\tnomal:  " + str(round(matched_nom_sim, 4)) + " = " + str(nomalnums_in_matches) + "/" + str(
                        tpl_nom_num) + "\n")
                f.write("\t\tcg tpl: " + str(round(cg_sim_tpl, 4)) + " of " + str(cg_size_tpl) + "\n")
                f.write("\t\tcg apk: " + str(round(cg_sim_apk, 4)) + " of " + str(cg_size_apk) + "\n")
                f.write("\t\tscore:  " + str(score) + "\n")

                if cg_sim_tpl >= tpl_cg_sim_ratio and cg_sim_apk >= apk_cg_sim_ratio and matched_nom_sim >= nom_sim_ratio:
                    f.write("~~~yes\n")
                    detect_res[tpl_] = (score, matched_nom_sim, nomalnums_in_matches, matched_all_sim, matched_all_num)
                else:
                    f.write("~~~no\n")
                f.write("\n")

            t2m[tpl_] = [id2method_apk[x] for x in res.values()]

        final_match = get_final_match(detect_res)
        t2m_new = {}
        for ftpl in final_match.keys():
            t2m_new[ftpl] = t2m[ftpl]

        with open(f"./ans-{out}.txt", "a") as f:
            f.write(apk_file + "\n")
            f.write("ans:   " + str(final_match) + "\n")

        final_t = find_independent_sets(t2m_new, 0.3)
        new_final_match = []
        for i in final_t:
            new_final_match.append(final_match[i])

        wubaos = []
        loubaos = []
        gt_num = len(gts)
        ans_num = len(new_final_match)
        correct_num = 0
        for x in new_final_match:
            flag = False
            for xx in x:
                if xx in gts:
                    flag = True
                    break
            if flag:
                correct_num += 1
            else:
                wubaos.append(x)
                ans_num += len(x) - 1
        for x in gts:
            flag = False
            for fmt in new_final_match:
                if x in fmt:
                    flag = True
                    break
            if not flag:
                loubaos.append(x)
        totol_gt += gt_num
        totol_ans += ans_num
        correct += correct_num
        jd = correct_num / ans_num if ans_num else 0
        zh = correct_num / gt_num if gt_num else 0
        jds += jd
        zhs += zh
        with open(f"./ans-{out}.txt", "a") as f:

            f.write("ans:   " + str(new_final_match) + "\n")
            f.write("jd: " + str(round(jd, 4)) + "   zh: " + str(round(zh, 4)) + "\n")
            if wubaos:
                f.write("wubao: " + str(wubaos) + "\n")
            if loubaos:
                f.write("loubao: " + str(loubaos) + "\n")
            f.write("jd: " + str(round(correct / totol_ans, 4)) + "   zh: " + str(
                (round(correct / totol_gt, 4) if totol_gt else 0)) + "\n")
            f.write(str(correct) + "   " + str(totol_ans) + "   " + str(totol_gt) + "   " + str(d_t) + "\n")
        with open(f"./log-{out}.txt", "a") as f:
            f.write("\n")
        with open(f"./ans-{out}.txt", "a") as f:
            f.write("\n")
    with open(f"./log-{out}.txt", "a") as f:
        f.write("features apk cost avg: " + str(round(f_a_t / apk_len, 4)) + "s\n")
        f.write("features lib cost avg: " + str(round(f_l_t / len(libs_f), 4)) + "s\n")
        f.write("detect cost avg: " + str(round(d_t / cnt, 4)) + "s\n")
    with open(f"./ans-{out}.txt", "a") as f:
        f.write("jd: " + str(round(correct / totol_ans, 4)) + "   " + str(round(jds / apk_len, 4)) + "\n")
        f.write("zh: " + str((round(correct / totol_gt, 4) if totol_gt else 0)) + "   " + str(
            round(zhs / apk_len, 4)) + "\n")
    print("features apk cost avg:", round(f_a_t / apk_len, 4), "s")
    print("features lib cost avg:", round(f_l_t / len(libs_f), 4), "s")
    print("detect cost avg:", round(d_t / cnt, 4), "s")


if __name__ == "__main__":
    evaluate("apks_features_r8", "libs_features_r8", "r8/gt.txt",
             os.listdir("r8/apks_dft"), "dft")
    evaluate("apks_features_r8", "libs_features_r8", "r8/gt.txt",
             os.listdir("r8/apks_none"), "none")
    evaluate("apks_features_r8", "libs_features_r8", "r8/gt.txt",
             os.listdir("r8/apks_opt"), "opt")
    evaluate("apks_features_r8", "libs_features_r8", "r8/gt.txt",
             os.listdir("r8/apks_orlis"), "orlis")
