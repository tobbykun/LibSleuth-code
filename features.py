import functools
import itertools
import os
import re
import time
import pickle
from androguard.misc import AnalyzeAPK, AnalyzeDex
from loguru import logger

logger.remove()

acnotes = {}


@functools.cache
def access_nom(_str):
    if _str in acnotes:
        return acnotes[_str]

    new_str = ""
    if 'interface' in _str:
        new_str += 'interface'
    if 'abstract' in _str:
        new_str += 'abstract'
    if 'static' in _str:
        new_str += 'static'
    if 'constructor' in _str:
        new_str += 'constructor'
    acnotes[_str] = new_str
    return new_str


stds = ['Landroid/Manifest', 'Landroid/R', 'Landroid/accessibilityservice', 'Landroid/accounts', 'Landroid/adservices',
        'Landroid/animation', 'Landroid/annotation', 'Landroid/app', 'Landroid/appwidget', 'Landroid/bluetooth',
        'Landroid/companion', 'Landroid/content', 'Landroid/credentials', 'Landroid/crypto', 'Landroid/database',
        'Landroid/devicelock', 'Landroid/drm', 'Landroid/gesture', 'Landroid/graphics', 'Landroid/hardware',
        'Landroid/health', 'Landroid/icu', 'Landroid/inputmethodservice', 'Landroid/location', 'Landroid/media',
        'Landroid/mtp', 'Landroid/net', 'Landroid/nfc', 'Landroid/opengl', 'Landroid/os', 'Landroid/preference',
        'Landroid/print', 'Landroid/printservice', 'Landroid/provider', 'Landroid/renderscript', 'Landroid/sax',
        'Landroid/se', 'Landroid/security', 'Landroid/service', 'Landroid/speech', 'Landroid/system',
        'Landroid/telecom', 'Landroid/telephony', 'Landroid/test', 'Landroid/text', 'Landroid/transition',
        'Landroid/util', 'Landroid/view', 'Landroid/webkit', 'Landroid/widget', 'Landroid/window', 'Ldalvik/annotation',
        'Ldalvik/bytecode', 'Ldalvik/system', 'Ljava/awt', 'Ljava/beans', 'Ljava/io', 'Ljava/lang', 'Ljava/math',
        'Ljava/net', 'Ljava/nio', 'Ljava/security', 'Ljava/sql', 'Ljava/text', 'Ljava/time', 'Ljava/util',
        'Ljavax/annotation', 'Ljavax/crypto', 'Ljavax/microedition', 'Ljavax/net', 'Ljavax/security', 'Ljavax/sql',
        'Ljavax/xml',
        'Lorg/w3c', 'Lorg/xml', 'Lorg/xmlpull']
is_stds = {}


@functools.cache
def check_is_std(name):
    if name in is_stds:
        return is_stds[name]
    else:
        is_std = False
        for x in stds:
            if x in name:
                is_std = True
                break
        is_stds[name] = is_std
        return is_std


type_notes = {}


@functools.cache
def type_nom(_str):
    '''
    https://source.android.com/docs/core/dalvik/dex-format?hl=zh-cn#typedescriptor
    V,Z,B,S,C,I,J,F,D
    L
    [
    '''
    if _str in type_notes:
        return type_notes[_str]
    is_array = _str[0] == '['
    str_t = _str
    if is_array:
        _str = _str.strip('[')
    if _str:
        if _str[0] == 'L' and not check_is_std(_str):
            if is_array:
                ans = str_t[:str_t.find('[L') + 1] + "X"
                type_notes[str_t] = ans
                return ans
            else:
                type_notes[str_t] = 'X'
                return 'X'
        else:
            type_notes[str_t] = str_t
            return str_t
    return '['


simple_op_notes = {"if-ne": "if0", "if-eq": "if0",
                   "if-nez": "if1", "if-eqz": "if1",
                   "if-lt": "if2", "if-ge": "if2",
                   "if-gt": "if3", "if-le": "if3",
                   "if-gez": "if4", "if-ltz": "if4",
                   "if-lez": "if5", "if-gtz": "if5"}


@functools.cache
def simple_op(op):
    if op in simple_op_notes:
        return simple_op_notes[op]
    if "/2addr" in op:
        ops = op[:-6]
        simple_op_notes[op] = ops
        return ops
    if "/lit" in op:
        ops = op[:op.find("/l")]
        simple_op_notes[op] = ops
        return ops
    if "move" in op and "/" in op:
        ops = op.split("/")[0]
        simple_op_notes[op] = ops
        return ops
    if op.endswith("/range"):
        ops = op[:-6]
        simple_op_notes[op] = ops
        return ops
    simple_op_notes[op] = op
    return op


valid_v_1 = set()


@functools.cache
def is_valid_string(s):
    if s in valid_v_1:
        return True
    if re.match(r'^v\d+,?$', s):
        valid_v_1.add(s)
        return True
    else:
        return False


nom_op_notes = {}


@functools.cache
def nom_op(sli):
    if sli in nom_op_notes:
        return nom_op_notes[sli]
    new_slis = []
    slis = sli.split(" ")
    op_flag = True
    ivk_flag = False
    vs = []
    for t in slis:
        if not t:
            continue
        if op_flag:
            if t in nom_op_notes:
                return nom_op_notes[t]
            new_slis.append(simple_op(t))
            if "invoke" in t:
                ivk_flag = True
            op_flag = False
            continue
        if t[0] == '"':
            break
        elif t[0] == "v":
            if is_valid_string(t):
                vs.append(int(t[1:].strip(',')))
                continue
        elif t[0] == 'L':
            if ivk_flag:
                callee = sli.split(", L")
                if len(callee) != 2:
                    callee = 'L' + sli.split(" L")[1]
                else:
                    callee = 'L' + callee[1]
                cls = callee.split(';')[0] + ';'
                args = callee.split('(')[1].split(')')
                inputs = args[0].split(' ')
                out = args[1]
                new_slis.append(type_nom(cls))
                for i in inputs:
                    if i:
                        new_slis.append(type_nom(i))
                new_slis.append(type_nom(out))
                break
            else:
                new_slis.append(type_nom(t))
        elif t[0] == '[':
            if ivk_flag:
                callee = sli.split(", [")
                if len(callee) != 2:
                    callee = '[' + sli.split(" [")[1]
                else:
                    callee = '[' + callee[1]
                cls = callee.split(';')[0] + ';'
                args = callee.split('(')[1].split(')')
                inputs = args[0].split(' ')
                out = args[1]
                new_slis.append(type_nom(cls))
                for i in inputs:
                    if i:
                        new_slis.append(type_nom(i))
                new_slis.append(type_nom(out))
                break
            else:
                new_slis.append(type_nom(t))
        elif t in ['V', 'Z', 'B', 'S', 'C', 'I', 'J', 'F', 'D']:
            new_slis.append(t)
    if '/range' in sli and "..." in sli:
        vs = list(range(vs[0], vs[1] + 1))
    new_sli = ' '.join(new_slis)
    res = (new_sli, vs)
    nom_op_notes[sli] = res
    return res


@functools.cache
def get_v_direct(op):
    if "if" in op or "return" in op or "-switch" in op or "invoke-" in op or "filled-new-array" in op:
        # all up
        return -4
    if "move-result" in op:  # +pre
        return -1
    if "aput" in op or "iput" in op or "sput" in op:
        return 1
    if "monitor-enter" in op or "monitor-exit" in op or "throw" in op or "check-cast" in op:  # no
        return -3
    if "/2addr" in op:  # 0 down and 0,1 up
        return -2
    return 0


moveresults = {"move-result", "move-result-wide", "move-result-object"}
moves = {"move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16", "move-object",
         "move-object/from16", "move-object/16"}
firsts = {"const/4", "const/16", "const", "const/high16", "const-wide/16", "const-wide/32", "const-wide",
          "const-wide/high16", "const-string", "const-string/jumbo", "const-class", "instance-of", "array-length",
          "new-instance", "new-array", "fill-array-data", "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double",
          "cmp-long", "aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short",
          "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short", "sget",
          "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short", "neg-int", "not-int",
          "neg-long", "not-long", "neg-float", "neg-double", "int-to-long", "int-to-float", "int-to-double",
          "long-to-int", "long-to-float", "long-to-double", "float-to-int", "float-to-long", "float-to-double",
          "double-to-int", "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short", "add-int",
          "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
          "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long", "or-long", "xor-long", "shl-long",
          "shr-long", "ushr-long", "add-float", "sub-float", "mul-float", "div-float", "rem-float", "add-double",
          "sub-double", "mul-double", "div-double", "rem-double", "add-int/2addr", "sub-int/2addr", "mul-int/2addr",
          "div-int/2addr", "rem-int/2addr", "and-int/2addr", "or-int/2addr", "xor-int/2addr", "shl-int/2addr",
          "shr-int/2addr", "ushr-int/2addr", "add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr",
          "rem-long/2addr", "and-long/2addr", "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr",
          "ushr-long/2addr", "add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr",
          "rem-float/2addr", "add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr",
          "rem-double/2addr", "add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16",
          "and-int/lit16", "or-int/lit16", "xor-int/lit16", "add-int/lit8", "rsub-int/lit8", "mul-int/lit8",
          "div-int/lit8", "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8",
          "ushr-int/lit8"}
seconds = {"aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short", "iput",
           "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short"}
passes = {"sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short", "move-exception",
          "return-void", "return", "return-wide", "return-object", "monitor-enter", "monitor-exit", "check-cast",
          "filled-new-array", "filled-new-array/range", "throw", "goto", "goto/16", "goto/32", "packed-switch",
          "sparse-switch", "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz", "if-nez", "if-ltz", "if-gez",
          "if-gtz", "if-lez", "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static", "invoke-interface",
          "invoke-virtual/range", "invoke-super/range", "invoke-direct/range", "invoke-static/range",
          "invoke-interface/range"}


def is_define(opt, vs, v):
    op = opt.split(" ")[0]
    if op in moveresults:
        return -1
    elif op in firsts:
        if vs[0] == v:
            if "/2addr" in op:
                return 4
            return 1
    elif op in seconds:
        if vs[1] == v:
            return 1
    elif op in moves:
        if v == vs[0]:
            return 3
        elif v == vs[1]:
            return 2
    return 0


slides_notes = {}


def get_slides_until_define(b, i, v, direct, step, b2ins):

    code_slides = set()
    xref_slides = set()
    if step == 5:
        return code_slides, xref_slides
    strv = 'v' + str(v)
    key = b.name + str(i) + strv + str(direct)

    if key in slides_notes:
        return slides_notes[key]

    if direct:
        ists = b2ins[b.name]
        end_flag = False
        for idx in range(i + 1, len(ists)):
            istt = ists[idx]
            opt = istt.get_name() + " " + istt.get_output()

            nom_opt, vst = nom_op(opt)
            if v in vst:
                define_res = is_define(opt, vst, v)
                if define_res == 1 or define_res == -1 or define_res == 3:
                    end_flag = True
                    break
                code_slides.add(nom_opt)
                xref_slides.add(opt)
                if define_res == 2:
                    code_slides_t, xref_slides_t = get_slides_until_define(b, idx, vst[0], True, step + 1, b2ins)
                    code_slides.update(code_slides_t)
                    xref_slides.update(xref_slides_t)
                elif define_res == 4:
                    end_flag = True
                    break
        if not end_flag:
            q = []
            vi = set()
            for bt in b.childs:
                q.append(bt[2])
            while True:
                if not q:
                    break
                now_b = q.pop()
                bname = now_b.name
                if bname in vi:
                    continue
                vi.add(bname)
                ists = b2ins[now_b.name]
                end_flag = False
                for idx in range(len(ists)):

                    istt = ists[idx]
                    opt = istt.get_name() + " " + istt.get_output()

                    nom_opt, vst = nom_op(opt)
                    if v in vst:
                        define_res = is_define(opt, vst, v)
                        if define_res == 1 or define_res == -1 or define_res == 3:
                            end_flag = True
                            break
                        code_slides.add(nom_opt)
                        xref_slides.add(opt)
                        if define_res == 2:
                            code_slides_t, xref_slides_t = get_slides_until_define(now_b, idx, vst[0], True, step + 1,
                                                                                   b2ins)
                            code_slides.update(code_slides_t)
                            xref_slides.update(xref_slides_t)
                        elif define_res == 4:
                            end_flag = True
                            break
                if not end_flag:
                    for bt in now_b.childs:
                        q.append(bt[2])
    else:
        ists = b2ins[b.name]
        end_flag = False
        for idx in range(max(i - 1, 0), -1, -1):

            istt = ists[idx]
            opt = istt.get_name() + " " + istt.get_output()

            nom_opt, vst = nom_op(opt)
            if v in vst:
                code_slides.add(nom_opt)
                xref_slides.add(opt)
                define_res = is_define(opt, vst, v)
                if define_res == 1 or define_res == 4:
                    end_flag = True
                    break
                elif define_res == -1:

                    istt = ists[idx - 1]
                    opt = istt.get_name() + " " + istt.get_output()

                    nom_opt, vst = nom_op(opt)
                    code_slides.add(nom_opt)
                    xref_slides.add(opt)
                    end_flag = True
                    break
                elif define_res == 3:
                    code_slides_t, xref_slides_t = get_slides_until_define(b, idx, vst[1], False, step + 1, b2ins)
                    code_slides.update(code_slides_t)
                    xref_slides.update(xref_slides_t)
                    end_flag = True
                    break
        if not end_flag:
            q = []
            vi = set()
            for bt in b.fathers:
                q.append(bt[2])
            while True:
                if not q:
                    break
                now_b = q.pop()
                bname = now_b.name
                if bname in vi:
                    continue
                vi.add(bname)
                ists = b2ins[now_b.name]
                end_flag = False
                for idx in range(len(ists) - 1, -1, -1):

                    istt = ists[idx]
                    opt = istt.get_name() + " " + istt.get_output()

                    nom_opt, vst = nom_op(opt)
                    if v in vst:
                        code_slides.add(nom_opt)
                        xref_slides.add(opt)
                        define_res = is_define(opt, vst, v)
                        if define_res == 1 or define_res == 4:
                            end_flag = True
                            break
                        elif define_res == -1:

                            opt = str(ists[idx - 1])
                            istt = ists[idx - 1]
                            opt = istt.get_name() + " " + istt.get_output()

                            nom_opt, vst = nom_op(opt)
                            code_slides.add(nom_opt)
                            xref_slides.add(opt)
                            end_flag = True
                            break
                        elif define_res == 3:
                            code_slides_t, xref_slides_t = get_slides_until_define(now_b, idx, vst[1], False, step + 1,
                                                                                   b2ins)
                            code_slides.update(code_slides_t)
                            xref_slides.update(xref_slides_t)
                            end_flag = True
                            break
                if not end_flag:
                    for bt in now_b.fathers:
                        q.append(bt[2])
    slides_notes[key] = (code_slides, xref_slides)

    return code_slides, xref_slides




def get_related_code_slice(xref_slice, code_slice, method, bs, input_parameters, output_parameter):

    global slides_notes
    slides_notes = {}

    totol_ops = set()
    bbhashs_3gram = {}
    bbhashs = {}
    ljlb = {}

    in_params_correct = []
    if input_parameters and 'params' in method.get_information():
        start_v = method.get_locals() + 1 - (input_parameters.count('J') + input_parameters.count('D'))
        v2id = {}
        idx_t = 0
        for ipt in input_parameters:
            in_params_correct.append(start_v)
            v2id[start_v] = idx_t
            idx_t += 1
            if ipt in ['J', 'D']:
                start_v += 2
            else:
                start_v += 1

    string_constants = []
    string_notes = set()

    ipv_notes = {}
    opv_note = []

    vsp = []
    nom_optp = ''
    optp = ''
    pre_is_ivk = []
    b2ins = {}

    unadd_3grams = {}

    for b in bs:
        b_name = b.name
        ops = []
        instructions = tuple(b.get_instructions())
        b2ins[b_name] = instructions
        for i, x in enumerate(instructions):
            opt = x.get_name() + " " + x.get_output()
            if "const-string" in opt:
                if opt in string_notes:
                    continue
                string_constants.append(opt)
            if opt.startswith("nop") or opt[0] == '<':
                continue
            nom_opt, vs = nom_op(opt)

            if isinstance(nom_opt, str):
                v_type = get_v_direct(nom_opt)
                ops.append(nom_opt)
            else:
                ops.extend(nom_opt)
                continue

            if not vs:
                continue


            if in_params_correct:

                st = time.time()

                if "invoke-" in nom_opt or "filled-new-array" in nom_opt:
                    vsp = vs.copy()
                    nom_optp = nom_opt
                    optp = opt
                    for ipt in in_params_correct:
                        if ipt in vs:
                            pre_is_ivk.append(v2id[ipt])
                if "move-result" in nom_opt and pre_is_ivk:
                    for pre_vid in pre_is_ivk:
                        code_slice[pre_vid].add(nom_opt)
                        xref_slice[pre_vid].add(opt)
                        ipv_notes[pre_vid].append((b, i, vs[0], True))
                    pre_is_ivk = []

                for ipt in in_params_correct:

                    if ipt in vs:
                        vid = v2id[ipt]

                        if vid not in ipv_notes:
                            ipv_notes[vid] = []
                        code_slice[vid].add(nom_opt)
                        xref_slice[vid].add(opt)

                        if v_type == 0:
                            vt = vs[0]
                            if vt != ipt:
                                ipv_notes[vid].append((b, i, vt, True))  # down
                            for vt in vs[1:]:
                                if vt != ipt:
                                    ipv_notes[vid].append((b, i, vt, False))  # up
                        elif v_type == 1:
                            vt = vs[0]
                            if vt != ipt:
                                ipv_notes[vid].append((b, i, vt, False))
                            lvs = len(vs)
                            if lvs != 1:
                                vt = vs[1]
                                if vt != ipt:
                                    ipv_notes[vid].append((b, i, vt, True))
                            if lvs == 3:
                                vt = vs[2]
                                if vt != ipt:
                                    ipv_notes[vid].append((b, i, vt, False))
                        elif v_type == -4:
                            for vt in vs:
                                if vt != ipt:
                                    ipv_notes[vid].append((b, i, vt, False))
                        elif v_type == -2:
                            vt = vs[0]
                            if vt != ipt:
                                ipv_notes[vid].append((b, i, vt, True))
                                ipv_notes[vid].append((b, i, vt, False))
                            vt = vs[1]
                            if vt != ipt:
                                ipv_notes[vid].append((b, i, vt, False))
                        elif v_type == -1:
                            code_slice[vid].add(nom_optp)
                            xref_slice[vid].add(optp)
                            for vt in vsp:
                                ipv_notes[vid].append((b, i - 1, vt, False))
            if output_parameter != 'V':
                if "return" in nom_opt and "-void" not in nom_opt:
                    code_slice[-1].add(nom_opt)
                    xref_slice[-1].add(opt)
                    opv_note.append((b, i, vs[0], False))

        ljlb[b_name] = []
        for child in b.childs:
            ljlb[b_name].append(child[2].name)

        if ops:
            ops_set = set(ops)
            totol_ops.update(ops_set)
            len_ops_set = len(ops_set)
            bbhashs[b_name] = (ops_set, len_ops_set)
            bbhashs_3gram[b_name] = [ops_set.copy(), len_ops_set]
            for father in b.fathers:
                father_name = father[2].name
                if father_name not in bbhashs_3gram:
                    unadd_3grams[father_name] = b_name
                else:
                    bbhashs_3gram[b_name][0].update(bbhashs[father_name][0])
                    # bbhashs_3gram[b_name][1] += bbhashs[father_name][1]
                    bbhashs_3gram[b_name][1] = len(bbhashs_3gram[b_name][0])
                    bbhashs_3gram[father_name][0].update(ops_set)
                    # bbhashs_3gram[father_name][1] += len_ops_set
                    bbhashs_3gram[father_name][1] = len(bbhashs_3gram[father_name][0])

    for father, child in unadd_3grams.items():
        if father in bbhashs:
            bbhashs_3gram[father][0].update(bbhashs[child][0])
            bbhashs_3gram[father][1] = len(bbhashs_3gram[father][0])
            bbhashs_3gram[child][0].update(bbhashs[father][0])
            bbhashs_3gram[child][1] = len(bbhashs_3gram[child][0])

    for iid, rvs in ipv_notes.items():
        for rv in rvs:
            code_slice_t, xref_slice_t = get_slides_until_define(rv[0], rv[1], rv[2], rv[3], 0, b2ins)
            xref_slice[iid].update(xref_slice_t)
            code_slice[iid].update(code_slice_t)


    return totol_ops, bbhashs, bbhashs_3gram, ljlb, tuple(code_slice), xref_slice, string_constants


fields_notes = {}


def get_fields_from_method(_fields, dx, io, xref_slice, field_nums):
    fields = []
    for _, field, _ in _fields:
        field_name = field.get_name()
        field_ac = access_nom(field.get_access_flags_string())
        field_descriptor = field.get_descriptor()
        field_class_name = field.get_class_name()

        ori_f_sig = field_class_name + field_descriptor + field_name

        ori_f_sig_io = ori_f_sig + io
        if ori_f_sig_io in field_nums:
            continue
        field_nums.add(ori_f_sig_io)

        if ori_f_sig in fields_notes:
            nom_sig, field_sc, _code = fields_notes[ori_f_sig]
        else:
            field_sc_name = None
            field_sc_num = -1
            field_cls_ac = ""
            classobj = dx.get_class_analysis(field_class_name)
            if not classobj.is_external():
                f_c_t = classobj.orig_class
                field_cls_ac = access_nom(f_c_t.get_access_flags_string())
                field_sc_name, field_sc_num = find_father(dx, field_class_name, 0)
                field_sc_name = (field_sc_name + str(field_sc_num)) if check_is_std(field_sc_name) else None

            nom_sig = type_nom(field_class_name) + type_nom(field_descriptor) + field_cls_ac + field_ac
            _code = field_class_name + "->" + field_name
            field_sc = (field_sc_name, field_sc_num)
            fields_notes[ori_f_sig] = (nom_sig, field_sc, _code)

        field_xref = set()
        for _idx, _arg in enumerate(xref_slice):
            for sli in _arg:
                if _code in sli:
                    field_xref.add(_idx)
                    break
        nom_sig += io
        fields.append((ori_f_sig_io, nom_sig, field_sc, field_xref))
    return fields


@functools.cache
def find_father(dx, cls, f):
    sc_cls = dx.get_class_analysis(cls)
    if not sc_cls:
        return cls, 0
    if sc_cls.is_external():
        return sc_cls.name, 0
    name, numt = find_father(dx, sc_cls.extends, f)
    return name, numt + 1


def get_main_classes(manifest, main_classe_type):
    main_classes = []
    for main_classe in manifest.findall(f".//{main_classe_type}"):
        app_name = main_classe.get("{http://schemas.android.com/apk/res/android}name")
        if app_name:
            main_classes.append("L" + app_name.replace(".", "/"))
    return main_classes


def extract_main_classes(manifest):
    main_classes = set()
    main_classes.update(get_main_classes(manifest, "application"))
    main_classes.update(get_main_classes(manifest, "activity"))
    main_classes.update(get_main_classes(manifest, "service"))
    main_classes.update(get_main_classes(manifest, "provider"))
    main_classes.update(get_main_classes(manifest, "receiver"))
    return main_classes


def get_feature(apk_path, _type, param_acnotes, param_is_stds, param_type_notes, param_simple_op_notes, param_valid_v_1,
                param_nom_op_notes, param_method_arg_nom_notes, param_params2nomnote, param_method_protonote):

    global acnotes
    acnotes = param_acnotes
    global is_stds
    is_stds = param_is_stds
    global type_notes
    type_notes = param_type_notes
    global simple_op_notes
    simple_op_notes = param_simple_op_notes
    global valid_v_1
    valid_v_1 = param_valid_v_1
    global nom_op_notes
    nom_op_notes = param_nom_op_notes


    stt = time.time()

    is_apk = False
    if _type == "apk":
        is_apk = True
        apk, dv, dx = AnalyzeAPK(apk_path)
        manifest = apk.get_android_manifest_xml()
        if manifest is not None:
            main_classes = extract_main_classes(manifest)
        else:
            main_classes = []
    else:
        _, dv, dx = AnalyzeDex(apk_path)
    method_signatures = set()
    method2id = {}
    id2method = []
    id2construct = []
    features = {}
    basics = []
    args = []
    strings = []
    fields = []
    apis = []
    bbcfgs = []
    cg = {}
    fuzzy_sig_mappings_v1 = {}
    fuzzy_sig_mappings_v2 = {}
    sc_nums = {}
    smalls = set()
    idx = 0
    global fields_notes
    fields_notes = {}
    methods_notes = {}
    method_arg_nom_notes = param_method_arg_nom_notes
    params2nomnote = param_params2nomnote
    method_protonote = param_method_protonote
    abs_method_num = 0


    for cls in dx.get_classes():
        if cls.is_external():
            continue

        cls_name = cls.name
        if is_apk:
            is_main = False
            for x in main_classes:
                if x in cls_name:
                    is_main = True
                    break
            if is_main:
                continue

        stt = time.time()

        cls_ac = access_nom(cls.orig_class.get_access_flags_string())
        sc, sc_num = find_father(dx, cls.name, 0)
        sc_is_std = False
        if check_is_std(sc):
            sc_is_std = True
        else:
            sc = "X"
        sc_num_str = str(sc_num)
        sc += sc_num_str


        for method in cls.get_methods():  # get_method_analysis

            stt = time.time()
            ori_method = method.method

            method_access = access_nom(method.access)

            method_proto = method.descriptor  # 方法参数类型
            if method_proto in method_protonote:
                input_parameters, output_parameter, args_nom = method_protonote[method_proto]
            else:
                input_parameters = method_proto[1:method_proto.find(')')]
                input_parameters_o = input_parameters
                if not input_parameters:
                    input_parameters = []
                else:
                    input_parameters = input_parameters.split(' ')
                output_parameter = method_proto[method_proto.find(')') + 1:]

                input_parameters_nom = []
                if input_parameters_o in params2nomnote:
                    input_parameters_nom = params2nomnote[input_parameters_o]
                else:
                    for i in input_parameters:
                        input_parameters_nom.append(type_nom(i))
                    params2nomnote[input_parameters_o] = input_parameters_nom

                output_parameter_nom = type_nom(output_parameter)
                args_nom = ",".join(input_parameters_nom) + ':' + output_parameter_nom

                method_protonote[method_proto] = input_parameters, output_parameter, args_nom

            is_constrcut = False
            method_name = method.name
            if "<init>" in method_name:
                method_name_nom = "<init>"
                is_constrcut = True
            elif "<clinit>" in method_name:
                method_name_nom = "<clinit>"
                is_constrcut = True
            else:
                method_name_nom = ""

            method_origin_signature = cls_name + ":" + method_name + ":" + method_proto.replace(' ', '')
            fuzzy_sig = cls_ac + method_access + args_nom + method_name_nom
            fuzzy_sig_v1 = sc + fuzzy_sig
            fuzzy_sig_v2 = sc_num_str + fuzzy_sig

            if fuzzy_sig in sc_nums:
                sc_nums[fuzzy_sig] = max(sc_nums[fuzzy_sig], sc_num)
            else:
                sc_nums[fuzzy_sig] = sc_num

            method_signatures.add(method_origin_signature)
            method2id[method_origin_signature] = idx
            id2method.append(method_origin_signature)

            basics.append((sc_is_std, fuzzy_sig_v1, fuzzy_sig_v2))

            id2construct.append(is_constrcut)

            if sc_is_std:
                if fuzzy_sig_v1 not in fuzzy_sig_mappings_v1:
                    fuzzy_sig_mappings_v1[fuzzy_sig_v1] = set()
                fuzzy_sig_mappings_v1[fuzzy_sig_v1].add(idx)
            if fuzzy_sig_v2 not in fuzzy_sig_mappings_v2:
                fuzzy_sig_mappings_v2[fuzzy_sig_v2] = set()
            fuzzy_sig_mappings_v2[fuzzy_sig_v2].add(idx)

            xref_slice = []
            arg_slice = []
            for ipt in input_parameters:
                arg_slice.append(set())
                xref_slice.append(set())
            arg_slice.append(set())
            xref_slice.append(set())
            bbhashs = {}
            bbhashs_3gram = {}
            ljlb = {}
            totol_ops = set()
            _method_strings = None

            if not method.is_external():
                bs = method.get_basic_blocks().gets()
                totol_ops, bbhashs, bbhashs_3gram, ljlb, arg_slice, xref_slice, _method_strings = get_related_code_slice(
                    xref_slice, arg_slice, ori_method, bs, input_parameters, output_parameter)
            bbcfgs.append((totol_ops, bbhashs, bbhashs_3gram, ljlb))


            arg_slices_totol_list = tuple(itertools.chain.from_iterable(arg_slice))
            arg_slices_totol_set = set(arg_slices_totol_list)
            args.append((arg_slice, len(arg_slices_totol_list), arg_slices_totol_set))
            string_xrefs = set()
            strings_len = 0
            if _method_strings:
                for _code in _method_strings:
                    for _idx, _arg in enumerate(xref_slice):
                        if _code in _arg:
                            string_xrefs.add(_idx)
                strings_len = len(_method_strings)
            strings.append((strings_len, string_xrefs))

            field_nums = set()
            # print("###", method_origin_signature)
            field_features = get_fields_from_method(method.get_xref_read(), dx, "read", xref_slice, field_nums)
            field_features += get_fields_from_method(method.get_xref_write(), dx, "write", xref_slice, field_nums)
            fields.append((tuple(field_features), len(field_nums)))

            method_calls = []
            method_v = set()
            for call in method.get_xref_to():
                call0 = call[0]
                call1 = call[1]
                # call1.name  0
                call_access_flags_string = access_nom(call1.get_access_flags_string())  # 1
                call_descriptor = call1.get_descriptor()  # 2
                call_class_name = call1.get_class_name()  # 3
                call_name = call1.name

                ori_api_sig = call_class_name + call_name + call_descriptor
                if ori_api_sig in method_v:
                    continue
                method_v.add(ori_api_sig)

                if ori_api_sig in methods_notes:
                    nom_sig, nom_sig_no_access, mothed_sc, _code = methods_notes[ori_api_sig]
                else:

                    _code = call_class_name + "->" + call_name + call_descriptor

                    if call_descriptor in method_arg_nom_notes:
                        nom_args = method_arg_nom_notes[call_descriptor]
                    else:
                        ykh_idx = call_descriptor.find(')')
                        o_args = call_descriptor[1:ykh_idx].split(' ')
                        o_args.append(call_descriptor[ykh_idx + 1:])
                        nom_args = ''.join((type_nom(x) for x in o_args if x))
                        method_arg_nom_notes[call_descriptor] = nom_args

                    method_sc_num = -1
                    method_sc_name = None
                    call_cls_access = ""
                    if not call0.is_external():
                        call_c_t = call0.get_vm_class()
                        call_cls_access = access_nom(call_c_t.get_access_flags_string())
                        method_sc_name, method_sc_num = find_father(dx, call_c_t.name, 0)
                        method_sc_name = (method_sc_name + str(method_sc_num)) if check_is_std(method_sc_name) else None
                    mothed_sc = (method_sc_name, method_sc_num)

                    nom_sig_no_access = type_nom(call_class_name) + nom_args
                    nom_sig = nom_sig_no_access + call_cls_access + call_access_flags_string

                    methods_notes[ori_api_sig] = (nom_sig, nom_sig_no_access, mothed_sc, _code)

                call_type = ''
                call_xref = set()
                for _idx, _arg in enumerate(xref_slice):
                    for sli in _arg:
                        if _code in sli:
                            call_xref.add(_idx)
                            if not call_type:
                                call_type = sli[:sli.find(' ')]
                                if '/range' in call_type:
                                    call_type = call_type[:-6]
                            break

                method_calls.append((ori_api_sig, nom_sig, nom_sig_no_access, mothed_sc, call_xref, call_type))

                sttt = time.time()
                if not call0.is_external():
                    callee_signature = call_class_name + ":" + call_name + ":" + call_descriptor.replace(' ', '')
                    if method_origin_signature not in cg:
                        cg[method_origin_signature] = []
                    cg[method_origin_signature].append(callee_signature)
            apis.append((tuple(method_calls), len(method_v)))


            bh0 = None
            for x in bbhashs:
                bh0 = bbhashs[x]
                break
            if not bbhashs or (
                    len(bbhashs) == 1 and len(bh0) <= 4 and len(field_features) <= 2 and len(method_calls) <= 1):
                smalls.add(idx)

            if "abstract" in cls_ac or "interface" in cls_ac:
                abs_method_num += 1

            idx += 1

    stt = time.time()
    id_cg = {}
    for caller, callees in cg.items():
        index = method2id[caller]
        id_cg[index] = []
        for callee in callees:
            if callee in method2id:
                id_cg[index].append(method2id[callee])
    if is_apk:
        for _sig, _max_sc_num in sc_nums.items():
            if _max_sc_num == 1:
                continue
            if _max_sc_num == 2:
                sig_x = "1" + _sig
                if sig_x not in fuzzy_sig_mappings_v2:
                    fuzzy_sig_mappings_v2[sig_x] = fuzzy_sig_mappings_v2["2" + _sig].copy()
                else:
                    fuzzy_sig_mappings_v2[sig_x] |= fuzzy_sig_mappings_v2["2" + _sig]
                continue
            pre_sig = str(_max_sc_num) + _sig
            for idx in range(_max_sc_num - 1, 0, -1):
                sig_x = str(idx) + _sig
                if sig_x not in fuzzy_sig_mappings_v2:
                    fuzzy_sig_mappings_v2[sig_x] = fuzzy_sig_mappings_v2[pre_sig].copy()
                else:
                    fuzzy_sig_mappings_v2[sig_x] |= fuzzy_sig_mappings_v2[pre_sig]
                pre_sig = sig_x
    features['basics'] = basics
    features['args'] = args
    features['strings'] = strings
    features['fields'] = fields
    features['apis'] = apis
    features['bbcfgs'] = bbcfgs

    if abs_method_num == idx:
        return method_signatures, method2id, tuple(id2method), tuple(
            id2construct), features, id_cg, fuzzy_sig_mappings_v1, fuzzy_sig_mappings_v2, {-1}, (
    acnotes, is_stds, type_notes, simple_op_notes, valid_v_1, nom_op_notes, method_arg_nom_notes, params2nomnote,
    method_protonote)
    return method_signatures, method2id, tuple(id2method), tuple(
        id2construct), features, id_cg, fuzzy_sig_mappings_v1, fuzzy_sig_mappings_v2, smalls, (
    acnotes, is_stds, type_notes, simple_op_notes, valid_v_1, nom_op_notes, method_arg_nom_notes, params2nomnote,
    method_protonote)



def features_ori(files, type, root, out_path):
    file2f = {}
    if type == "apk":
        root_path = root
    else:
        root_path = root
    acnotes = {}
    is_stds = {}
    type_notes = {}
    simple_op_notes = {"if-ne": "if0", "if-eq": "if0",
                       "if-nez": "if1", "if-eqz": "if1",
                       "if-lt": "if2", "if-ge": "if2",
                       "if-gt": "if3", "if-le": "if3",
                       "if-gez": "if4", "if-ltz": "if4",
                       "if-lez": "if5", "if-gtz": "if5"}
    valid_v_1 = set()
    nom_op_notes = {"sparse-switch": (["if0", "if1", "if2", "if3", "if4", "if5"], []),
                "packed-switch": (["if0", "if1", "if2", "if3", "if4", "if5"], [])}
    method_arg_nom_notes = {}
    params2nomnote = {}
    method_protonote = {}
    cnt = 0
    for file in files:
        cnt += 1
        print(file)
        s = time.time()
        result = get_feature(
            os.path.join(root_path, file)
            # file
            , type,
            acnotes, is_stds, type_notes,
            simple_op_notes, valid_v_1, nom_op_notes, method_arg_nom_notes, params2nomnote,
            method_protonote)
        stime = time.time() - s
        print(stime)
        ans = result[:9]
        file2f[file.split("/")[-1]] = ans
        notes = result[9]
        acnotes_t, is_stds_t, type_notes_t, simple_op_notes_t, valid_v_1_t, nom_op_notes_t, method_arg_nom_notes_t, params2nomnote_t, method_protonote_t = \
            notes[0], notes[1], notes[2], notes[3], notes[4], notes[5], notes[6], notes[7], notes[8]
        acnotes.update(acnotes_t)
        is_stds.update(is_stds_t)
        type_notes.update(type_notes_t)
        simple_op_notes.update(simple_op_notes_t)
        valid_v_1.update(valid_v_1_t)
        nom_op_notes.update(nom_op_notes_t)
        method_arg_nom_notes.update(method_arg_nom_notes_t)
        params2nomnote.update(params2nomnote_t)
        method_protonote.update(method_protonote_t)
        file_name = file.split("/")[-1] + ".pkl"
        with open(f"{out_path}/{file_name}", 'wb') as f:
            pickle.dump(ans, f)
    return file2f


if __name__ == "__main__":
    root_path = ""
    out_path = ""
    files = os.listdir(root_path)
    features_ori(files, "apk/tpl", root_path, out_path)

