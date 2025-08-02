import subprocess
import zipfile
import os
import re

def extract_min_sdk_version(string):
    pattern = r'--min-sdk-version\s+>=\s+(\d+)'
    match = re.search(pattern, string)
    if match:
        min_sdk_version = match.group(1)
        return min_sdk_version
    else:
        return None


def jar2dex(jar_path):
    output = jar_path[:-4] + ".dex"
    try:
        cmd = "dex2jar/d2j-jar2dex.sh " + jar_path + " -o " + output
        print(cmd)
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print("success")
    except subprocess.CalledProcessError as e:
        print("failed 0")
        sdk_v = None
        suc_flag = 0
        __err = ""
        for i in range(5):
            try:
                if sdk_v:
                    _cmd = f"java -jar dex2jar/lib/dx-30.0.2.jar --dex --no-warning --min-sdk-version={sdk_v} --output={output} {jar_path} "
                else:
                    _cmd = f"java -jar dex2jar/lib/dx-30.0.2.jar --dex --no-warning --output={output} {jar_path} "
                print(_cmd)
                subprocess.run(_cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                print("success")
                suc_flag = 1
                break
            except subprocess.CalledProcessError as ee:
                print("failed", i+1)
                __err = str(ee.stderr.strip()).replace('\n', ' ')
                sdk_v = extract_min_sdk_version(__err)
                if not sdk_v:
                    break
        if not suc_flag:
            _eer = str(e.stderr.strip()).replace('\n', ' ')
            with open("todex_log.txt", "a") as f:
                print(f"{jar_path}:::{_eer}///{__err}")
                f.write(f"{jar_path}:::{_eer}///{__err}\n")


def tpl2dex(libs_dir):
    for root, dirs, files in os.walk(libs_dir):
        for lib in files:
            if os.path.exists(os.path.join(root, lib[:lib.rfind(".")] + ".dex")):
                continue
            if lib[:-4] not in td:
                continue
            if lib.endswith(".aar"):
                if os.path.exists(os.path.join(root, lib[:lib.rfind(".")] + ".jar")):
                    os.remove(os.path.join(root, lib[:lib.rfind(".")] + ".jar"))
                with zipfile.ZipFile(os.path.join(root, lib), 'r') as zip_ref:
                    cls_flag = 0
                    for file_info in zip_ref.infolist():
                        if file_info.filename == 'classes.jar':
                            zip_ref.extract(file_info, root)
                            jar_path = os.path.join(root, lib[:lib.rfind(".")] + ".jar")
                            os.rename(os.path.join(root, "classes.jar"), jar_path)
                            print(jar_path + "...")
                            jar2dex(jar_path)
                            cls_flag = 1
                            break
                    if not cls_flag:
                        print("no classes.jar")
                        with open("todex_log.txt", "a") as f:
                            f.write(f"{jar_path}:::no classes.jar\n")
            if lib.endswith(".jar"):
                jar2dex(os.path.join(root, lib))
            print()

def d8process():
    with open("todex_log.txt", "r") as f:
        ls = [x.split(":::")[0] for x in f.readlines() if x.strip()]
    for jar_path in ls:
        output = jar_path[:-4] + ".zip"
        output_dex = jar_path[:-4] + ".dex"
        root = jar_path[:jar_path.rfind("/")]
        try:
            cmd = "~/androids/android-sdk/build-tools/34.0.0/d8 --output " + output + " " + jar_path
            print(cmd)
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            has_dex = 0
            with zipfile.ZipFile(output, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    if file_info.filename == 'classes.dex':
                        has_dex = 1
                        zip_ref.extract(file_info, root)
            if has_dex:
                os.rename(os.path.join(root, "classes.dex"), output_dex)
                os.remove(output)
                print("success")
            else:
                print("failed\n", jar_path, ":::d8 output no classes.dex")
        except subprocess.CalledProcessError as e:
            print("failed")
            print(jar_path, ":::", str(e))


tpls_dir = ""
tpl2dex(tpls_dir)
d8process()
