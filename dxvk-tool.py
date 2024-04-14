# dxvk-tool by shinrax2

# std lib
import json
import sys
import os
import tarfile
import shutil

# pip packages
import pefile # pefile
import requests # requests

class dxvk_tool():
    DXVK_LATEST = "https://api.github.com/repos/doitsujin/dxvk/releases/latest"
    DXVK_TAG = "https://api.github.com/repos/doitsujin/dxvk/releases/tags/{0}"
    DXVK_RELEASES = "https://api.github.com/repos/doitsujin/dxvk/releases"
    CACHE_DIR = "./dxvk_cache"
    DXVK_CACHE_FILE = "./dxvk_cache.json"
    DEPLOYMENTS_FILE = "./dxvk_deployments.json"
    VERSION = "v0.2"
    AUTHOR = "shinrax2"
    
    def __init__(self):
        try:
            with open(self.DEPLOYMENTS_FILE, "r", encoding="utf-8") as f:
                self.deployments = json.loads(f.read())
        except (json.JSONDecodeError, IOError):
            self.deployments = []

        try:
            with open(self.DXVK_CACHE_FILE, "r", encoding="utf-8") as f:
                self.dxvk_cache = json.loads(f.read())
        except (json.JSONDecodeError, IOError):
            self.dxvk_cache = {}
        if os.path.isdir(self.CACHE_DIR) == False:
            os.mkdir(self.CACHE_DIR)
        self.LATEST_TAG = ""
        self.resolve_latest()
    
    def resolve_latest(self):
        self.LATEST_TAG = json.loads(requests.get(self.DXVK_LATEST).content)["tag_name"]
    
    def extract_dxvk(self, tag, file):
        dir = f"{self.CACHE_DIR}/{tag}"
        file = f"{self.CACHE_DIR}/{file}"
        pre = f"dxvk-{tag[1:]}"
        files32 = [
            f"{pre}/x32/d3d9.dll",
            f"{pre}/x32/d3d10core.dll",
            f"{pre}/x32/d3d11.dll",
            f"{pre}/x32/dxgi.dll"
        ]
        files64 = [
            f"{pre}/x64/d3d9.dll",
            f"{pre}/x64/d3d10core.dll",
            f"{pre}/x64/d3d11.dll",
            f"{pre}/x64/dxgi.dll"
        ]
        if os.path.isdir(dir) == False:
            os.mkdir(dir)
        os.mkdir(f"{dir}/32")
        os.mkdir(f"{dir}/64")
        with tarfile.open(file, "r:gz") as tf:
            for f in files32:
                with open(f"{dir}/32/{os.path.basename(f)}", "wb") as fh:
                    fh.write(tf.extractfile(f).read())
            for f in files64:
                with open(f"{dir}/64/{os.path.basename(f)}", "wb") as fh:
                    fh.write(tf.extractfile(f).read())

    def save_dxvk_cache(self):
        with open(self.DXVK_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.dxvk_cache, ensure_ascii=False))
            
    def save_deployments(self):
        with open(self.DEPLOYMENTS_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.deployments, ensure_ascii=False))

    def download_dxvk(self, tag=None):
        if len(self.dxvk_cache) != 0:
            k = self.dxvk_cache.keys()
        else:
            k = []
        chunk_size=98304
        if tag is not None:
            data = json.loads(requests.get(self.DXVK_TAG.format(tag)).content)
            tag = data["tag_name"]
        else:
            data = json.loads(requests.get(self.DXVK_TAG.format(self.LATEST_TAG)).content)
            tag = self.LATEST_TAG
        if tag not in k:
            print(f"downloading dxvk version '{tag}'")
            dl_url = None
            for asset in data["assets"]:
                if os.path.basename(asset["browser_download_url"]).startswith("dxvk-") and os.path.basename(asset["browser_download_url"]).endswith(".tar.gz"):
                    dl_url = asset["browser_download_url"]
                    break
            local_filename = f"{self.CACHE_DIR}/{os.path.basename(dl_url)}"
            with requests.get(dl_url, stream=True) as r:
                    r.raise_for_status()
                    with open(local_filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=chunk_size): 
                            if chunk:
                                f.write(chunk)
            self.dxvk_cache[tag] = os.path.basename(dl_url)
            self.extract_dxvk(tag, os.path.basename(dl_url))
            self.save_dxvk_cache()
        else:
            print(f"dxvk version '{tag}' already in cache")

    def install_dxvk(self, exe, bitness, tag=None, files=[], dxvkconf=None):
        if self.is_exe_deployed(exe) == True:
            print(f"dxvk is already deployed for '{exe}'")
            return
        if tag is None:
            tag = self.LATEST_TAG
        self.download_dxvk(tag)
        cdir = f"{self.CACHE_DIR}/{tag}/{bitness}"
        exedir = os.path.dirname(exe)
        print(f"installing dxvk '{tag}'({bitness}bit) to '{exedir}'")
        for file in files:
            try:
                shutil.copy2(f"{cdir}/{file}", f"{exedir}/{file}")
            except OSError:
                print(f"couldnt copy files to '{exedir}'\nplease try again with administrator/root rights")
                sys.exit(0)
        deploy = {
            "exe": exe,
            "bitness": bitness,
            "files" : files,
            "tag" : tag
        }
        f = open(f"{exedir}/dxvk.conf", "w")
        if dxvkconf is not None:
            deploy["dxvkconf"] = dxvkconf
            f.write(dxvkconf)
        f.close()
        self.deployments.append(deploy)
        self.save_deployments()
    
    def remove_dxvk(self, exe):
        if self.is_exe_deployed == False:
            print(f"no dxvk deployed for '{exe}'")
            return 
        for deploy in self.deployments:
            if os.path.abspath(exe) == os.path.abspath(deploy["exe"]):
                d = deploy
        exedir = os.path.dirname(exe)
        for file in d["files"]:
            os.remove(f"{exedir}/{file}")
        os.remove(f"{exedir}/dxvk.conf")
        new_deploys = []
        for deploy in self.deployments:
            if os.path.abspath(exe) != os.path.abspath(deploy["exe"]):
                new_deploys.append(deploy)
        self.deployments = new_deploys
        self.save_deployments()
    
    def update_dxvk(self, exe, tag=None):
        if self.is_exe_deployed == False:
            print(f"no dxvk deployed for '{exe}'")
            return 
        if tag is None:
            tag = self.LATEST_TAG
        for deploy in self.deployments:
            if os.path.abspath(exe) == os.path.abspath(deploy["exe"]):
                d = deploy
        self.remove_dxvk(exe)
        self.install_dxvk(d["exe"], d["bitness"], tag, files=d["files"], dxvkconf=d["dxvkconf"])
    
    def update_all_dxvk(self, tag=None):
        if tag is None:
            tag = self.LATEST_TAG
        for d in self.deployments:
            self.update_dxvk(d[exe], tag)
    
    def list_deployments(self):
        for d in self.deployments:
            print(d)
    
    def parse_exe(self, exe):
        supported_dlls = [b"d3d9.dll", b"d3d10core.dll", b"d3d11.dll", b"dxgi.dll"]
        dllfiles = []
        pe = pefile.PE(exe, fast_load=True)
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            bitness = 32
        else:
            bitness = 64
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll in supported_dlls:
                dllfiles.append(entry.dll.decode("ascii"))
        return (bitness, dllfiles)
    
    def is_exe_deployed(self, exe):
        for deploy in self.deployments:
            if os.path.abspath(exe) == os.path.abspath(deploy["exe"]):
                return True
        return False

class dxvk_tool_cli():
    def __init__(self, dx):
        self.dx = dx
    
    def run(self):
        print(f"dxvk-tool {self.dx.VERSION} by {self.dx.AUTHOR}")
        while True:
            if self._main_menu() == "EXIT":
                break
        print("exiting dxvk-tool")
    
    def _get_menu_input(self, menu):
        keys = menu.keys()
        self._print_menu(menu)
        while True:
            i = input()
            try:
                if i in keys or int(i) in keys:
                    return int(i)
            except ValueError:
                return i
    
    def _print_menu(self, menu):
        for k, v in menu.items():
            print(f"{k}:\t{v}")
    
    def _select_deployment(self):
        print("please select a deployment")
        menu = {}
        i = 1
        for d in self.dx.deployments:
            menu[i] = os.path.abspath(d["exe"])
            i += 1
        return menu[self._get_menu_input(menu)]
    
    def _select_dxvk_tag(self):
        print("please select dxvk tag to install/update to\nleave empty for LATEST tag")
        menu = {}
        i = 1
        for tag in json.loads(requests.get(self.dx.DXVK_RELEASES).content):
            menu[i] = tag["tag_name"]
            i += 1
        try:
            return menu[self._get_menu_input(menu)]
        except KeyError:
            return self.dx.LATEST_TAG
    
    def _edit_bitness(self, o_b):
        supported_bitness = {
            1 : "32bit" if o_b == 64 else "32bit[X]",
            2 : "64bit" if o_b == 32 else "64bit[X]",
        }
        val = {
            1: 32,
            2: 64,
        }
        print("please select a bitness:")
        return val[self._get_menu_input(supported_bitness)]
    
    def _commaseparated_input(self, menu):
        print("please select a number of files to deploy as a comma separated list eg. 1,2,3,4,5,")
        keys = menu.keys()
        self._print_menu(menu)
        ok = False
        while ok == False:
            rtn = []
            i = input()
            il = i.split(",")
            for l in il:
                try:
                    if int(l) in keys:
                        rtn.append(int(l))
                except ValueError:
                    pass
            if len(rtn) != 0:
                ok = True
        return rtn

    def _edit_dllfiles(self, o_d):
        supported_dlls = {
                1 : "d3d9.dll" if "d3d9.dll" not in o_d else "d3d9.dll[X]", 
                2 : "d3d10core.dll" if "d3d10core.dll" not in o_d else "d3d10core.dll[X]",
                3 : "d3d11.dll" if "d3d11.dll" not in o_d else "d3d11.dll[X]",
                4 : "dxgi.dll" if "dxgi.dll" not in o_d else "dxgi.dll[X]",
        }
        val = {
                1 : "d3d9.dll", 
                2 : "d3d10core.dll",
                3 : "d3d11.dll",
                4 : "dxgi.dll",
        }
        rtn = []
        fl = self._commaseparated_input(supported_dlls)
        for f in fl:
            rtn.append(val[f])
        return rtn
        
    def _edit_bitness_and_files(self, exe, bitness, dllfiles):
        n_b = 0
        n_d = []
        ok = False
        print(f"automatic detection for '{exe}':\n\tbitness: {bitness}\n\tdll files: {'\n\t\t'.join(dllfiles)}")
        while ok == False:
            print("enter a number:")
            menu = {
                0 : "OK",
                1 : "edit bitness",
                2 : "edit dll files",
            }
            i = self._get_menu_input(menu)
            if i == 0 or i == "":
                ok = True
            elif i == 1:
                n_b = self._edit_bitness(bitness if n_b == 0 else n_b)
            elif i == 2:
                n_d = self._edit_dllfiles(dllfiles if len(n_d) == 0 else n_d)
        return (bitness if n_b == 0 else n_b, dllfiles if len(n_d) == 0 else n_d)
    
    def _create_deployment(self):
        print("creating an deployment:")
        print("please enter the path to your game executable:")
        while True:
            i = input().replace('"', '')
            if os.path.isfile(i) == True and os.path.abspath(i).endswith(".exe") == True:
                break
        exe = i
        bitness, dllfiles = self.dx.parse_exe(exe)
        bitness, dllfiles = self._edit_bitness_and_files(exe, bitness, dllfiles)
        tag = self._select_dxvk_tag()
        dxvkconf = self._get_dxvkconf_input()
        self.dx.install_dxvk(exe, bitness, tag, files=dllfiles, dxvkconf=dxvkconf)
    
    def _update_all(self):
        print("updating all deployments")
        tag = self._select_dxvk_tag()
        self.dx.update_all_dxvk(tag)
    
    def _update(self):
        print("updating deployment")
        exe = self._select_deployment()
        tag = self._select_dxvk_tag()
        self.dx.update_dxvk(exe, tag)
    
    def _list_deployments(self):
        print("deployments:")
        for d in self.dx.deployments:
            print(f"\t{os.path.abspath(d['exe'])}\n\t\tbitness: {d['bitness']}\ttag: {d['tag']}\tfiles: {d["files"]}")
    
    def _list_dxvk_cache(self):
        print("dxvk tags in cache:")
        for tag, file in self.dx.dxvk_cache.items():
            p = os.path.abspath(f"{self.dx.CACHE_DIR}/{file}")
            print(f"\t{tag}\tfile: {p}\tsize: {os.stat(p).st_size / (1024 * 1024)}MiB")
    
    def _clear_dxvk_cache(self):
        print(f"clearing {len(self.dx.dxvk_cache)} dxvk tags from cache")
        shutil.rmtree(self.dx.CACHE_DIR)
        os.mkdir(self.dx.CACHE_DIR)
        self.dx.dxvk_cache = {}
        self.dx.save_dxvk_cache()
    
    def _multiline_input(self):
        data = []
        run = True
        while run == True:
            try:
                i = input()
                data.append(str(i))
            except KeyboardInterrupt:
                run = False
        return data
    
    def _get_dxvkconf_input(self):
        ok = False
        while ok == False:
            print("please enter the dxvk.conf you want, line by line and finish with CTRL+C")
            data = self._multiline_input()
            print("your dxvk.conf will look like this:")
            for line in data:
                print(f"\t{line}")
            print("press enter to accept or press CTRL+C to start inputting your dxvk.conf over")
            try:
                input()
                ok = True
            except KeyboardInterrupt:
                pass
        return "\n".join(data)

    def _main_menu(self):
        print("main menu:")
        menu = {
            1: "list dxvk deployments",
            2: "create dxvk deployment",
            3: "remove deployment",
            4: "update deployment",
            5: "update all dxvk deployments",
            6: "list dxvk cache",
            7: "clear dxvk cache",
            "q": "exit"
        }
        i = self._get_menu_input(menu)
        if i == 1:
            self._list_deployments()
        elif i == 2:
            self._create_deployment()
        elif i == 3:
            if len(self.dx.deployments) == 0:
                print("no deployments founds!")
            else:
                self.dx.remove_dxvk(self._select_deployment())
        elif i == 4:
            if len(self.dx.deployments) == 0:
                print("no deployments founds!")
            else:
                self._update()
        elif i == 5:
            if len(self.dx.deployments) == 0:
                print("no deployments founds!")
            else:
                self._update_all()
        elif i == 6:
            if len(self.dx.dxvk_cache) == 0:
                print("no dxvk caches found!")
            else:
                self._list_dxvk_cache()
        elif i == 7:
            if len(self.dx.dxvk_cache) == 0:
                print("no dxvk caches found!")
            else:
                self._clear_dxvk_cache()
        elif i == "q":
            return "EXIT"
        
if __name__ == "__main__":
    dx = dxvk_tool_cli(dxvk_tool())
    dx.run()
