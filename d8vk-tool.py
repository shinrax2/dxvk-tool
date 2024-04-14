# d8vk-tool by shinrax2

# std lib
import json
import sys
import os
import tarfile
import shutil

# pip packages
import pefile # pefile
import requests # requests

class d8vk_tool():
    D8VK_LATEST = "https://api.github.com/repos/AlpyneDreams/d8vk/releases/latest"
    D8VK_TAG = "https://api.github.com/repos/AlpyneDreams/d8vk/releases/tags/{0}"
    D8VK_RELEASES = "https://api.github.com/repos/AlpyneDreams/d8vk/releases"
    CACHE_DIR = "./d8vk_cache"
    D8VK_CACHE_FILE = "./d8vk_cache.json"
    DEPLOYMENTS_FILE = "./d8vk_deployments.json"
    VERSION = "v0.1"
    AUTHOR = "shinrax2"
    
    def __init__(self):
        try:
            with open(self.DEPLOYMENTS_FILE, "r", encoding="utf-8") as f:
                self.deployments = json.loads(f.read())
        except (json.JSONDecodeError, IOError):
            self.deployments = []

        try:
            with open(self.D8VK_CACHE_FILE, "r", encoding="utf-8") as f:
                self.d8vk_cache = json.loads(f.read())
        except (json.JSONDecodeError, IOError):
            self.d8vk_cache = {}
        if os.path.isdir(self.CACHE_DIR) == False:
            os.mkdir(self.CACHE_DIR)
        self.LATEST_TAG = ""
        self.resolve_latest()
    
    def resolve_latest(self):
        self.LATEST_TAG = json.loads(requests.get(self.D8VK_LATEST).content)["tag_name"]
    
    def extract_d8vk(self, tag, file):
        dir = f"{self.CACHE_DIR}/{tag}"
        file = f"{self.CACHE_DIR}/{file}"
        files32 = [
            "x32/d3d8.dll"
        ]
        if os.path.isdir(dir) == False:
            os.mkdir(dir)
        os.mkdir(f"{dir}/32")
        with tarfile.open(file, "r:gz") as tf:
            for f in files32:
                with open(f"{dir}/32/{os.path.basename(f)}", "wb") as fh:
                    fh.write(tf.extractfile(f).read())

    def save_d8vk_cache(self):
        with open(self.D8VK_CACHE_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.d8vk_cache, ensure_ascii=False))
            
    def save_deployments(self):
        with open(self.DEPLOYMENTS_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(self.deployments, ensure_ascii=False))

    def download_d8vk(self, tag=None):
        if len(self.d8vk_cache) != 0:
            k = self.d8vk_cache.keys()
        else:
            k = []
        chunk_size=98304
        if tag is not None:
            data = json.loads(requests.get(self.D8VK_TAG.format(tag)).content)
            tag = data["tag_name"]
        else:
            data = json.loads(requests.get(self.D8VK_TAG.format(self.LATEST_TAG)).content)
            tag = self.LATEST_TAG
        if tag not in k:
            print(f"downloading d8vk version '{tag}'")
            dl_url = None
            for asset in data["assets"]:
                if os.path.basename(asset["browser_download_url"]).startswith("d8vk-") and os.path.basename(asset["browser_download_url"]).endswith(".tar.gz"):
                    dl_url = asset["browser_download_url"]
                    break
            local_filename = f"{self.CACHE_DIR}/{os.path.basename(dl_url)}"
            with requests.get(dl_url, stream=True) as r:
                    r.raise_for_status()
                    with open(local_filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=chunk_size): 
                            if chunk:
                                f.write(chunk)
            self.d8vk_cache[tag] = os.path.basename(dl_url)
            self.extract_d8vk(tag, os.path.basename(dl_url))
            self.save_d8vk_cache()
        else:
            print(f"d8vk version '{tag}' already in cache")

    def install_d8vk(self, exe, bitness, tag=None, files=[], dxvkconf=None):
        if self.is_exe_deployed(exe) == True:
            print(f"d8vk is already deployed for '{exe}'")
            return
        if tag is None:
            tag = self.LATEST_TAG
        self.download_d8vk(tag)
        cdir = f"{self.CACHE_DIR}/{tag}/{bitness}"
        exedir = os.path.dirname(exe)
        print(f"installing d8vk '{tag}'({bitness}bit) to '{exedir}'")
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
    
    def remove_d8vk(self, exe):
        if self.is_exe_deployed == False:
            print(f"no d8vk deployed for '{exe}'")
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
    
    def update_d8vk(self, exe, tag=None):
        if self.is_exe_deployed == False:
            print(f"no d8vk deployed for '{exe}'")
            return 
        if tag is None:
            tag = self.LATEST_TAG
        for deploy in self.deployments:
            if os.path.abspath(exe) == os.path.abspath(deploy["exe"]):
                d = deploy
        self.remove_d8vk(exe)
        self.install_d8vk(d["exe"], d["bitness"], tag, files=d["files"], d8vkconf=d["d8vkconf"])
    
    def update_all_d8vk(self, tag=None):
        if tag is None:
            tag = self.LATEST_TAG
        for d in self.deployments:
            self.update_d8vk(d[exe], tag)
    
    def list_deployments(self):
        for d in self.deployments:
            print(d)
    
    def parse_exe(self, exe):
        supported_dlls = [b"d3d8.dll"]
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

class d8vk_tool_cli():
    def __init__(self, dx):
        self.dx = dx
    
    def run(self):
        print(f"d8vk-tool {self.dx.VERSION} by {self.dx.AUTHOR}")
        while True:
            if self.main_menu() == "EXIT":
                break
        print("exiting d8vk-tool")
    
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
    
    def _select_d8vk_tag(self):
        print("please select d8vk tag to install/update to\nleave empty for LATEST tag")
        menu = {}
        i = 1
        for tag in json.loads(requests.get(self.dx.D8VK_RELEASES).content):
            menu[i] = tag["tag_name"]
            i += 1
        try:
            return menu[self._get_menu_input(menu)]
        except KeyError:
            return self.dx.LATEST_TAG
    
    
    def _create_deployment(self):
        print("creating an deployment:")
        print("please enter the path to your game executable:")
        while True:
            i = input().replace('"', '')
            if os.path.isfile(i) == True and os.path.abspath(i).endswith(".exe") == True:
                break
        exe = i
        bitness, dllfiles = self.dx.parse_exe(exe)
        tag = self._select_d8vk_tag()
        self.dx.install_d8vk(exe, bitness, tag, files=dllfiles)
    
    def _update_all(self):
        print("updating all deployments")
        tag = self._select_d8vk_tag()
        self.dx.update_all_d8vk(tag)
    
    def _update(self):
        print("updating deployment")
        exe = self._select_deployment()
        tag = self._select_d8vk_tag()
        self.dx.update_d8vk(exe, tag)
    
    def _list_deployments(self):
        print("deployments:")
        for d in self.dx.deployments:
            print(f"\t{os.path.abspath(d['exe'])}\n\t\tbitness: {d['bitness']}\ttag: {d['tag']}\tfiles: {d["files"]}")
    
    def _list_d8vk_cache(self):
        print("d8vk tags in cache:")
        for tag, file in self.dx.d8vk_cache.items():
            p = os.path.abspath(f"{self.dx.CACHE_DIR}/{file}")
            print(f"\t{tag}\tfile: {p}\tsize: {os.stat(p).st_size / (1024 * 1024)}MiB")
    
    def _clear_d8vk_cache(self):
        print(f"clearing {len(self.dx.d8vk_cache)} d8vk tags from cache")
        shutil.rmtree(self.dx.CACHE_DIR)
        os.mkdir(self.dx.CACHE_DIR)
        self.dx.d8vk_cache = {}
        self.dx.save_d8vk_cache()
    
    def main_menu(self):
        print("main menu:")
        menu = {
            1: "list d8vk deployments",
            2: "create d8vk deployment",
            3: "remove deployment",
            4: "update deployment",
            5: "update all d8vk deployments",
            6: "list d8vk cache",
            7: "clear d8vk cache",
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
                self.dx.remove_d8vk(self._select_deployment())
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
            if len(self.dx.d8vk_cache) == 0:
                print("no d8vk caches found!")
            else:
                self._list_d8vk_cache()
        elif i == 7:
            if len(self.dx.d8vk_cache) == 0:
                print("no d8vk caches found!")
            else:
                self._clear_d8vk_cache()
        elif i == "q":
            return "EXIT"
        
if __name__ == "__main__":
    dx = d8vk_tool_cli(d8vk_tool())
    dx.run()
