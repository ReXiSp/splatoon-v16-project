from mitmproxy import http, ctx
from dicttoxml import dicttoxml
import bosscrypto
from datetime import datetime
import pytz
import os
import traceback
from xml.dom.minidom import parseString
import copy

# Secret
BOSS_AES_KEY = "PASTE_YOUR_BOSS_AES_KEY"
BOSS_HMAC_KEY = "PASTE_YOUR_BOSS_HMAC_KEY"

# Constants
SPL_V16_SCHDATA = "schdata"
SPL_V16_OPTDATA = "optdata"
SPL_V16_TASKSHEET = [SPL_V16_SCHDATA, SPL_V16_OPTDATA]

SPL_V16_PATH = "splatoon-v16/"

SPL_REGION_EUR = "zvGSM4kOrXpkKnpT"
SPL_REGION_USA = "rjVlM7hUXPxmYQJh"
SPL_REGION_JPN = "bb6tOEckvgZ50ciH"
SPL_REGION_LIST = [SPL_REGION_EUR, SPL_REGION_USA, SPL_REGION_JPN]

SPL_TITLEID_EUR = "0005000010176a00"
SPL_TITLEID_USA = "0005000010176900"
SPL_TITLEID_JPN = "0005000010162b00"
SPL_TITLEID = {
    SPL_REGION_EUR: SPL_TITLEID_EUR,
    SPL_REGION_USA: SPL_TITLEID_USA,
    SPL_REGION_JPN: SPL_TITLEID_JPN
}

SPL_V16_SPOOFURL = "https://splatoon-v16.spoof/"

SPL_TASKSHEET_TEMPLATE = {
    "TaskSheet": {
        "TitleId": "TITLE_ID",
        "TaskId": "TASK_ID",
        "ServiceStatus": "open",
        "Files": [
            # SPL_TASKSHEET_FILE_TEMPLATE
        ]
    }
}

SPL_TASKSHEET_FILE_TEMPLATE = {
    "Filename": "FILENAME",
    "DataId": 0,
    "Type": "AppData",
    "Url": "URL",
    "Size": 0,
    "Notify": {
        "New": "app",
        "LED": "false"
    }
}

spl_DataID = 0
bossDataMap = {
    SPL_REGION_EUR: {
        SPL_V16_SCHDATA: [
            {
                "fileName": "VSSetting.byaml",
                "path": SPL_V16_PATH
            }
        ],
        SPL_V16_OPTDATA: [
            {
                "fileName": "Festival3003.byaml",
                "path": SPL_V16_PATH + "EUR/"
            },
            {
                "fileName": "HapTexture3003.bfres",
                "path": SPL_V16_PATH + "EUR/"
            },
            {
                "fileName": "PanelTexture3003.bfres",
                "path": SPL_V16_PATH + "EUR/"
            }
        ],
    },
    SPL_REGION_JPN: {
        SPL_V16_SCHDATA: [
            {
                "fileName": "VSSetting.byaml",
                "path": SPL_V16_PATH
            }
        ],
        SPL_V16_OPTDATA: [
            {
                "fileName": "Festival1003.byaml",
                "path": SPL_V16_PATH + "JPN/"
            },
            {
                "fileName": "HapTexture1003.bfres",
                "path": SPL_V16_PATH + "JPN/"
            },
            {
                "fileName": "PanelTexture1003.bfres",
                "path": SPL_V16_PATH + "JPN/"
            }
        ],
    },
    SPL_REGION_USA: {
        SPL_V16_SCHDATA: [
            {
                "fileName": "VSSetting.byaml",
                "path": SPL_V16_PATH
            }
        ],
        SPL_V16_OPTDATA: [
            {
                "fileName": "Festival2003.byaml",
                "path": SPL_V16_PATH + "USA/"
            },
            {
                "fileName": "HapTexture2003.bfres",
                "path": SPL_V16_PATH + "USA/"
            },
            {
                "fileName": "PanelTexture2003.bfres",
                "path": SPL_V16_PATH + "USA/"
            }
        ],
    }
}

def is_v16_task(url: str) -> list:
    for region in SPL_REGION_LIST:
        for tasksheet in SPL_V16_TASKSHEET:
            if f"p01/tasksheet/1/{region}/{tasksheet}" in url:
                return [region, tasksheet]

    return ["", ""]

def get_bossdata(region: str, task: str):
    return bossDataMap[region][task]

def get_bossdata_from_name(region: str, name: str):
    for data in bossDataMap[region][SPL_V16_SCHDATA]:
        if data["fileName"] == name:
            return data
    for data in bossDataMap[region][SPL_V16_OPTDATA]:
        if data["fileName"] == name:
            return data
    return None

def make_fake_tasksheet(region: str, task: str):
    global spl_DataID
    bossData = get_bossdata(region, task)

    fakeDict = copy.deepcopy(SPL_TASKSHEET_TEMPLATE)
    fakeDict["TaskSheet"]["TitleId"] = SPL_TITLEID[region]
    fakeDict["TaskSheet"]["TaskId"] = task

    if "Files" not in fakeDict["TaskSheet"] or not isinstance(fakeDict["TaskSheet"]["Files"], list):
        fakeDict["TaskSheet"]["Files"] = []

    for boss in bossData:
        ctx.log.info(f"Spoof for {boss['fileName']}")
        fileData = copy.deepcopy(SPL_TASKSHEET_FILE_TEMPLATE)
        fileData["DataId"] = spl_DataID
        spl_DataID += 1
        open(SPL_V16_PATH + ".id", "w").write(str(spl_DataID))
        fileData["Filename"] = boss["fileName"]
        fileData["Size"] = len(boss["raw"])
        fileData["Url"] = SPL_V16_SPOOFURL + region + "/" + boss["fileName"]
        fakeDict["TaskSheet"]["Files"].append(fileData)

    my_item_func = lambda x: "File"
    taskSheetXML = parseString(dicttoxml(fakeDict, root=False, attr_type=False, item_func=my_item_func)).toprettyxml(indent="", encoding="UTF-8", newl="")
    # print(parseString(taskSheetXML).toprettyxml(indent="  "))
    now_utc = datetime.now(pytz.utc)
    fmt = now_utc.strftime("%a, %d %b %Y %H:%M:%S GMT")
    return http.Response.make(
        200,
        taskSheetXML,
        {
            "Content-Type": "text/xml",
            "Content-Length": str(len(taskSheetXML)),
            "Accept-Ranges": "bytes",
            "Cache-Control": "public, max-age=0",
            "Last-Modified": fmt,
            "Server": "cloudflare",
            "X-Powered-By": "Express",
            "Date": fmt
        }
    )

def load_bossfiles():
    ctx.log.info("Loading Boss Files...")
    for region in SPL_REGION_LIST:
        for task in SPL_V16_TASKSHEET:
            for data in bossDataMap[region][task]:
                try:
                    data["raw"] = bosscrypto.encrypt_wiiu(data["path"] + data["fileName"], BOSS_AES_KEY, BOSS_HMAC_KEY)
                    ctx.log.info(f"Loaded {data['fileName']}")
                except Exception as e:
                    traceback.print_exc()

class PretendoAddon:
    def load(self, loader) -> None:
        global spl_DataID
        loader.add_option(
            name="pretendo_redirect",
            typespec=bool,
            default=True,
            help="Redirect all requests from Nintendo to Pretendo",
        )

        loader.add_option(
            name="pretendo_host",
            typespec=str,
            default="",
            help="Host to send Pretendo requests to (keeps the original host in the Host header)",
        )

        loader.add_option(
            name="pretendo_host_port",
            typespec=int,
            default=80,
            help="Port to send Pretendo requests to (only applies if pretendo_host is set)",
        )

        loader.add_option(
            name="pretendo_http",
            typespec=bool,
            default=False,
            help="Sets Pretendo requests to HTTP (only applies if pretendo_host is set)",
        )

        loader.add_option(
            name="splatoon_early_spoof",
            typespec=bool,
            default=False,
            help="spoon",
        )

        load_bossfiles()

        spl_DataID = int(open(SPL_V16_PATH + ".id", "r").read())
        ctx.log.info("Data ID Loaded: " + str(spl_DataID))

        # Test
        ctx.log.info("Testing fake...")
        # fake = make_fake_tasksheet(SPL_REGION_EUR, SPL_V16_SCHDATA)
        # ctx.log.info(fake.content)
        ctx.log.info("Testing get_bossdata_from_name")
        ctx.log.info("Found " + get_bossdata_from_name(SPL_REGION_EUR, "VSSetting.byaml")["fileName"])

    def request(self, flow: http.HTTPFlow) -> None:
        if ctx.options.pretendo_redirect:
            if "nintendo.net" in flow.request.pretty_host:
                flow.request.host = flow.request.pretty_host.replace(
                    "nintendo.net", "pretendo.cc"
                )
            elif "nintendowifi.net" in flow.request.pretty_host:
                flow.request.host = flow.request.pretty_host.replace(
                    "nintendowifi.net", "pretendo.cc"
                )

            if ctx.options.pretendo_http:
                flow.request.scheme = "http"

            if ctx.options.pretendo_host and (
                "pretendo.cc" in flow.request.pretty_host
                or "pretendo.network" in flow.request.pretty_host
                or "pretendo-cdn.b-cdn.net" in flow.request.pretty_host
            ):
                original_host = flow.request.host_header
                flow.request.host = ctx.options.pretendo_host
                flow.request.port = ctx.options.pretendo_host_port
                flow.request.host_header = original_host

                if ctx.options.pretendo_http:
                    flow.request.scheme = "http"

        if ctx.options.splatoon_early_spoof:
            ctx.log.info(flow.request.url)

            v16 = is_v16_task(flow.request.url)
            if v16[0] != "":
                # It is v16 tasksheet
                ctx.log.info("Splatoon v16 tasksheet detected; Spoofing...")
                flow.response = make_fake_tasksheet(v16[0], v16[1])
                ctx.log.info("Spoofed.")

        if "api/content/agreements/Nintendo-Network-EULA" in flow.request.url:
            # Spoof EULA
            try:
                with open(SPL_V16_PATH + "eula.xml", "r", encoding="utf-8") as f:
                    eulaContent = f.read().encode("utf-8")
                    flow.response = http.Response.make(
                        200,
                        eulaContent,
                        {
                            "Content-Type": "application/xml; charset=utf-8",
                            # "Cache-Control": "no-cache", 
                            "Content-Length": str(len(eulaContent))
                        }
                    )
                    ctx.log.info("Custom EULA response sent.")
            except Exception as e:
                print(e)

        # Spoofed Request
        if flow.request.url.startswith(SPL_V16_SPOOFURL):
            ctx.log.info("Got spoofed request.")
            region = ""
            for r in SPL_REGION_LIST:
                if r in flow.request.url:
                    region = r
                    break
            data = get_bossdata_from_name(region, os.path.basename(flow.request.url))
            if data:
                ctx.log.info(f"Found {data['fileName']}. Sending")
                flow.response = http.Response.make(
                    200,
                    data["raw"],
                    {
                        "Content-Type": "applicatoin/octet-stream", # nintendo's typo.
                        "Content-Disposition": "attachment",
                        "Content-Transfer-Encoding": "binary",
                        "Content-Length": str(len(data["raw"]))
                    }
                )
            else:
                ctx.log.error(f"Data not found: {os.path.basename(flow.request.url)}")


addons = [PretendoAddon()]
