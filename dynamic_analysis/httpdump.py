from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import io
import json
import time


def item(package_name, id_, url, method, content, log=""):
    return {
        "package_name": package_name,
        "traffic_id": id_,
        "url": url,
        "request_method": method,
        "content": content,
        "encrypt_flag": "",
        "third_party_flag": "1",
        "plaintext": "",
        "hook_func_signature": "",
        "traffic_keyword": "",
        "log": log,
    }


class HTTPDump:
    def __init__(self) -> None:
        self.t = time.strftime("%Y-%m-%d_%H_%M_%S", time.localtime())

    def load(self, loader):
        loader.add_option(
            name="pkg_name",
            typespec=str,
            default="",
            help="Add a count header to responses",
        )

        loader.add_option(
            name="apk_name",
            typespec=str,
            default="",
            help="Add a count header to responses",
        )

    def request(self, flow: http.HTTPFlow):
        pkg_name = ""
        apk_name = ""
        if len(ctx.options.pkg_name) > 0:
            pkg_name = ctx.options.pkg_name
        if len(ctx.options.apk_name) > 0:
            apk_name = ctx.options.apk_name
        flow_id = flow.id
        flow_path = flow.request.url
        query2dict = {}
        for k in flow.request.query.keys():
            query2dict[k] = flow.request.query.get(k)
        flow_content = {"query": query2dict, "content": flow.request.content.decode("utf-8")}
        flow_item = item(
            pkg_name, flow_id, flow_path, flow.request.method, str(flow_content)
        )
        with open(
            f"./result_huawei/{pkg_name}-{apk_name}-simple.txt",
            "a",
            encoding="utf-8",
        ) as f:
            f.write(json.dumps(flow_item) + "\n")

    def running(self):
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        # 同mitmweb导出的文件，有flow的完整信息
        pkg_name = ""
        apk_name = ""
        if len(ctx.options.pkg_name) > 0:
            pkg_name = ctx.options.pkg_name
        if len(ctx.options.apk_name) > 0:
            apk_name = ctx.options.apk_name
        with open(f"./result_huawei/{pkg_name}-{apk_name}-{self.t}-verbose.txt", "wb") as f:
            w = io.FlowWriter(f)
            w.add(flow)

    def done(self):
        pass


addons = [HTTPDump()]

