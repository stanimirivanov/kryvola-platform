"""Explicit synthetic-data overlay: real policies/CSI, no host-hardening claims."""

import copy

if __package__:
    from . import m1_preproduction as profile
else:
    import m1_preproduction as profile


def build(images):
    base = profile.build(images)["items"]
    items = [copy.deepcopy(x) for x in base if x["kind"] != "PodTemplate"]
    for identity in items:
        if identity["kind"] == "ClusterSPIFFEID":
            identity["metadata"]["labels"] = {
                "spire.spiffe.io/class-name": identity["spec"]["className"]
            }
    for source in base:
        if source["kind"] != "PodTemplate" or source["metadata"]["name"] == "messaging":
            continue
        role = source["metadata"]["name"]
        pod = copy.deepcopy(source["template"])
        pod.update(apiVersion="v1", kind="Pod")
        pod["metadata"] = copy.deepcopy(source["metadata"]) | copy.deepcopy(
            source["template"]["metadata"]
        )
        spec = pod["spec"]
        # KIND shares its host kernel: never mint audited core/swap labels.
        spec["nodeSelector"] = {
            k: v for k, v in spec["nodeSelector"].items() if k.endswith("/domain")
        }
        for volume in spec["volumes"]:
            if "persistentVolumeClaim" in volume:
                volume.clear()
                volume.update(name="private", emptyDir={"medium": "Memory", "sizeLimit": "8Mi"})
        if role == "workflow":
            spec["volumes"] = [v for v in spec["volumes"] if v["name"] != "role-config"]
        for c in spec["containers"]:
            c["imagePullPolicy"] = "IfNotPresent"
            c["command"] = ["python3", "-c", "import time;time.sleep(3600)"]
            if role == "workflow":
                c["volumeMounts"] = [v for v in c["volumeMounts"] if v["name"] != "role-config"]
        spec["volumes"].append(
            {"name": "probe", "configMap": {"name": "isolation-probe", "defaultMode": 292}}
        )
        for c in spec["containers"]:
            c["volumeMounts"] = copy.deepcopy(c["volumeMounts"])
            c["volumeMounts"].append(
                {"name": "probe", "mountPath": "/run/isolation", "readOnly": True}
            )
        if role == "compute":
            # Trusted instrumenter shares the real worker's Pod UID, SA and UID.
            # Native worker filesystem is inventoried separately in Engine.
            helper = copy.deepcopy(spec["containers"][0])
            helper.update(name="instrumenter", image=images["runtime"])
            spec["containers"] = [spec["containers"][0], helper]
        if role == "runtime":
            code = (
                "import sys,asyncio,pathlib,shutil;"
                "sys.path.insert(0,'/run/m1-launch');import service;"
                "p=pathlib.Path('/run/m1-state/config');p.mkdir(exist_ok=True);"
                "[shutil.copyfile('/run/m1-secrets/'+n,p/n) for n in ('database','s3.json')];"
                '(p/\'policy.json\').write_text(\'{"boot_id":"unstarted","grants":[]}\');'
                "service.SECRETS=p;asyncio.run(service.runtime())"
            )
            spec["containers"][0]["command"] = ["python", "-c", code]
        for c in spec["containers"]:
            c["command"] = ["python3", "/run/m1-launch/launch.py", *c["command"]]
        items.append(pod)
    return items
