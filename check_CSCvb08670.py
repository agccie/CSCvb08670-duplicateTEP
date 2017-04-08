#!/usr/bin/python2.7

import subprocess, sys, traceback, logging, os
import time, re, json

# ensure check_output is available
if not hasattr(subprocess, "check_output"):
    m = """
    When executing from the APIC, you must use the python2.7 library:
        /usr/bin/python2.7 %s
    """ % __file__
    sys.exit(m)

logger = logging.getLogger(__name__)

OFFLINE_OBJECTS = [ "dhcpLease", "dhcpPool", "opflexODev", "topSystem"]
OFFLINE_FILES = {}
OFFLINE_MODE = False

###############################################################################
# lib functions
###############################################################################

def setup_logger(**kwargs):
    global logger
    logging_level = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARN,
        "error": logging.ERROR,
        logging.DEBUG: logging.DEBUG,
        logging.INFO: logging.INFO,
        logging.WARN: logging.WARN,
        logging.ERROR: logging.ERROR
    }.get(kwargs.get("logging_level", logging.DEBUG), logging.DEBUG)
    logger.setLevel(logging_level)
    logger_handler = logging.StreamHandler(sys.stdout)

    fmt ="%(asctime)s.%(msecs).03d||%(levelname)s||"
    fmt+="(%(lineno)d)||%(message)s"
    logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%dT%H:%M:%S")
    )
    logger.addHandler(logger_handler)

def offline_extract(tgz, **kwargs):
    """ 
    extract files in tar bundle to tmp directory.  Only files matching
    provided offline_keys dict (which is also used as key in returned dict)
    """
    offline_files = {}
    offline_dir = kwargs.get("offline_dir", "/tmp/")
    offline_keys = kwargs.get("offline_keys", {})
    import tarfile
    # force odir to real directory (incase 'file' is provided as offline_dir)
    odir = os.path.dirname(offline_dir)
    try:
        t = tarfile.open(tgz, "r:gz")
        for m in t.getmembers():
            # check for files matching offline_keys
            for tn in offline_keys:
                if "%s." % tn in m.name:
                    offline_files[tn] = "%s/%s" % (odir, m.name)
                    t.extract(m, path=odir)
                    logging.debug("extracting %s/%s" % (odir, m.name))
                    break

    except Exception as e:
        logging.error("Failed to extract content from offline tar file")
        import traceback
        traceback.print_exc()
        sys.exit()
    
    return offline_files

def get_cmd(cmd):
    """ return output of shell command, return None on error"""
    try:
        logger.debug("get_cmd: %s" % cmd)
        return subprocess.check_output(cmd, shell=True, 
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        logger.warn("error executing command: %s" % e)
        return None

def pretty_print(js):
    """ try to convert json to pretty-print format """
    try:
        return json.dumps(js, indent=4, separators=(",", ":"))
    except Exception as e:
        return "%s" % js

def icurl(url, **kwargs):
    """ perform icurl for object/class based on relative dn and 
        return json object.  Returns None on error
    """    
    
    # default page size handler and timeouts
    page_size = kwargs.get("page_size", 75000)
    page = 0
    
    # build icurl command
    url_delim = "?"
    if "?" in url: url_delim="&"

    # walk through pages until return count is less than page_size
    results = []
    while 1:
        turl = "%s%spage-size=%s&page=%s" % (url, url_delim, page_size, page)
        logger.debug("icurl: %s" % turl)
        tstart = time.time()
        try:
            resp = get_cmd("icurl -s http://127.0.0.1:7777/%s" % turl)
        except Exception as e:
            logger.warn("exception occurred in get request: %s" % (
                traceback.format_exc()))
            return None
        logger.debug("response time: %f" % (time.time() - tstart))
        if resp is None:
            logger.warn("failed to get data: %s" % url)
            return None
        try:
            js = json.loads(resp)
            if "imdata" not in js or "totalCount" not in js:
                logger.error("failed to parse js reply: %s" % pretty_print(js))
                return None
            results+=js["imdata"]
            logger.debug("results count: %s/%s"%(len(results),js["totalCount"]))
            if len(js["imdata"])<page_size or \
                len(results)>=int(js["totalCount"]):
                logger.debug("all pages received")
                return results
            page+= 1
        except ValueError as e:
            logger.error("failed to decode resp: %s" % resp)
            return None
    return None

def get_dn(dn, **kwargs):
    # get a single dn
    opts = build_query_filters(**kwargs)
    url = "/api/mo/%s.json%s" % (dn,opts)
    results = icurl(url, **kwargs)
    if results is not None:
        if len(results)>0: return results[0]
        else: return {} # empty non-None object implies valid empty response
    return None

def get_class(classname, **kwargs):
    # perform class query

    # support offline for class query only for now
    if OFFLINE_MODE:
        if classname not in OFFLINE_FILES: 
            logger.error("%s not found in offline files" % classname)
            return None
        fname = OFFLINE_FILES[classname]
        try:
            logger.debug("reading file %s" % fname)
            with open(fname, "r") as f:
                js = json.loads(f.read())
                if "imdata" not in js or "totalCount" not in js:
                    logger.error("failed to parse js reply: %s" % (
                        pretty_print(js)))
                    return None
                return js["imdata"]
        except ValueError as e:
            logger.error("failed to decode resp: %s" % f.read())
        except Exception as e:
            logging.error("unabled to read %s: %s" % (fname,e))
            return None
    
    opts = build_query_filters(**kwargs)
    url = "/api/class/%s.json%s" % (classname, opts)
    return icurl(url, **kwargs)

def build_query_filters(**kwargs):
    """
        queryTarget=[children|subtree]
        targetSubtreeClass=[mo-class]
        queryTargetFilter=[filter]
        rspSubtree=[no|children|full]
        rspSubtreeInclude=[attr]
        rspPropInclude=[all|naming-only|config-explicit|config-all|oper]
    """
    queryTarget         = kwargs.get("queryTarget", None)
    targetSubtreeClass  = kwargs.get("targetSubtreeClass", None)
    queryTargetFilter   = kwargs.get("queryTargetFilter", None)
    rspSubtree          = kwargs.get("rspSubtree", None)
    rspSubtreeInclude   = kwargs.get("rspSubtreeInclude", None)
    rspPropInclude      = kwargs.get("rspPropInclude", None)
    opts = ""
    if queryTarget is not None:
        opts+= "&query-target=%s" % queryTarget
    if targetSubtreeClass is not None:
        opts+= "&target-subtree-class=%s" % targetSubtreeClass
    if queryTargetFilter is not None:
        opts+= "&query-target-filter=%s" % queryTargetFilter
    if rspSubtree is not None:
        opts+= "&rsp-subtree=%s" % rspSubtree
    if rspSubtreeInclude is not None:
        opts+= "&rsp-subtree-include=%s" % rspSubtreeInclude
    if rspPropInclude is not None:
        opts+= "&rsp-prop-include=%s" % rspPropInclude

    if len(opts)>0: opts = "?%s" % opts.strip("&")
    return opts

def ipv4_to_int(oipv4):
    """ convert ipv4 address to integer 
        return None on error
    """
    # strip prefix if present
    ipv4 = re.sub("/[0-9]+","",oipv4) 
    ipv4 = ipv4.split(".")
    if len(ipv4)!=4:
        logger.debug("invalid ipv4 address: %s" %oipv4)
        return None
    for x in xrange(0,4):
        ipv4[x] = int(ipv4[x])
        i = ipv4[x]
        if i<0 or i>255:
            logger.debug("invalid octect %s in %s" % (i, opiv4))
            return None
    return (ipv4[0]<<24) + (ipv4[1]<<16) + (ipv4[2]<<8) + ipv4[3]

def ipv4_to_str(ipv4):
    """ convert ipv4 integer to string """
    return "%s.%s.%s.%s" % (
        (ipv4 & 0xff000000) >> 24,
        (ipv4 & 0x00ff0000) >> 16,
        (ipv4 & 0x0000ff00) >> 8,
        (ipv4 & 0x000000ff)
    )
    

###############################################################################
# CSCvb08670 specific checks
###############################################################################

def get_nodes():
    """ get all active nodes and vnodes in fabric, and return dict indexed
        by address. Also, return dict of duplicate IP's
        return (nodes, dups)
            where each n has following attributes: {
                "id"
                "address"
                "address_str"
                "name"
                "role":
                "clientId":  expected clientId for this node (diff for vleaf)
            }
        returns None on error
        
    """
    nodes = {}      # indexed by ip
    dups = {}       # indexed by ip

    # get spine/leafs first
    fnodes = get_class("topSystem")
    if fnodes is None:
        logger.error("failed to get topSystem")
        return (None,None)
    node_regex = "topology/pod-[0-9]+/node-(?P<node>[0-9]+)/"
    for obj in fnodes:
        if "attributes" in obj[obj.keys()[0]]:
            attr = obj[obj.keys()[0]]["attributes"]
            for r in ["dn", "address", "role", "name", "serial"]:
                if r not in attr:
                    logger.error("missing %s, invalid object: %s" % (
                        r, pretty_print(obj)))
                    return (None,None)
            if attr["role"] != "spine" and attr["role"] != "leaf":
                logger.debug("skipping role: %s, %s" % (
                    attr["role"], attr["dn"]))
                continue
            r1 = re.search(node_regex, attr["dn"])
            if r1 is None:
                logger.error("failed to determine node-id from: %s" % (
                    attr["dn"]))
                return (None,None)
            addr_str = "%s" % attr["address"]
            attr["address"] = ipv4_to_int(attr["address"])
            if attr["address"] is None:
                logger.error("failed to convert ipv4 address for %s" % obj)
                return (None,None)
            n = {
                "id": r1.group("node"),
                "address": attr["address"],
                "address_str": addr_str,
                "name": attr["name"],
                "role": attr["role"], 
                "clientId": attr["serial"]
            }
            if attr["address"] in nodes:
                o = nodes[attr["address"]]
                logger.info("%s is duplicate IP (%s, %s)" % (attr["address"],
                    nodes[attr["address"]], n))
                if attr["address"] not in dups: dups[attr["address"]] = [o]
                dups[attr["address"]].append(n) 
            else:
                logger.debug("adding %s to nodes" % n)
                nodes[attr["address"]] = n

    # get vleafs
    vnodes = get_class("opflexODev")
    if vnodes is None:
        logger.error("failed to get opflexODev")
        return (None,None)
    for obj in vnodes:
        if "attributes" in obj[obj.keys()[0]]:
            attr = obj[obj.keys()[0]]["attributes"]
            for r in ["ip", "mac", "hostName", "id", "compHvDn"]:
                 if r not in attr:
                    logger.error("missing %s, invalid object: %s" % (
                        r, pretty_print(obj)))
                    return (None,None)

            addr_str = "%s" % attr["ip"]
            attr["ip"] = ipv4_to_int(attr["ip"])
            if attr["ip"] is None:
                logger.error("failed to convert ipv4 address for %s" % obj)
                return (None,None)
            n = {
                "id": attr["id"],
                "address": attr["ip"],
                "address_str": addr_str,
                "name": "vleaf-host-%s" % attr["hostName"],
                "role": "vleaf",
                "clientId": "0x01%s" % re.sub(":","",attr["mac"]).lower()
            }
            if n["address"] in nodes:
                # if the mac is the same, then it's ok since opflexODev
                # built on multiple leafs
                o = nodes[n["address"]]
                if n["clientId"] == o["clientId"]: continue
                logger.info("%s is duplicate IP (%s, %s)" % (n["address"],
                    o, n))
                if attr["address"] not in dups: dups[attr["address"]] = [o]
                dups[attr["address"]].append(n)
            else:
                logger.debug("adding %s to nodes" % n)
                nodes[n["address"]] = n

    return (nodes, dups)

def get_leases():
    """ get all dhcp leases in mo and return dict indexed by address
        return (leases, dups)
            where each n has following attributes: {
                "address":
                "address_str":
                "clientId":
                "state":  (should be active)
            }
        return None on error
    """
    gclass = get_class("dhcpLease")
    if gclass is None:
        logger.error("failed to get dhcpLease")
        return (None, None)
    
    leases = {}
    dups = {}
    for obj in gclass:
        if "attributes" in obj[obj.keys()[0]]:
            attr = obj[obj.keys()[0]]["attributes"]
            for r in ["ip","clientId", "state"]:
                if r not in attr:
                    logger.error("missing %s, invalid object: %s" % (
                        r, pretty_print(obj)))
                    return (None,None)

            addr_str = "%s" % attr["ip"]
            attr["ip"] = ipv4_to_int(attr["ip"])
            if attr["ip"] is None:
                logger.error("failed to convert ipv4 address for %s" % obj)
                return (None,None)
            n = {
                "address": attr["ip"],
                "address_str": addr_str,
                "clientId": attr["clientId"],
                "state": attr["state"]
            }
            if n["address"] in leases:
                o = leases[n["address"]]
                # ignore duplicate leases for the same client
                if n["clientId"] == o["clientId"]: continue
                logger.info("%s is duplicate lease (%s, %s)" % (n["address"],
                    o, n))
                dups.append(n)
                if attr["address"] not in dups: dups[attr["address"]] = [o]
                dups[attr["address"]].append(n)
            else:
                logger.debug("adding %s to leases" % n)
                leases[n["address"]] = n

    return (leases, dups)

def get_pools():
    """ get all dhcp pools 
        returns a dict in following format {
            "start_ip": {
                "bad_lease":[],
                "good_lease":[],
                "type"
                "state" <- normal if any pool is normal
                "address"
                "pools": [{
                    "className": (pod, vleaf, vip, protectionchain,...)
                    "dn"
                    "id"
                    "type"  (should be recovery or normal)
                    "address"
                    "address_str"
                    "freeIPs"
                }]
            }
        }
        returns None on error
    """
    gclass = get_class("dhcpPool")
    if gclass is None:
        logger.error("failed to get dhcpPool")
        return None

    pools = {}
    for obj in gclass:
        if "attributes" in obj[obj.keys()[0]]:
            attr = obj[obj.keys()[0]]["attributes"]
            for r in ["className", "dn", "id", "type", "startIp", 
                "endIp", "freeIPs"]:
                if r not in attr:
                    logger.error("missing %s, invalid object: %s" % (
                        r, pretty_print(obj)))
                    return None
            ip = ipv4_to_int(attr["startIp"])
            if ip is None:
                logger.error("failed to convert ipv4 address for %s" % obj)
                return None
            p = {
                "className": attr["className"],
                "dn": attr["dn"],
                "id": attr["id"],
                "type": attr["type"],
                "address": ip,
                "address_str": attr["startIp"],
                "freeIPs": attr["freeIPs"]
            }
            if ip not in pools:
                pools[ip] = {"bad_lease":[], "good_lease":[], "pools":[],
                    "type":attr["className"], "state":"", "address":ip}
            pools[ip]["pools"].append(p)

    # loop through all entries in pool and update state
    for ip in pools:
        state = "recovery"
        for p in pools[ip]["pools"]:
            if p["type"]!="recovery": state = p["type"]
        pools[ip]["state"] = state
    return pools
                

def main(args):
    """ cross reference active nodes vs. leases to determine if:
        1) any dhcpLeases are in abandoned state
        2) any dhcpLeases MOs missing for corresponding node/vnode
        3) check for any nodes/vleafs with duplicate IP's
        4) for all leases that are freed/abandoned, cross reference
            corresponding pool to determine how many free IP's remain before
            a duplicate IP will be assigned
    """
    (nodes, dup_nodes) = get_nodes()
    (leases, dup_leases) = get_leases()
    pools = get_pools()
    if nodes is None or leases is None or pools is None or dup_nodes is None \
        or dup_leases is None:
        logger.error("failed to get nodes/leases/or pools")
        return False
    
    # add 'unknown' entry to pools for ip's we can't map a lease
    pools["unknown"] = {
        "pools":[],
        "address":"unknown",
        "state":"unknown",
        "type":"unknown",
        "good_lease":[],
        "bad_lease":[]
    }

    # start counting
    node_count = 0
    vleaf_count = 0
    bad_lease_count = 0
    bad_lease_count_recovery = 0
    freed_lease_count = 0
    freed_lease_count_recovery = 0
    pools_with_bad_lease = {}   # index by pool_ip
    
    for ip in nodes:
        n = nodes[ip]
        if n["role"] == "vleaf": vleaf_count+=1
        else: node_count+= 1

        # map ip to pool - add to unknown if can't find the pool
        # note, all pools are 32 ips so static mask
        pool_ip = ip & 0xffffffe0
        current_pool = pools["unknown"]
        if pool_ip not in pools:
            logger.info("can't map %s to pool(%s)" % (ip, pool_ip))
        else:
            logger.debug("mapping %s to pool(%s)" % (ip, pool_ip))
            current_pool = pools[pool_ip]

        if ip not in leases:
            logger.info("no lease for node:%s, ip:%s" % (n["name"], 
                ipv4_to_str(ip)))
            if current_pool["state"] == "recovery":
                freed_lease_count_recovery+= 1
            else:
                freed_lease_count+=1
            current_pool["bad_lease"].append(n)
            if current_pool["address"] not in pools_with_bad_lease:
                pools_with_bad_lease[current_pool["address"]] = 1
        else:
            # ensure lease is valid/not abandoned
            if leases[ip]["state"]!="active": 
                logger.info("invalid lease(%s) for node:%s, ip:%s" % (
                    leases[ip]["state"], n["name"], ipv4_to_str(ip)))
                if current_pool["state"] == "recovery":
                    bad_lease_count_recovery+=1
                else:
                    bad_lease_count+=1
                current_pool["bad_lease"].append(n)
                if current_pool["address"] not in pools_with_bad_lease:
                    pools_with_bad_lease[current_pool["address"]] = 1
            else:
                logger.debug("valid lease found for node:%s, ip:%s" % (
                    n["name"], ipv4_to_str(ip)))
                current_pool["good_lease"].append(n)

    # print results
    col_len = 35
    rows = []
    rows.append('{0:<{n}}: {1}'.format("fabric nodes", node_count, n=col_len))
    rows.append('{0:<{n}}: {1}'.format("vleafs", vleaf_count, n=col_len))
    rows.append('{0:<{n}}: {1}'.format("dhcp pools", len(pools)-1, n=col_len))
    rows.append('{0:<{n}}: {1}'.format("dhcp leases", len(leases), n=col_len))

    # handle formatting for duplicate IPs
    rows.append('{0:<{n}}: {1}'.format("duplicate IPs", len(dup_nodes), 
        n=col_len))
    for ip in dup_nodes:
        for n in dup_nodes[ip]:
            rows.append("    %s, node-%s, %s, %s" % (n["address_str"],
                n["id"], n["name"], n["clientId"]))

    # handle formatting for duplicate Leases
    rows.append('{0:<{n}}: {1}'.format("duplicate leases", len(dup_leases), 
        n=col_len))
    for ip in dup_leases:
        for l in dup_leases[ip]:
            # try to map the client-id of the dup lease to a node
            n = {"id":"?", "name":"?"}
            for xip in nodes:
                if l["clientId"] == nodes[xip]["clientId"]:
                    n = nodes[xip]
                    break
            rows.append("    %s, node-%s, %s, %s" % (l["address_str"],
                n["id"], n["name"], l["clientId"]))

    # handle formatting for pools with bad leases
    rows.append('{0:<{n}}: {1}'.format("Recovery Abandoned/Freed Leases ", 
        (bad_lease_count_recovery + freed_lease_count_recovery), n=col_len))
    rows.append('{0:<{n}}: {1}'.format("Abandoned/Freed Leases", 
        (bad_lease_count + freed_lease_count), n=col_len))
   
    if len(pools_with_bad_lease)>0: rows.append("") 
    for pool_ip in pools_with_bad_lease:
        # should never happen
        if pool_ip not in pools:
            logger.error("abort -> pool ip %s not found in any pools"%pool_ip)
            logger.error("\n%s" % pretty_print(pools))
            sys.exit()
    
        p = pools[pool_ip]
        # don't print recovery pools by default
        if p["state"] == "recovery" and not args.recovery: continue
        pool_ip_str = pool_ip
        free_count = "?"
        good_lease_count = "?"
        if pool_ip != "unknown": 
            pool_ip_str = ipv4_to_str(pool_ip)
            free_count = 32 - len(p["good_lease"]) - len(p["bad_lease"])
            good_lease_count = len(p["good_lease"])
        rows.append("    pool: %s" % pool_ip_str)
        rows.append("        type       : %s" % p["type"])
        rows.append("        state      : %s" % p["state"])
        rows.append("        pool size  : 32")
        rows.append("        free count : %s" % free_count)
        rows.append("        good leases: %s" % good_lease_count)
        rows.append("        bad leases : %s" % len(p["bad_lease"]))
        for n in p["bad_lease"]:
            rows.append("           %s, node-%s, %s, %s" % (
                n["address_str"], n["id"], n["name"], n["clientId"]))
             
    print "\n".join(rows)

    msg_0 = """
    There are NO abandoned/freed leases found in any non-recovery pool.
    There ARE duplicate leases and or duplicate IPs currently present in the 
    fabric that should be addressed as soon as possible.  See CSCvb08670 for
    more details.
    To recover a duplicate IP or lease, decommission (with remove from apic
    option) and recommission each node with the affected IP.
    """
    msg_1 = """
    There are NO abandoned/freed leases found in any non-recovery pool.
    All DHCP pools and leases are in a healthy state.  There is no further
    action required.
    """
    msg_1a = """
    There are %s abandoned/freed leases in recovery pools. This is
    expected after applying the workaround to CSCvb08670.  'Bad' leases in 
    these pools will NOT trigger a duplicate IP for new nodes added to the 
    fabric and can therefore be ignored.

    BONUS if you would like to clean abandoned/freed leases in recovery pools,
    you can decommission (with remove from apic option) and recommission each 
    affected node.  This step is OPTIONAL as 'bad' leases in recovery 
    pools will not trigger duplicate IPs. 
    Re-run this script with --recovery action to get details of each 'bad' 
    lease in a recovery pool.
    """ % (bad_lease_count_recovery + freed_lease_count_recovery)

    msg_2 = """
    There are %s abandoned/freed leases found that could create a duplicate IP
    address. Apply the workaround as described in CSCvb08670 to mark the 
    pool corresponding to the bad lease as 'recovery'.  
    """ % (bad_lease_count + freed_lease_count)

    # print useful information to help customer understand output
    print "\n%s Summary %s" % ("*"*35, "*"*35)
    if bad_lease_count + freed_lease_count > 0: print msg_2        
    else:
        if (len(dup_nodes) + len(dup_leases))>0: print msg_0
        elif (bad_lease_count_recovery + freed_lease_count_recovery)>0:
            print msg_1a
        else: print msg_1

    return True
    


if __name__ == "__main__":

    import argparse
    desc = """
    Check fabric against CSCvb08670
    """

    offlineHelp="""
    Use this option when executing the script on offline data. 
    If not set, this script assumes it is executing on a live 
    system and will query objects directly.
    """
    recoveryHelp="""
    Abandoned/Freed leases in 'recovery' pools are not at risk of creating a
    duplicate IP.  Therefore, only abandoned/freed leases in 'normal' pools
    are disabled by default. To show all abandoned/freed leases, use the 
    --recovery flag.
    """

    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--debug", action="store", help="debug level",
        dest="debug", default="warn", choices=["debug","info","warn","error"])
    parser.add_argument("--recovery", action="store_true", help=recoveryHelp,
        dest="recovery")
    parser.add_argument("--offline", action="store", dest="offline",
        help=offlineHelp, default=None)
    parser.add_argument("--offlineHelp", action="store_true", dest="ohelp",
        help="print further offline help instructions")
    args = parser.parse_args()
    setup_logger(logging_level=args.debug)

    #offline-help
    if args.ohelp:
        cmds = []
        for o in OFFLINE_OBJECTS:
            c = "icurl http://127.0.0.1:7777/api/class/%s.json " % o
            c+= " > /tmp/off_%s.json" % o
            cmds.append(c)

        offlineOptionDesc="""
  Offline mode expects a .tgz file.  For example:
  %s --offline ./offline_data.tgz

  When executing in offline mode, ensure that all required data is present in
  input tar file. For best results, collect information for all tables using
  the filenames used below. Once all commands have completed, the final tar 
  file can be found at:
    /tmp/offline_data.tgz

  bash -c '
   %s
  rm /tmp/offline_data.tgz
  tar -zcvf /tmp/offline_data.tgz /tmp/off_*
  rm /tmp/off_*
  '""" % (__file__, "\n   ".join(cmds))
        print offlineOptionDesc
        sys.exit()

    else:
        if args.offline: 
            OFFLINE_MODE = True
            OFFLINE_FILES = offline_extract(args.offline, 
                offline_keys=OFFLINE_OBJECTS)
        elif get_dn("/uni") is None:
                msg = "\nError: Trying to execute on an unsupported device. "
                msg+= "This script is intended to run on the apic or offline"
                msg+= " offline data.  Use -h for help.\n"
                sys.exit(msg)
       
    # execute main function
    main(args)
