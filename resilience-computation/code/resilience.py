import argparse
from itertools import combinations
import json
import time
from os import listdir
from os.path import join
import multiprocessing as mp
import numpy as np
import netaddr
from hist_utils import *


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--sim_json",
                        required=True,
                        help="Simulation resilience output in JSON format")
    parser.add_argument("-S", "--sim_json_rpki",
                        default="",
                        help="JSON of secondary simulation resilience \
                        output if applying real-world ROA deployment \
                        analysis")
    parser.add_argument("-l", "--lookup_dir", required=True,
                        help="Input directory of DNS lookups")
    parser.add_argument("-o", "--origin_class_ids_file", required=True,
                        help="Origin class IDS CSV file")
    parser.add_argument("-r", "--routinator_csv_file",
                        help="ROA file")
    parser.add_argument("-a", "--a_records_only", action='store_const',
                        const=True, default=False,
                        help='Consider only webserver (A record) IP addresses\
                        as attack surface when computing resilience')
    parser.add_argument("-O", "--output_dir", required=True,
                        help='Directory to write output')
    # parser.add_argument("--threads", type=int, default=mp.cpu_count()//4)
    return parser.parse_args()


def quorumLE(res_vp_dict):
    return (res_vp_dict["le_via_west"] & 
            ((res_vp_dict["ec2_eu_central_1"] & res_vp_dict["ec2_us_east_2"]) | 
            (res_vp_dict["ec2_eu_central_1"] & res_vp_dict["ec2_us_west_2"]) |
            (res_vp_dict["ec2_us_east_2"] & res_vp_dict["ec2_us_west_2"])))


def quorumFull(res_vp_dict):
    res = np.bitwise_and.reduce([res_vp_dict[vp] for vp in [LE_PRIMARY, *LE_REMOTE_VPS]])
    return res


def apply_quorum_single_vp(vp):
    def quorumPolicy(res_vp_dict):
        return res_vp_dict[vp]
    return quorumPolicy


def apply_quorum_full_vps(*vps):
    def quorumPolicy(res_vp_dict):
        res = np.bitwise_and.reduce([res_vp_dict[vp] for vp in vps])
        return res
    return quorumPolicy


def apply_quor_primary_with_remote_fail(primaryVP, remote_vps):
    remoteVPSet = set(remote_vps)

    def quorumPolicy(res_vp_dict):
        res = None
        for vpAllowedToFail in remoteVPSet:
            requiredVPs = remoteVPSet.copy()
            requiredVPs.remove(vpAllowedToFail)
            requiredBits = None
            for requiredVP in requiredVPs:
                if requiredBits is None:
                    requiredBits = res_vp_dict[requiredVP].copy()
                else:
                    requiredBits &= res_vp_dict[requiredVP]
            if res is None:
                res = requiredBits.copy() # This copy might not actually be needed and could be a direct assignment.
            else:
                res |= requiredBits
        return res & res_vp_dict[primaryVP]
    return quorumPolicy


LE_VPS = ["le_via_west", "ec2_eu_central_1", "ec2_us_east_2", "ec2_us_west_2"]
LE_PRIMARY = "le_via_west"
LE_REMOTE_VPS = ["ec2_eu_central_1", "ec2_us_east_2", "ec2_us_west_2"]


def apply_nminus1_quorum_le_plus(*addtl_vps):
    return apply_quor_primary_with_remote_fail(LE_PRIMARY, [*LE_REMOTE_VPS, *addtl_vps])


def apply_quorum_full_le_plus(*addtl_vps):
    def quorumPolicy(res_vp_dict):
        return np.bitwise_and.reduce([res_vp_dict[vp] for vp in [LE_PRIMARY, *LE_REMOTE_VPS, *addtl_vps]])
    return quorumPolicy


def apply_quorum_full_vps(*vps):
    def quorumPolicy(res_vp_dict):
        return np.bitwise_and.reduce([res_vp_dict[vp] for vp in [*vps]])
    return quorumPolicy


# Full vp list from simulation processor:
# This is a dict mapping vantage points in the quorums and pattern string dict to vantage points in the DSN lookup info.
# Note that the results even for quorums that do not depend on certain pieces of DNS data are influenced by the total set of DNS vantage points used. Do not include a DNS vantage point of a quorum doesn't need it.
# DNS VPs from full DNS lookups: 
# us-west-2,ap-southeast-1,us-east-2,ap-northeast-1,eu-central-1,eu-west-3

active_vps = {'gcp_asia_northeast1': "ap-northeast-1", # Tokyo to Tokyo
                'gcp_asia_southeast1': "ap-southeast-1", # Singapore to Singapore
                'gcp_europe_west2': "eu-west-3", # London to Paris
                'gcp_northamerica_northeast2': "us-east-2", # Toronto to Ohio
                'gcp_us_east4': "us-east-2", # Ashburn Virginia to Ohio
                'gcp_us_west1': "us-west-2", # Oregon to Oregon
                'ec2_ap_northeast_1': "ap-northeast-1", # Tokyo to Tokyo
                'ec2_ap_south_1': "ap-southeast-1", # Mumbai to Singapore
                'ec2_ap_southeast_1': "ap-southeast-1", # Singapore to Singapore
                'ec2_eu_central_1': "eu-central-1", # Frankfurt to Frankfurt
                'ec2_eu_north_1': "eu-central-1", # Stockholm to Frankfurt
                'ec2_eu_west_3': "eu-west-3", # Paris to Paris
                'ec2_sa_east_1': "us-east-2", # São Paulo Brazil to Ohio
                'ec2_us_east_2': "us-east-2", # Ohio to Ohio
                'ec2_us_west_2': "us-west-2", # Oregon to Oregon
                'azure_japan_east_tokyo': "ap-northeast-1", # Tokyo to Tokyo
                'azure_us_east_2': "us-east-2", # Virginia to Ohio
                'azure_west_europe': "eu-central-1", # Netherlands to Frankfurt
                'azure_germany_west_central': "eu-central-1", # Frankfurt to Frankfurt
                'le_via_west': "us-west-2"} # Salt Lake City/Denver to Oregon

quor_pols_to_run = {}
quor_pols_to_run["quorumLE"] = quorumLE
quor_pols_to_run["full"] = quorumFull


non_le_vps = [_ for _ in active_vps if _ not in LE_VPS]

for vp in active_vps.keys():
    quor_pols_to_run[f"0_Only-{vp}"] = apply_quorum_single_vp(vp)

vps_2comb = combinations(active_vps.keys(), 2)
for vp1, vp2 in vps_2comb:
    quor_pols_to_run[f"1_{vp1}+{vp2}"] = apply_quorum_full_vps(vp1, vp2)


for vp in non_le_vps:
    quor_pols_to_run[f"2_LE+{vp}"] = apply_nminus1_quorum_le_plus(vp)


vps_2comb_exceptle = combinations(non_le_vps, 2)
for vp1, vp2 in vps_2comb_exceptle:
    quor_pols_to_run[f"3_LE+{vp1}+{vp2}"] = apply_nminus1_quorum_le_plus(vp1, vp2)


vps_3comb = combinations(non_le_vps, 3)
for vp1, vp2, vp3 in vps_3comb:
    quor_pols_to_run[f"4_LE+{vp1}+{vp2}+{vp3}"] = apply_nminus1_quorum_le_plus(vp1, vp2, vp3)


for vp in non_le_vps:
    quor_pols_to_run[f"5_LE-full+{vp}"] = apply_quorum_full_le_plus(vp)


vps_2comb_exceptle = combinations(non_le_vps, 2)
for vp1, vp2 in vps_2comb_exceptle:
    quor_pols_to_run[f"6_LE-full+{vp1}+{vp2}"] = apply_quorum_full_le_plus(vp1, vp2)


ideal_four = [('gcp_europe_west2', 
               'gcp_northamerica_northeast2',
               'ec2_ap_southeast_1',
               'azure_germany_west_central'),
              ('ec2_ap_northeast_1',
               'ec2_ap_south_1',
               'ec2_ap_southeast_1',
               'ec2_eu_north_1')]

ideal_five = [('gcp_asia_northeast1',
               'gcp_asia_southeast1',
               'ec2_ap_southeast_1',
               'azure_us_east_2',
               'azure_west_europe'),
              ('ec2_ap_northeast_1',
               'ec2_ap_south_1',
               'ec2_ap_southeast_1',
               'ec2_eu_north_1',
               'ec2_sa_east_1')]

# vps_choose_four = combinations(non_le_vps, 4)
vps_choose_four = ideal_four
for comb_four in vps_choose_four:
    vp1, vp2, vp3, vp4 = comb_four
    quor_pols_to_run[f"7_LE+{vp1}+{vp2}+{vp3}+{vp4}"] = apply_nminus1_quorum_le_plus(vp1, vp2, vp3, vp4)


# vps_choose_five = combinations(non_le_vps, 5)
vps_choose_five = ideal_five
for comb_five in vps_choose_five:
    vp1, vp2, vp3, vp4, vp5 = comb_five
    quor_pols_to_run[f"8_LE+{vp1}+{vp2}+{vp3}+{vp4}+{vp5}"] = apply_nminus1_quorum_le_plus(vp1, vp2, vp3, vp4, vp5)

quor_pol_names = list(quor_pols_to_run)

NUMBINS = 10000


class Counter(object):
    def __init__(self):
        self.val = mp.Value('i', 0)

    def increment(self, n=1):
        with self.val.get_lock():
            self.val.value += n

    @property
    def value(self):
        return self.val.value


def unpack_res_ptrn_str_dict(pattern_d, adv_count):

    res_obj_dict = {}
    bitmask = np.full((adv_count,), dtype=np.uint8, fill_value=0x1)
    for vp in pattern_d:
        res_obj_dict[vp] = {}
        vp_dict = res_obj_dict[vp]
        for ocid in pattern_d[vp]:
            vp_dict[ocid] = np.packbits(np.frombuffer(pattern_d[vp][ocid].encode('utf-8'), dtype=np.uint8) & bitmask)

    return res_obj_dict


def lookupASRoutesObject(ip, routesObject, rangeMaxInclusive=32, rangeMinInclusive=8, ip6RangeMaxInclusive=128, ip6RangeMinInclusive=8):
    if ip is None:
        return (None, None)
    rangeMax = rangeMaxInclusive
    rangeMin = rangeMinInclusive - 1
    if ":" in ip:
        rangeMax = ip6RangeMaxInclusive
        rangeMin = ip6RangeMinInclusive - 1
    for i in range(rangeMax, rangeMin, -1):
        cidr = netaddr.IPNetwork(str(ip) + "/" + str(i)).cidr
        strCidr = str(cidr)
        if strCidr in routesObject:
            return (strCidr, routesObject[strCidr])
    return (None, None)


def load_routes_obj_from_routinator_file(routinator_csv_f):
    # This function processes routing data from routinator vrps --format csv
    routes_obj = {}
    with open(routinator_csv_f) as f:
        next(f)
        for line in f:
            sline = line.strip()
            if len(sline) == 0:
                continue
            splitLine = sline.split(",")
            asn, prefix, maxLength, trust_anchor = splitLine
            asn_spliced = asn.replace("AS", "")
            routes_obj[prefix] = asn_spliced
            # if prefix in routesObject:
            #     routesObject[prefix].append((asn_spliced, maxLength, trust_anchor))
            # else:
            #     routesObject[prefix] = [(asn_spliced, maxLength, trust_anchor)]
    return routes_obj


def load_ocid_obj_from_ocids_file(ocid_f):
    ocid_obj = {}
    with open(ocid_f) as f:
        for line in f:
            sline = line.strip()
            if len(sline) == 0:
                continue
            splitLine = sline.split(":")
            if len(splitLine) < 2:
                print("short line")
                continue
            ocid = splitLine[0]
            prefix_list = [s[1:-1] for s in ":".join(splitLine[1:-1])[1:-1].split(", ")]
            for prefix in prefix_list:
                if prefix in ocid_obj:
                    print(f'dupl for {prefix}')
                ocid_obj[prefix] = ocid
    return ocid_obj


# initialize global counters
failed_lookups = Counter()
good_lookups = Counter()
rpki_covered_ips = Counter()
total_domains = Counter()
domains_skipped_missing_dns = Counter()
dns_vp_missing_arecs = {vp_loc: Counter() for vp_loc in active_vps.values()}
lines_written = Counter()


def compute_quorum_res(dns_lookup, res_obj_dict, 
                       rpki_res_obj_dict, 
                       ocid_obj,
                       routinator_obj,
                       adv_count, 
                       arec_only, 
                       count_rpki=True):

    global good_lookups, failed_lookups
    quorum_res_map = {}
    res_vp_dict = {}
    for vp in active_vps:
        res_obj_for_vp = np.full((int((adv_count - 1)/ 8) + 1,), dtype=np.uint8, fill_value=0x0)
        if active_vps[vp] in dns_lookup:
            dns_lkup_info_for_vp = dns_lookup[active_vps[vp]]
            a_recs = [_ for _ in dns_lkup_info_for_vp[0] if len(_) > 0]
            for ip in a_recs:
                try:
                    if count_rpki and lookupASRoutesObject(ip, routinator_obj) != (None, None):
                        rpki_covered_ips.increment()
                        res_obj_for_vp |= rpki_res_obj_dict[vp][lookupASRoutesObject(ip, ocid_obj)[1]]
                    else:  
                        res_obj_for_vp |= res_obj_dict[vp][lookupASRoutesObject(ip, ocid_obj)[1]]
                    good_lookups.increment()
                except KeyError:
                    failed_lookups.increment()
            if not arec_only:
                dns_targ_ipsv4 = [_ for _ in dns_lkup_info_for_vp[2] if len(_) > 0]
                for ip in dns_targ_ipsv4:
                    try:
                        if count_rpki and lookupASRoutesObject(ip, routinator_obj) != (None, None):
                            rpki_covered_ips.increment()
                            res_obj_for_vp |= rpki_res_obj_dict[vp][lookupASRoutesObject(ip, ocid_obj)[1]]
                        else:
                            res_obj_for_vp |= res_obj_dict[vp][lookupASRoutesObject(ip, ocid_obj)[1]]
                        good_lookups.increment()
                    except KeyError:
                        failed_lookups.increment()
        res_vp_dict[vp] = res_obj_for_vp

    for pol_name in quor_pols_to_run:
        quorum = quor_pols_to_run[pol_name]
        quor_res_obj = quorum(res_vp_dict)
        quorum_res_map[pol_name] = np.unpackbits(quor_res_obj)

    return quorum_res_map


# def worker(in_f, res_obj, rpki_res_obj, ocid_obj, routinator_obj, adv_count, arec_only, count_rpki, out_q):
def worker(in_f, out_f, res_obj, rpki_res_obj, ocid_obj, routinator_obj, adv_count, arec_only, count_rpki):

    global total_domains, domains_skipped_missing_dns, dns_vp_missing_arecs
    policy_res_map = {p: init_hist(NUMBINS) for p in quor_pols_to_run}
    with open(in_f) as f:
        for line in f:
            sline = line.strip()
            if len(sline) > 0:
                total_domains.increment()
                dns_lkup_info = {}
                split_line = sline.split(",")
                full_arecs = True
                for i in range(int((len(split_line) - 1) / 5)):
                    vp_nm, a, aaaa, dns_targ_ipsv4, dns_targ_ipsv6 = split_line[i * 5 + 1: (i + 1) * 5 + 1]
                    dns_lkup_info[vp_nm] = (a.split(" "), aaaa, dns_targ_ipsv4.split(" "), dns_targ_ipsv6)
                    if len(a) == 0:
                        full_arecs = False
                        dns_vp_missing_arecs[vp_nm].increment()
                if not full_arecs:
                    domains_skipped_missing_dns.increment()
                else:
                    quorum_res = compute_quorum_res(dns_lkup_info,
                                                    res_obj,
                                                    rpki_res_obj, 
                                                    ocid_obj,
                                                    routinator_obj,
                                                    adv_count, arec_only, count_rpki)
                    merge_policy_hists(policy_res_map, quorum_res, adv_count)
                    # print(f'Finished processing {domain} from {in_f}')
                if (total_domains.value % 100) == 0: print(f'Done with {total_domains.value} so far {in_f}')

    print(f'Done parsing DNS lookups for {in_f}')
    reformat_json = {p: (k[0].tolist(), k[1].tolist()) for p, k in policy_res_map.items()}
    write_gz_json(out_f, reformat_json)
    print(f'Finished writing to {out_f}')


def compute_domain_resilience(args):

    start = time.time()
    count_rpki = False
    routinator_obj = {}
   
    print(f"Processing {len(quor_pols_to_run)} different quorum policies.")

    if args.routinator_csv_file is not None:
        count_rpki = True
        t1 = time.time()
        routinator_obj = load_routes_obj_from_routinator_file(args.routinator_csv_file)
        t2 = time.time()
        print(f"Loaded routes object from routinator csv file. \
                Couting IPs secured by RPKI. ({t2 - t1:.3f} seconds)")
    
    print(f'Applying RPKI analysis? {count_rpki}')

    sim_pattern_str_dict = json.load(open(args.sim_json))
    adv_count = len(next(iter(next(iter(sim_pattern_str_dict.values())).values()))) 
    print(f"JSON pattern string dict loaded. Adversary count: {adv_count}.")

    t1 = time.time()
    res_obj_dict = unpack_res_ptrn_str_dict(sim_pattern_str_dict, adv_count)
    rpki_res_obj_dict = {}
    if len(args.sim_json_rpki) > 0:
        rpki_sim_pattern_str_dict = json.load(open(args.sim_json_rpki))
        rpki_res_obj_dict = unpack_res_ptrn_str_dict(rpki_sim_pattern_str_dict, adv_count)
    t2 = time.time()
    print(f"Resilience object(s) loaded ({t2 - t1:.3f} seconds).")

    t1 = time.time()
    ocid_obj = load_ocid_obj_from_ocids_file(args.origin_class_ids_file)
    t2 = time.time()
    print(f"OCID object loaded ({t2 - t1:.3f} seconds).")
    
    files_to_process = []
    output_files = [] 
    for f in listdir(args.lookup_dir):
        f_prefix = f[:f.rindex('.')]
        output_files.append(join(args.output_dir, f'{f_prefix}-res.json.gz'))
        files_to_process.append(join(args.lookup_dir, f))

    print(output_files)
    manager = mp.Manager()
    pool = mp.Pool(min(len(files_to_process), mp.cpu_count()//2))

    jobs = []
    for i in range(len(files_to_process)):
        job = pool.apply_async(worker, (files_to_process[i], output_files[i], res_obj_dict, rpki_res_obj_dict, ocid_obj, routinator_obj, adv_count, args.a_records_only, count_rpki))
        jobs.append(job)

    for job in jobs:
        job.get()

    pool.close()
    pool.join()

    print("Processing complete.")
    print(f"IP to OCID lookup info: Good Lookups: {good_lookups.value}, Failed Lookups: {failed_lookups.value}")
    print(f"RPKI Lookups: IPs in RPKI table: {rpki_covered_ips.value}, total IPs looked up: {good_lookups.value + failed_lookups.value}")
    
    print(f"Total domains: {total_domains.value}, domains skipped because of missing A records at vantage points: {domains_skipped_missing_dns.value}")
    print("Domains skipped at each DNS vantage point:")
    for vp, vp_count in dns_vp_missing_arecs.items():
        print(f"\t{vp}:{vp_count.value}")

    end = time.time()
    print(f"Total time: {end - start:.3f} seconds.")


if __name__ == '__main__':
    compute_domain_resilience(parse_args())
