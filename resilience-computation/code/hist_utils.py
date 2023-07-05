import gzip
import json
import numpy as np


def write_gz_json(fpath, data):

    with gzip.open(fpath, 'wt', encoding='UTF-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def read_gz_json(fpath):
    with gzip.open(fpath, 'rt', encoding='UTF-8') as f:
        j = json.load(f)
    return j


def init_hist(numbins, datamin=0, datamax=1):
    bins = np.linspace(datamin, datamax, numbins)
    hist = np.zeros(numbins - 1)
    return (hist, bins)


def get_mean(hist, bins):
    bin_meds = [(bins[i] + bins[i+1])/2 for i in range(len(bins) - 1)]
    return np.sum(np.multiply(hist, bin_meds))/np.sum(hist)


def get_median(hist, bins):
    total = 0
    num_items = int(sum(hist))
    median_index = (num_items - 1)//2
    bin_meds = [(bins[i] + bins[i+1])/2 for i in range(len(bins) - 1)]
    for idx, value in enumerate(hist):
        total += value
        if total > median_index:
            return bin_meds[idx]


def merge_policy_hists(merge_map, res_map, adv_count):
    for pol_name in res_map:
        res_bit_vect = res_map[pol_name]
        resilience = float(adv_count - np.sum(res_bit_vect))/adv_count
        prev_hist, prev_bins = merge_map[pol_name]
        htemp, _ = np.histogram(resilience, prev_bins)
        prev_hist += htemp