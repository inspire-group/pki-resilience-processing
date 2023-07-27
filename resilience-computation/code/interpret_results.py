import argparse
import gzip
import json
import re
import hist_utils


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--json_summary_file",
                        help="JSON output from resilience.py")
    return parser.parse_args()


def parseLineForMedianAndAverage(sline):
    median = float(sline.split("Median: ")[1].split(" Average:")[0])
    average = float(sline.split("Average: ")[1])
    return (median, average)


def getQuorumNameFromLine(sline):
    return " ".join(sline.split(",")[0].replace("File: ", "").split(" ")[1:]).replace("-cdf.csv", "")


def main(args):
    resultsClasses = []
    resultsClassNames = []


    results_class_names = {
            "Default Let's Encrypt (n-1)": r'quorumLE',
            "Full Quorum Let's Encrypt": r'full',
            "Single VP": r'0_Only-(?P<vp>.+)',
            "Any Two VPs": r'1_(.+)\+(.+)',
            "Let's Encrypt +1": r'2_LE\+(.+)',
            "Let's Encrypt +2": r'3_LE\+(.+)\+(.+)',
            "Let's Encrypt +2 only EC2": r'3_LE\+(ec2_.+)\+(ec2_.+)',
            "Let's Encrypt +3": r'4_LE\+(.+)\+(.+)\+(.+)',
            "Let's Encrypt +3 only EC2": r'4_LE\+(ec2_.+)\+(ec2_.+)\+(ec2_.+)',
            "Let's Encrypt +3 EC2 and Azure": r'4_LE\+((?!gcp).+)\+((?!gcp).+)\+((?!gcp).+)',
            "Let's Encrypt +3 EC2 and GCP": r'4_LE\+((?!azure).+)\+((?!azure).+)\+((?!azure).+)',
            "Full Quorum Let's Encrypt +1": r'5_LE-full\+(.+)',
            "Full Quorum Let's Encrypt +1 only EC2": r'5_LE-full\+(ec2_.+)',
            "Full Quorum Let's Encrypt +2": r'6_LE-full\+(.+)\+(.+)',
            "Full Quorum Let's Encrypt +2 only EC2": r'6_LE-full\+(ec2_.+)\+(ec2_.+)',
            "Full Quorum Let's Encrypt +2 EC2 and Azure": r'6_LE-full\+((?!gcp).+)\+((?!gcp).+)',
            "Full Quorum Let's Encrypt +2 EC2 and GCP": r'6_LE-full\+((?!azure).+)\+((?!azure).+)'}

    results_class_reg = {v: k for k, v in results_class_names.items()}
    best_results_by_class = {k: (0, 0, "") for k in results_class_names}

    with gzip.open(args.json_summary_file) as f:
        res_js = json.load(f)
    for quor_pol_name, res in res_js.items():
        res_vals, res_bins = res
        mean = hist_utils.get_mean(*res)
        med = hist_utils.get_median(*res)
        for regex in results_class_reg:
            if re.match(regex, quor_pol_name):
                pol_type_name = results_class_reg[regex]
                best_mean, best_median, best_pol = best_results_by_class[pol_type_name]
                if (med >= best_median) and (mean > best_mean):
                    best_results_by_class[pol_type_name] = (mean, med, quor_pol_name)


    for res_class, best in best_results_by_class.items():
        regex = results_class_names[res_class]
        best_med, best_mean, best_pol = best
        vps = ", ".join(re.match(results_class_names[res_class], best_pol).groups())
        print(f"Best config for {res_class}: {vps} (median {best_med}, mean {best_mean}")
        print()        

if __name__ == '__main__':
    main(parse_args())
