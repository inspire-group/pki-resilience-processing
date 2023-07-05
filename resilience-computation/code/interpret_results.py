#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################

# Designed to process results from ./summary_from_csv.py -c * | tee ../results.summary.txt

import argparse
import matplotlib.pyplot as plt


def parse_args():
    parser = argparse.ArgumentParser()
    # This is a CAIDA AS topology.
    parser.add_argument("-s", "--summary_file",
                        default="data/results.summary.txt")
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

    resultsClasses.append(lambda line: line.startswith("File: 0"))
    resultsClassNames.append("Single VP")

    resultsClasses.append(lambda line: line.startswith("File: 1"))
    resultsClassNames.append("Any Two VPs")

    resultsClasses.append(lambda line: line.startswith("File: quorumLE"))
    resultsClassNames.append("LE Quorum")

    resultsClasses.append(lambda line: line.startswith("File: 2"))
    resultsClassNames.append("Lets Encrypt + 1")

    resultsClasses.append(lambda line: line.startswith("File: 3"))
    resultsClassNames.append("Lets Encrypt + 2")

    resultsClasses.append(lambda line: line.startswith("File: 3") and line.count("ec2") == 2)
    resultsClassNames.append("Lets Encrypt + 2 Only EC2")

    resultsClasses.append(lambda line: line.startswith("File: 4"))
    resultsClassNames.append("Lets Encrypt + 3")

    resultsClasses.append(lambda line: line.startswith("File: 4") and line.count("ec2") == 3)
    resultsClassNames.append("Lets Encrypt + 3 Only EC2")

    resultsClasses.append(lambda line: line.startswith("File: 4") and not "gcp" in line)
    resultsClassNames.append("Lets Encrypt + 3 EC2 + Azure")

    resultsClasses.append(lambda line: line.startswith("File: 4") and not "azure" in line)
    resultsClassNames.append("Lets Encrypt + 3 EC2 + GCP")

    resultsClasses.append(lambda line: line.startswith("File: 5"))
    resultsClassNames.append("Full Quorum LE + 1")

    resultsClasses.append(lambda line: line.startswith("File: 5") and line.count("ec2") == 1)
    resultsClassNames.append("Full Quorum LE + 1 Only EC2")

    resultsClasses.append(lambda line: line.startswith("File: 6"))
    resultsClassNames.append("Full Quorum LE + 2")

    resultsClasses.append(lambda line: line.startswith("File: 6") and line.count("ec2") == 2)
    resultsClassNames.append("Full Quorum LE + 2 Only EC2")

    resultsClasses.append(lambda line: line.startswith("File: 6") and not "gcp" in line)
    resultsClassNames.append("Full Quorum LE + 2 EC2 + Azure")

    resultsClasses.append(lambda line: line.startswith("File: 6") and not "azure" in line)
    resultsClassNames.append("Full Quorum LE + 2 EC2 + GCP")

    resultsClasses.append(lambda line: line.startswith("File: full-"))
    resultsClassNames.append("Full Quorum LE")

    # Each entry is a running best median and average tuple.
    runningBestForResultsClass = [(0,0,"")] * len(resultsClasses)
    for line in open(args.summary_file):
        sline = line.strip()
        if sline == "":
            continue
        for i in range(len(resultsClasses)):
            # If the line is included in the results class.
            if resultsClasses[i](sline):
                # Compare best based on median alone. Todo: add runing best for average too.
                median, average = parseLineForMedianAndAverage(sline)
                if median > runningBestForResultsClass[i][0]:
                    runningBestForResultsClass[i] = (median, average, getQuorumNameFromLine(sline))

    for i in range(len(resultsClasses)):
        print(f"{''+ resultsClassNames[i]:<35}, {'Best: ' + str(runningBestForResultsClass[i])}")
                

if __name__ == '__main__':
    main(parse_args())
