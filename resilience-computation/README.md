# resilience-computation
Calculate resilience of domain names under a range of potential multiVA deployment configurations.

# Usenix 23 Artifact Evaluation
The resilience code can be evaluated by running .
There are two main steps: (1) run ```resilience.py``` to combine Internet topology simulation results with DNS lookup data to compute resilience values for domain names; (2) run ```analyze_results.py``` to summarize and print results across classes of quorum policies/vantage point sets.

## An overview of resilience.py
resilience.py computes the resilience of a domain name against equally-specific BGP attacks on its webservers and/or DNS nameservers, using the routing simulation results computed with the `pki-topology-simulator` tool (Please refer to the separate [repository](https://github.com/inspire-group/pki-topology-simulator/tree/main)). Running ```python3 resilience.py -h``` (from the code directory; all python commands are intended to be executed from the code directory) gives the help output showing the various input file flags:

```
usage: resilience.py [-h] -s SIM_JSON [-S SIM_JSON_RPKI] -l LOOKUP_DIR -o
                     ORIGIN_CLASS_IDS_FILE [-r ROUTINATOR_CSV_FILE] [-a] -O
                     OUTPUT_DIR

optional arguments:
  -h, --help            show this help message and exit
  -s SIM_JSON, --sim_json SIM_JSON
                        Simulation resilience output in JSON format
  -s SIM_JSON_RPKI, --sim_json SIM_JSON_RPKI
                        JSON of secondary simulation resilience output if
                        applying real-world ROA deployment analysis
  -l LOOKUP_DIR, --lookup_dir LOOKUP_DIR
                        Input directory of DNS lookups
  -o ORIGIN_CLASS_IDS_FILE, --origin_class_ids_file ORIGIN_CLASS_IDS_FILE
                        Origin class IDS CSV file
  -r ROUTINATOR_CSV_FILE, --routinator_csv_file ROUTINATOR_CSV_FILE
                        ROA file
  -a, --a_records_only
                        Consider only webserver (A record) IP addresses as
                        attack surface when computing resilience
  -O OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Directory to write output
```

This flags specify all input files to the resilience calculation framework. Below they are explained in order.

### Preparing data
Some of the input data to the `resilience.py` script is stored in compressed format. To extract, run the following commands from the `resilience-computation` folder:
```
gzip -d data/sim_json/*
gzip -d data/ocids/*
gzip -d data/roa/*
```

### SIM_JSON
This is an output of Internet topology simulations, converted to JSON format. We provide two prepackaged simulation outputs, containing simulations from a 10% sample of the 1K randomly selected AS-level attackers presented in our paper, in ```data/sim_json```: ```sim_output_k100_nonrpki.json``` and ```sim_output_k100_rpki.json```.

### SIM_JSON_RPKI
Similar to SIM_JSON, this is another JSON format-Internet topology simulation output. This argument is needed when performing real-world ROA deployment scenario to resilience calculation: the resilience calculator loads both the non-RPKI and RPKI simulation results, and applies the correct simulation output per IP address depending on the ROA coverage status of the prefix.

### LOOKUP_DIR
Directory path containing CSV-formatted lookup files output from the ```routing-aware-dns``` resolver tool.
For the sake of brevity, we provide a file of 10000 domains (randomly sampled from the 1.39M surveyed in our study) and their associated lookups in ```data/domains/lookups_10ksample.txt```.

### ORIGIN_CLASS_IDS_FILE
CSV file containing BGP announcement profiles of all prefixes announced on the Internet, based on RIB files from public route collectors.
We provide one file (compiled using BGP monitor data in March 2022) in ```data/ocids/origin-class-ids-2022-03-15.csv```.

### ROUTINATOR_CSV_FILE
CSV file of validated ROA payloads (VRPs) for simulating real-world ROA adoption in resilience calculations.
You can download the latest ROA objects by using the [Routinator tool](https://routinator.docs.nlnetlabs.nl/en/stable/ "for more details"). 
We provide ROA data from September 15 2023 (the data used in our paper) in ```data/roa/routinator-2022-09-15.csv```.

### a_records_only
Boolean flag to indicate whether to consider only webserver IP addresses as the attack surface for BGP hijacks in calculating domain name resilience. 
```a_records_only=False``` is a primary point of novelty for the resilience calculation framework.

### OUTPUT_DIR
Directory to write output histograms of resilience values per quorum configuration.
The output is in JSON format of the following schema:
```
{
  <policy_name>:<histogram of resilience values, bins of resilience histogram>
}
```
The resilience calculator sorts resilience into ```nbins=10000``` by default, to aggregate resilience at 0.01% granularity. The nbins parameter can be tweaked according to user preferences (for example, fewer bins translates to smaller output files).

## Running resilience.py

resilience.py primarily depends on python3. We were able to run it on a clean Ubuntu 22.04 VM with no ```apt``` or ```pip``` commands as it only depends on already-installed standard libraries.

Before running the resilience code, we recommend you make a directory called ```output/``` in the repo that will be ignored by git (based on the repos ```.gitignore```). From the base of the repo run:

```mkdir output```

Then cd to the code dir:

```cd code```

Below is an example run command that can be executed from the ```code/``` directory that points to 10K domain subsample included in the default input files, calculates resilience considering the DNS attack surface and real-world RPKI-ROA adoption, and writes output to the ```output``` directory:

```python3 resilience.py -s ../data/sim_json/sim_output_k100_nonrpki.json -S  ../data/sim_json/sim_output_k100_rpki.json -o ../data/ocids/origin-class-ids-2022-03-15.csv -r ../data/roa/routinator-2022-09-15.csv -l ../data/domains/lookups_10ksample.txt -O ../data/output/dns_realworld_rpki ```

This simulation took us approximately 90 minutes on a single-core virtual machine with a recent generation CPU. This version of the script is not multi-threaded so it will not benefit from being run on a cluster/HPC node.

Below is a variant of the command that calculates resilience considering only the webserver attack surface and assuming full RPKI-ROA adoption:

```python3 simulate.py -s ../data/sim_json/sim_output_k100_rpki.json -o ../data/ocids/origin-class-ids-2022-03-15.csv  -l ../data/domains/lookups_10ksample.txtt -O ../data/output/webserver_realworld_rpki```

For convenience and comparative purposes, we provide the output of the above two resilience simulations regimes in ```data/output_groundtruth```.
## Running analyze_results.py
This script reads the output of the preceding ```resilience.py```, computes statistics (median and mean) for each quorum configuration simulated, and outputs the ideal (i.e., highest resilience) deployment for each class of quorum policy/VP count.
Analyzing the results typically takes only a few minutes. Results are printed to stdout.

To output analyzed results of the prior DNS + real-world RPKI simulations:
```python3 analyze_results.py -i ../data/output/dns_realworld_rpki ```
