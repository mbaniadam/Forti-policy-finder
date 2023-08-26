# FortiGate Policy Dependency Finder
### The FortiGate Policy Dependency Finder is a Python script that leverages Fortinet FortiGate APIs to discover network policies related to specific IP addresses. This tool helps identify address dependencies, address groups, interfaces, and policies linked to the provided IP addresses.

## Table of Contents

#### Features
#### Prerequisites
#### Usage
#### Contributing


## Features
Discover FortiGate policies associated with provided IP addresses.
Identify address groups, interfaces, and policies related to IP addresses.
Validate IPv4 addresses for correctness and relevance.
Output results in a CSV file for easy analysis.


## Prerequisites
Before using the FortiGate Policy Dependency Finder, make sure you have the following prerequisites in place:

Python 3.x installed.

A FortiGate device with enabled API access.

An inventory YAML file (inventory.yml) containing FortiGate device information.

An IP list CSV file (IP_LIST.csv) with IP addresses to analyze.

## Usage

Make sure you have the inventory.yml and IP_LIST.csv files prepared with relevant information.

Run the script:
```console bash
python fortigate_policy_finder.py
```


## Contributing
Contributions are welcome! If you find a bug or have an enhancement in mind, feel free to open an issue or submit a pull request.

