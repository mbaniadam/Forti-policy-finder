# FortiGate Policy Dependency Finder

<img src="https://github.com/mbaniadam/Forti-policy-finder/assets/75830370/d5d909fe-d158-49d0-b53b-e2de80dc279d" width="200">

#### The FortiGate Policy Dependency Finder is a Python script that leverages Fortinet FortiGate APIs to discover policies related to specific IP addresses. 
#### This tool helps identify address dependencies, address groups, interfaces, and policies linked to the provided IP addresses.






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

