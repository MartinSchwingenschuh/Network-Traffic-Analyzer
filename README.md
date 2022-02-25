# Analyzer

## Table of contents
* [General info](#general-info)
* [Setup](#setup)
* [Dependencies](#dependencies)
* [Arguments](#arguments)
* [Custom Rules](#custom-rules)
* [Changelog](#changelog)

## General info
This is a tool to analyze network traffic captured by an [Arkime instance][1] and derive additional 
features based on custom rules.

## Setup
The program can be compiled for every system as long as the dependencies are met.
The precompile options have to be set accordingly to the Arkime installation.
For the execution check out the [arguments](#arguments) section.

## Dependencies
This program needs the following dependencies to compile:
* libcurl
* libjson

This program needs the following dependencies to execute correctly:
* Running Elastic search
* custom index tagpatterns
* custom index updates

## Arguments
| long           | short | argument       | description |
|----------------|-------|----------------|-------------|
| --help         |  -h   |  ---           | print help |
| --all          |  -a   |  ---           | set the scope to the whole database|
| --cutoff       |  -c   | time in hours  | set the scope to time - <time in hours> |
| --id           |  -i   | session_id     | set the scope to a single session |
| --hosts        |  -h   |  ---           | store found hostnames in ES |
| --verbose      |  -v   |  ---           | print additional information |
| --esurl        |  -e   | url            | override the url used to contact ES |
| --pprefix      |  -P   | prefix         | override the prefix used in pcap files |
| --nopcap       |  -p   |  ---           | dont read pcap files |
| --ignoreversion|  -I   |  ---           | ignore the version check |

Note that one of the three scope options (-a,-c,-i) has to be set.
    
Examples:
```
    ./Analyzer -h -I --cutoff=1
    ./Analyzer --id=<session_id>
```

## Custom-Rules
For creating a new rule add a function in the rules.h file and add the functionname to the rule_ptr array also in the rules.h file.
Rules have to implement the signature:
```
void rule_name(Session *session, LinkedList *tags)
```

## Changelog:
### v1.2

* global argument struct refactored with more options available
* introduces nopcap mode '-p' wich ignores pcap files
* rules can now access common fields of a session directly without the need of working through the json object. The parsing of the json object is handled in the elasticSearch module with the function es_parse_session
* rules can now delete tags from other rules
* introduced ruleversion field. Sessions are now only analyzed if the currend ruleversion is higher than the old one.
    This Ruleversion is not the same as the Analyzer version.
* update tagging now uses the vlan as device identification
* added options for overwriting default values

### v1.1
The initial version deployed



[1]: https://arkime.com/
    
