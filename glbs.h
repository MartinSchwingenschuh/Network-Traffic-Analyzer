/*
** Copyright (C) 2022  Martin Schwingenschuh
**
** Licensed under the EUPL, Version 1.2 or – as soon they will be approved by
** the European Commission - subsequent versions of the EUPL (the "Licence").
** You may not use this work except in compliance with the Licence.
** 
** You should have received a copy of the European Union Public License along
** with this program.  If not, you may obtain a copy of the Licence at:
** <https://joinup.ec.europa.eu/software/page/eupl>
** 
** Unless required by applicable law or agreed to in writing, software
** distributed under the Licence is distributed on an "AS IS" basis,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the Licence for the specific language governing permissions and
** limitations under the Licence.
**
*/
#ifndef HEADER_GLBS
#define HEADER_GLBS
/*******************************************************/
#include "pcap.h"
#include <stdbool.h>
#include <regex.h>
/*******************************************************/
/*                  general options                    */
/*******************************************************/
/* set to true for more output*/
#define DEBUG false
/* Set this to true if the program works in production enviroment
 * the indices have a different pattern in different arkime versions */
#define PROD true
/* the program version written to elastic search */
#define PROG_VERSION "v1.2"
/* version of the ruleset */
#define RULEVERSION 1
/*******************************************************/
/*                     ruleoptions                     */
/*******************************************************/
/* set the time in ms how long an update start is valid*/
#define MAXUPDATELENGTH 600000
/* set the time in ms how long into the past the dans
 * request should be considered */
#define MAXDNSTIME 86400000 //1day //600000 //10min
/*******************************************************/
/*                  database options                   */
/*******************************************************/
#define ES_URL "http://localhost:9200"
#define ES_DOC "_doc"
#if PROD
    #define ES_INDEXPREFIX "sessions2-"
    #define ES_FILEINDEX "files_v6"
    #define ES_TIMESTAMP "timestamp"
#else
    #define ES_INDEXPREFIX "arkime_sessions3-"
    #define ES_FILEINDEX "arkime_files_v30"
    #define ES_TIMESTAMP "@timestamp"
#endif
#define ES_UPDATE "_update"
#define ES_SEARCH "_search"
#define ES_ALL "_all"
#define ES_TAGPATTERNS "tagpatterns"
#define ES_UPDATES "updates"
#define ES_INDEXCHECK_ERROR "404 Not Found"
#define ES_INDEXCHECK_OK "200 OK"

/*******************************************************/
/*                    pcap options                     */
/*******************************************************/
#if PROD
    #define PCAPPREFIX "adsec-traffic"
#else
    #define PCAPPREFIX "vm"
#endif

/*******************************************************/
/*                     status messages                 */
/*******************************************************/
#define RED "\e[0;31m"
#define GREEN "\e[0;32m"
#define YELLOW "\e[0;33m"
#define NC "\e[0m"

#define STATUS_OK       "["GREEN"  OK   "NC"]"
#define STATUS_ERROR      "["RED" ERROR "NC"]"
#define STATUS_WARNING "["YELLOW"WARNING"NC"]"
#define STATUS_INFO            "[  INFO ]"

#define STATUS_STREAM stdout

/*******************************************************/
/*                     MemoryStruct                    */
/*******************************************************/
typedef struct MemoryStruct MemoryStruct;

struct MemoryStruct{
    char *memory;
    size_t size;
};
/*******************************************************/
/*                     StringArray                     */
/*******************************************************/
#define SA_ERROR -1
#define SA_SUCC 1
#define SA_FAIL 0

typedef struct StringArray StringArray;

struct StringArray{
    char **data;
    size_t size;
};

struct StringArray* newStringArray();

void expandArray(struct StringArray* toExpand);

/*
 * Adds the given string to the array
 * returns -1 if string is already stored
 * returns 1 if string was added
 */
int sa_add(struct StringArray *sa,char* toAdd);

/*
 * delete the given string from the array
 * returns 1 if entry was deleted
 * returns -1 if not deleted
 */
int sa_delete(struct StringArray *sa, char *toDelete);

void sa_print(struct StringArray *sa);

int freeArray(struct StringArray* toFree);
/*******************************************************/
/*                    Session                          */
/*******************************************************/
typedef struct Session Session;

struct Session{
    //contains the parsed json data
    struct json_object* json;

    char *sessionId;
    char *analyzer_version;
    int rule_version;
    char *src_ip;
    char *dst_ip;
    char *src_port;
    char *dst_port;

    char **src_macs;
    size_t src_macs_count;

    char **dst_macs;
    size_t dst_macs_count;

    char **vlans;
    size_t vlan_count;

    int64_t timestamp;
    char *timestamp_string;


    //path to the file where the pcap data is stored
    char *pcap_filename;
    //array of packet positions in the pcap file
    int64_t *pcap_positions;
    //contains the number of packets stored in the array pcap_positions
    size_t pcap_count;

    //raw packet array
    Packet **packets;
    //number of packets stored in packets array
    size_t nPackets;    
};

struct Session* newSession();

void freeSession(struct Session *toFree);

void printSession(struct Session *session);

/*******************************************************/
/*                    MatchData                        */
/*******************************************************/
typedef struct MatchData MatchData;

struct MatchData{
    regex_t *regex;
    struct StringArray *tags;
    struct MatchData *next;
};

struct MatchData* newMatchData();

void freeMatchData(struct MatchData **toFree);

/*******************************************************/
/*                    program glb_args                */
/*******************************************************/
typedef struct arguments Arguments;

struct arguments{
    bool FLAG_ALL;
    bool FLAG_ID;
    bool FLAG_VERBOSE;
    bool FLAG_CUTOFF;
    bool FLAG_STOREHOSTS;
    bool FLAG_IGNOREVERSION;
    bool FLAG_ES_URL_OVERRIDE;
    bool FLAG_PPREFIX_OVERRIDE;
    bool FLAG_PFOLDER_OVERRIDE;

    bool FLAG_SCOPE_SET;

    bool MODE_NOPCAP;

    char *sessionId;
    long deltaTime;
    char *es_url;
    char *pcap_folder;
    char *pcap_prefix;
};

/*******************************************************/
/*                         helpers                     */
/*******************************************************/
/*
 * convert a long into a string
 * string has to be freed from caller
 */
char* ltos(long number);

/*
 * extract the index from the given session_id
 * the returned string is allocated but must be freed from caller
 */
char* indexfromSession(char *session_id);

/*
 * get the size of an array
 */
#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))

#endif
