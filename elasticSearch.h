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
#ifndef HEADER_ELASTIC_SEARCH
#define HEADER_ELASTIC_SEARCH

//libcurl4-dev required for this import
#include <curl/curl.h>
//libjson-c-dev required for this import
#include<json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "glbs.h"
#include "pcap.h"

/*
 * executes the given url with the given payload in the elastic search db
 * if an error occours NULL is returned
 * if execution was succsessful the answer of elastic search is returned
 * the memory for the pointer is allocated in this function
 */
struct MemoryStruct* es_execute(char *url, char *payload);

/*
 * Extracts the session from elastic search and pcap files 
 * and stores the contend in a Session struct.
 */
int es_get_session(char* session_id, struct Session* session);


void es_parse_session(struct Session *session);

/*
 * returns the pcap-filename where the given session is stored
 */
const char* es_get_filename(const char* id);

/*
 * goes trough all documents in the given index and stores the document-ids
 * in the given StringArray ptr
 * returns true if execution was succsesful and false in an error case
*/
int es_get_ids(char *index,struct StringArray *dataptr);

/*
 * adds the given tag-string to the session defined by the session_id
 * makes a field if current tags is null
 * returns true if the tag was added succesfuly false in case of an error
 * if the same tag is already in the database nothing is added
 */
int es_add_tag(char *session_id, char *tag);

/*
 * Set the AnalyzerVersion field for the given session
 * The defined field PROG_VERSION in glbs.h is used for this
 */
void es_set_version(char *id);

/*
 * set the rule version field in elasticsearch db
 */
void es_set_rule_version(char *id);

/*
 * removes all tags for the given session-id
 */
void es_purge_tags(char *id);

/*
 * removes the given tag in the given session
 */
int es_remove_tag(char *session_id,char *tag);

/*
 * writes the host to elastic search
 */
int es_add_host(char *session_id, char *host);

/*
 * Removes all hosts stored in elastic search
 */
void es_purge_hosts(char *id);

/*
 * Fetches the stored matchdata (tagpatterns with tags)
 */
struct LinkedList* es_get_match_data();


#endif