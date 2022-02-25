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
#include "elasticSearch.h"

//libcurl4-dev required for this import
#include <curl/curl.h>
//libjson-c-dev required for this import
#include<json-c/json.h>
#include<json-c/json_object.h>

//standard imports
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "glbs.h"
#include "pcap.h"
#include "tools/stringBuilder.h"

/*      globals     */
extern struct arguments glb_args;

/*
 * callback function to write curl response into memory instead of stdout
 */
static size_t callback(void *contents, size_t size, size_t nmemb, void *userp){

    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    char *ptr = realloc(mem->memory,mem->size + realsize + 1);
    if(!ptr){
        printf(STATUS_ERROR"out of memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]),contents,realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;

}

MemoryStruct* es_execute(char *url, char *payload){

    if(url == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_execute/url is NULL\n");
        return NULL;
    }

    CURL *curl;
    CURLcode res;
    struct MemoryStruct *retVal = malloc(sizeof(struct MemoryStruct));
    retVal->memory = malloc(1);
    retVal->size = 0;

    //curl init
    curl_global_init(CURL_GLOBAL_ALL);

    //init the curl session
    curl = curl_easy_init();

    //specify url
    curl_easy_setopt(curl,CURLOPT_URL,url);

    //set header for request
    struct curl_slist *header = NULL;
    header = curl_slist_append(header, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);

    if(payload != NULL){
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    }

    //set callback funktion
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,callback);

    //set a pointer to link to *userp in callback function
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,(void *)retVal);

    //execute the prepared curl command
    res = curl_easy_perform(curl);

    if(res != CURLE_OK){
        //ERROR CASE
        fprintf(STATUS_STREAM,STATUS_ERROR" curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        free(retVal->memory);
        free(retVal);
        retVal = NULL;
    }

    //cleanup
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    curl_slist_free_all(header);

    return retVal;
}

int es_get_session(char *session_id, struct Session *session){

    struct MemoryStruct *res;

    //extract index from id
    #if PROD
    char index[17];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+10,session_id,6);
    index[16] = '\0';
    #else
    char index[24];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+17,session_id,6);
    index[23] = '\0';
    #endif

    //build url
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/");
    sb_append(url,ES_DOC);
    sb_append(url,"/");
    sb_append(url,session_id);
    sb_append(url,"?pretty=true");

    if(glb_args.FLAG_VERBOSE){
        printf("url for get session = %s\n",url->string);
    }

    res = es_execute(url->string,NULL);

    if(res != NULL){

        if(DEBUG){
            printf("%s\n",res->memory);
        }

        struct json_object *parsed_json;
        struct json_object *found_json;
        struct json_object *source_json;
        struct json_object *packetPos_json;
        struct json_object *pos_json;
        size_t n_packets;

        parsed_json = json_tokener_parse(res->memory);

        json_object_object_get_ex(parsed_json, "found", &found_json);

        if(strcmp("true",json_object_get_string(found_json)) == 0){
            
            session->json = parsed_json;
            json_object_object_get_ex(parsed_json, "_source", &source_json);
            json_object_object_get_ex(source_json, "packetPos", &packetPos_json);
            n_packets = json_object_array_length(packetPos_json);

            int64_t packetPos[n_packets - 1];

            pos_json = json_object_array_get_idx(packetPos_json, 0);
            const char *fileIndex = json_object_get_string(pos_json);

            for(size_t i=1;i<n_packets;i++) {
                pos_json = json_object_array_get_idx(packetPos_json, i);
                packetPos[i-1] = atoll(json_object_get_string(pos_json));
            }	

            //get the filename from the db
            char *filename = (char*) es_get_filename(fileIndex);

            if(glb_args.FLAG_VERBOSE){
                printf("filename = %s\n",filename);
            }

            // store the most relevant fields into session struct
            //copy number of pcap packets
            session->nPackets = n_packets-1; //TODO is that needed?
            session->pcap_count = n_packets-1;

            // //Analyzer Version
            // struct json_object *analyzerVersion_json;
            // json_object_object_get_ex(source_json, "AnalyzerVersion", &analyzerVersion_json);
            // session->analyzer_version = (char*) json_object_get_string(analyzerVersion_json);
            
            // //Rule Version
            // struct json_object *ruleVersion_json;
            // json_object_object_get_ex(source_json, "RuleVersion", &ruleVersion_json);
            // session->rule_version = json_object_get_int(ruleVersion_json);

            // //copy pcap filename
            session->pcap_filename = calloc(1,strlen(filename)+1);
            strcpy(session->pcap_filename,filename);
            
            es_parse_session(session);

            //copy pcap offset array
            session->pcap_positions = calloc(session->pcap_count,sizeof(int64_t));
            for (size_t i = 0; i < session->pcap_count; i++){
                session->pcap_positions[i] = packetPos[i];
            }

            // session->packets = pcap_get_packets(filename,packetPos,n_packets-1);
            free(filename); //TODO cleanup

            // if(session->nPackets != 0 && session->packets == NULL){
            //     fprintf(STATUS_STREAM,STATUS_WARNING" problem with pcap file at session-id: %s\n",session_id);
            // }            

        }else{
            fprintf(STATUS_STREAM,STATUS_WARNING" session-id not found in db");
            return 0;
        }

    }

    sb_free(url);
    free(res->memory);
    free(res);
    return 1;
}

void es_parse_session(struct Session *session){

    if(session == NULL){ return; }

    if(PROD){

        struct json_object *source_json;
        json_object_object_get_ex(session->json,"_source",&source_json);

        //timestamp
        struct json_object *timestamp_json;
        json_object_object_get_ex(source_json, "timestamp", &timestamp_json);
        session->timestamp_string = (char*) json_object_get_string(timestamp_json);
        session->timestamp = json_object_get_int64(timestamp_json);

        //Analyzer Version
        struct json_object *analyzerVersion_json;
        json_object_object_get_ex(source_json, "AnalyzerVersion", &analyzerVersion_json);
        session->analyzer_version = (char*) json_object_get_string(analyzerVersion_json);
        
        //Rule Version
        struct json_object *ruleVersion_json;
        json_object_object_get_ex(source_json, "RuleVersion", &ruleVersion_json);
        session->rule_version = json_object_get_int(ruleVersion_json);

        //source ip
        struct json_object *src_ip_json;
        json_object_object_get_ex(source_json, "srcIp", &src_ip_json);
        session->src_ip = (char*)json_object_get_string(src_ip_json);

        //destination ip
        struct json_object *dst_ip_json;
        json_object_object_get_ex(source_json, "dstIp", &dst_ip_json);
        session->dst_ip = (char*)json_object_get_string(dst_ip_json);

        //source port
        struct json_object *src_port_json;
        json_object_object_get_ex(source_json, "srcPort", &src_port_json);
        session->src_port = (char*)json_object_get_string(src_port_json);

        //destination port
        struct json_object *dst_port_json;
        json_object_object_get_ex(source_json, "dstPort", &dst_port_json);
        session->dst_port = (char*)json_object_get_string(dst_port_json);

        //source macs
        struct json_object *src_mac_json;
        json_bool ret = json_object_object_get_ex(source_json, "srcMac", &src_mac_json);
        if(src_mac_json != NULL){
            session->src_macs_count = json_object_array_length(src_mac_json);
            session->src_macs = calloc(session->src_macs_count,sizeof(char*));
            for (size_t i = 0; i < session->src_macs_count; i++){
                struct json_object *mac_json = json_object_array_get_idx(src_mac_json,i);
                char *mac = (char*)json_object_get_string(mac_json);
                session->src_macs[i] = calloc(1,strlen(mac)+1);
                strcpy(session->src_macs[i],mac);
            }
        }

        //destination macs
        struct json_object *dst_mac_json;
        json_object_object_get_ex(source_json, "dstMac", &dst_mac_json);
        if(dst_mac_json != NULL){
            session->dst_macs_count = json_object_array_length(dst_mac_json);
            session->dst_macs = calloc(session->dst_macs_count,sizeof(char*));
            for (size_t i = 0; i < session->dst_macs_count; i++){
                struct json_object *mac_json = json_object_array_get_idx(dst_mac_json,i);
                char *mac = (char*)json_object_get_string(mac_json);
                session->dst_macs[i] = calloc(1,strlen(mac)+1);
                strcpy(session->dst_macs[i],mac);
            }
        }

        //vlan
        struct json_object *vlans_json;
        json_object_object_get_ex(source_json, "vlan", &vlans_json);
        if(vlans_json != NULL){
            session->vlan_count = json_object_array_length(vlans_json);
            session->vlans = calloc(session->vlan_count,sizeof(char*));
            for (size_t i = 0; i < session->vlan_count; i++){
                struct json_object *vlan_json = json_object_array_get_idx(vlans_json,i);
                char *vlan = (char*)json_object_get_string(vlan_json);
                session->vlans[i] = calloc(1,strlen(vlan)+1);
                strcpy(session->vlans[i],vlan);
            }
        }

        
    }
}

const char* es_get_filename(const char *id){
    //id= PCAPPREFIX+"-number" example vm-1341
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    char *id_dup = strdup(id);
    char *retVal = NULL;

    //build url
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,ES_FILEINDEX);
    sb_append(url,"/");
    sb_append(url,ES_DOC);
    sb_append(url,"/");
    sb_append(url,PCAPPREFIX);
    sb_append(url,id_dup);
    sb_append(url,"?pretty=true");
    // char* urlBuild[] = {ES_URL, "/", ES_FILEINDEX, "/", ES_DOC, "/",PCAPPREFIX, id_dup, "?pretty=true"};
    // char* url = malloc(1);
    // concat(urlBuild,9,&url);

    //execute curl
    //curl init
    curl_global_init(CURL_GLOBAL_ALL);

    //init the curl session
    curl = curl_easy_init();

    //specify url
    curl_easy_setopt(curl,CURLOPT_URL,url->string);

    //set callback funktion
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,callback);

    //set a pointer to link to *userp in callback function
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,(void *)&chunk);

    //execute the prepared curl command
    res = curl_easy_perform(curl);

    if(res != CURLE_OK){
        fprintf(STATUS_STREAM,STATUS_ERROR" error while performing curl\n");
    }else{

        struct json_object *parsed_json;
        struct json_object *found_json;
        struct json_object *source_json;
        struct json_object *filename_json;

        parsed_json = json_tokener_parse(chunk.memory);
        json_object_object_get_ex(parsed_json,"_source",&source_json);
        json_object_object_get_ex(source_json,"name",&filename_json);

        retVal = strdup(json_object_get_string(filename_json));
        json_object_put(parsed_json);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(chunk.memory);
    sb_free(url);
    free(id_dup);
    return retVal;
}

int es_add_tag(char *session_id, char *tag){

    if(session_id == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_tag:session_id is null\n");
        return false;
    }

    if(strlen(session_id) < 6){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_tag:session_id too short\n");
        return false;
    }

    if(tag == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_tag:tag is null\n");
        return false;
    }

    int returncode;
    struct MemoryStruct *chunk;

    //extract index from id
    #if PROD
    char index[17];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+10,session_id,6);
    index[16] = '\0';
    #else
    char index[24];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+17,session_id,6);
    index[23] = '\0';
    #endif
    // char index[17];
    // strcpy(index,ES_INDEXPREFIX);
    // memcpy(index+10,session_id,6);
    // index[16] = '\0';
    // struct StringBuilder *index_sb = newStringBuilder();
    // sb_append(index_sb,ES_INDEXPREFIX);
    // sb_append(index_sb,session_id);

    //build url
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/");
    sb_append(url,ES_DOC);
    sb_append(url,"/");
    sb_append(url,session_id);
    sb_append(url,"/");
    sb_append(url,ES_UPDATE);
    sb_append(url,"?pretty=true");
    if(DEBUG) printf("url for add tag = \n%s\n",url->string);

    //set post data / script payload
    /*
        {
            "script":{
                "source":"
                    if(ctx._source.tags == null){
                        ctx._source.tags = [params.tag];
                        ctx._source.tagsCnt = 1;
                    }else if(!ctx._source.tags.contains(params.tag)){
                        ctx._source.tags.add(params.tag);
                        ctx._source.tagsCnt += params.increment;
                    }
                    ",
                "lang":"painless",
                "params":{
                    "tag":"<tagname>",
                    "increment":1
                }
            }
        }
    */
    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{\"script\":{\"source\":\"if(ctx._source.tags == null){ctx._source.tags = [params.tag]; ctx._source.tagsCnt = 1;}else if(!ctx._source.tags.contains(params.tag)){ctx._source.tags.add(params.tag); ctx._source.tagsCnt += params.increment;}\",\"lang\":\"painless\",\"params\":{\"tag\":\"");
    sb_append(data,tag);
    sb_append(data, "\",\"increment\":1}}}");
    if(DEBUG) printf("data string to send = \n%s\n",data->string); 
    
    //execute the command in elastic search db
    chunk = es_execute(url->string,data->string);

    if(chunk == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" error in es_add_tag, memoryStruct is NULL\n");
        returncode = false;
    }else{
        //OK
        if(DEBUG){
            printf("es_add_tag return value from elastic search:\n");
            printf("%s",chunk->memory);
            printf("\n");
        }

        //check if execution worked
        struct json_object *parsed_json;
        struct json_object *result_json; 
        struct json_object *error_json;

        parsed_json = json_tokener_parse(chunk->memory);
        json_object_object_get_ex(parsed_json,"result", &result_json);
        json_object_object_get_ex(parsed_json,"error", &error_json);

        if( error_json == NULL && 
            result_json != NULL &&
            strcmp(json_object_get_string(result_json),"updated") == 0){
            //everything worked
            returncode = true;
        }else{
            returncode = false;
            fprintf(STATUS_STREAM,STATUS_ERROR" elastic search returned error json reply:\n");
            fprintf(STATUS_STREAM,"%s",chunk->memory);
            fprintf(STATUS_STREAM,"\n");
        }

        json_object_put(parsed_json);
    }
    
    //clean up and return
    free(chunk->memory);
    free(chunk);
    sb_free(url);
    sb_free(data);
    return returncode;
}

int es_remove_tag(char *session_id,char *tag){
    
    int returncode = false;
    struct MemoryStruct *chunk;

    if(session_id == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_execute/url is NULL\n");
        return false;
    }

    if(tag == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_execute/payload is NULL\n");
        return false;
    }

    //extract index from id
    #if PROD
    char index[17];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+10,session_id,6);
    index[16] = '\0';
    #else
    char index[24];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+17,session_id,6);
    index[23] = '\0';
    #endif
    // struct StringBuilder *index_sb = newStringBuilder();
    // sb_append(index_sb,ES_INDEXPREFIX);
    // sb_append(index_sb,session_id);

    /*
      ES_URL/index/_doc/session_id/_update?pretty=true
    */
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/");
    sb_append(url,ES_DOC);
    sb_append(url,"/");
    sb_append(url,session_id);
    sb_append(url,"/");
    sb_append(url,ES_UPDATE);
    sb_append(url,"?pretty=true");
    if(DEBUG) printf("url for remove_tag = \n%s\n",url->string);

    /*
        {
            "script":{
                "source":"
                    if(ctx._source.tags != null && ctx._source.tags.contains(params.tag)){
                        ctx._source.tags.remove(ctx._source.tags.indexOf(params.tag));
                        ctx._source.tagsCnt -= params.decrement;
                    }
                ",
                "lang":"painless",
                "params":{
                    "tag":"<tagname>",
                    "decrement":1
                }
            }
        } 
    */
   struct StringBuilder *data = newStringBuilder();
   sb_append(data,
    "{"
        "\"script\":{"
            "\"source\":\""
                "if(ctx._source.tags != null && ctx._source.tags.contains(params.tag)){"
                    "ctx._source.tags.remove(ctx._source.tags.indexOf(params.tag));"
                    "ctx._source.tagsCnt -= params.decrement;"
                "}"
            "\","
            "\"lang\":\"painless\","
            "\"params\":{"
            "\"tag\":\""
    );
    sb_append(data,tag);
    sb_append(data,"\",\"decrement\":1}}}");
    if(DEBUG) printf("data for remove_tag = \n%s\n",data->string);

    chunk = es_execute(url->string,data->string);

    printf("%s\n", chunk->memory);

    return returncode;
}

int es_add_host(char *session_id, char *host){

    if(session_id == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_host:session_id is null\n");
        return false;
    }

    if(strlen(session_id) < 6){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_host:session_id too short\n");
        return false;
    }

    if(host == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" es_add_host:host is null\n");
        return false;
    }

    int returncode;
    struct MemoryStruct *chunk;

    //extract index from id
    #if PROD
    char index[17];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+10,session_id,6);
    index[16] = '\0';
    #else
    char index[24];
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+17,session_id,6);
    index[23] = '\0';
    #endif
    // char index[17];
    // strcpy(index,ES_INDEXPREFIX);
    // memcpy(index+10,session_id,6);
    // index[16] = '\0';
    // struct StringBuilder *index_sb = newStringBuilder();
    // sb_append(index_sb,ES_INDEXPREFIX);
    // sb_append(index_sb,session_id);

    //build url
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/");
    sb_append(url,ES_DOC);
    sb_append(url,"/");
    sb_append(url,session_id);
    sb_append(url,"/");
    sb_append(url,ES_UPDATE);
    sb_append(url,"?pretty=true");
    if(DEBUG) printf("url for add host = \n%s\n",url->string);

    //set post data / script payload
    /*
        {
            "script":{
                "source":"
                    if(ctx._source.tags == null){
                        ctx._source.tags = [params.tag];
                        ctx._source.tagsCnt = 1;
                    }else if(!ctx._source.tags.contains(params.tag)){
                        ctx._source.tags.add(params.tag);
                        ctx._source.tagsCnt += params.increment;
                    }
                    ",
                "lang":"painless",
                "params":{
                    "tag":"<tagname>",
                    "increment":1
                }
            }
        }
    */
    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{\"script\":{\"source\":\"if(ctx._source.FoundHosts == null){ctx._source.FoundHosts = [params.host]; ctx._source.FoundHostsCnt = 1;}else if(!ctx._source.FoundHosts.contains(params.host)){ctx._source.FoundHosts.add(params.host); ctx._source.FoundHostsCnt += params.increment;}\",\"lang\":\"painless\",\"params\":{\"host\":\"");
    sb_append(data,host);
    sb_append(data, "\",\"increment\":1}}}");
    if(DEBUG) printf("data string to send = \n%s\n",data->string); 
    
    //execute the command in elastic search db
    chunk = es_execute(url->string,data->string);

    if(chunk == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" error in es_add_host, memoryStruct is NULL\n");
        returncode = false;
    }else{
        //OK
        if(DEBUG){
            printf("es_add_host return value from elastic search:\n");
            printf("%s",chunk->memory);
            printf("\n");
        }

        //check if execution worked
        struct json_object *parsed_json;
        struct json_object *result_json; 
        struct json_object *error_json;

        parsed_json = json_tokener_parse(chunk->memory);
        json_object_object_get_ex(parsed_json,"result", &result_json);
        json_object_object_get_ex(parsed_json,"error", &error_json);

        if( error_json == NULL && 
            result_json != NULL &&
            strcmp(json_object_get_string(result_json),"updated") == 0){
            //everything worked
            returncode = true;
        }else{
            returncode = false;
            fprintf(STATUS_STREAM,STATUS_ERROR" elastic search returned error json reply:\n");
            fprintf(STATUS_STREAM,"%s",chunk->memory);
            fprintf(STATUS_STREAM,"\n");
        }

        json_object_put(parsed_json);
    }
    
    //clean up and return
    free(chunk->memory);
    free(chunk);
    sb_free(url);
    sb_free(data);
    return returncode;
}

void es_purge_hosts(char *id){
    char *index = indexfromSession(id);

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/"ES_UPDATE"/");
    sb_append(url,id);

    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{ \"script\" : \"ctx._source.FoundHosts = []; ctx._source.FoundHostsCnt = 0\" }");

    struct MemoryStruct *res =  es_execute(url->string,data->string);

    //cleanup
    sb_free(url);
    sb_free(data);
    free(index);
    free(res->memory);
    free(res);
}

int es_get_ids(char *index,struct StringArray *dataptr){
    //     curl http://localhost:9200/sessions2-210529/session/_search?pretty=true -H 'Content-Type: application/json' -d '
    // { 
    //     "query" : { 
    //         "match_all" : {} 
    //     },
    //     "stored_fields": []
    // }
    // '
    //lists every id of the session type in the given index
    //response:
    // {
    //   "_index" : "sessions2-210529",
    //   "_type" : "session",
    //   "_id" : "210529--0sZ5o3xErdNg5_D7HxHW6IB",
    //   "_score" : 1.0
    // }

    CURL *curl;
    CURLcode res;
    int returncode;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    //build url
    struct StringBuilder *url = newStringBuilder(); 
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/"ES_SEARCH"?scroll=10m;pretty=true"); // /session
    if(DEBUG) printf("url for get ids = %s\n",url->string);

    //curl init
    curl_global_init(CURL_GLOBAL_ALL);

    //init the curl session
    curl = curl_easy_init();

    //specify url
    curl_easy_setopt(curl,CURLOPT_URL,url->string);

    //set header for request
    struct curl_slist *header = NULL;
    header = curl_slist_append(header, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);

    //set post data / script payload
    // { 
    //     "query" : { 
    //         "match_all" : {} 
    //     },
    //     "stored_fields": []
    // }
    char* data = "{\"size\":1000,\"query\":{\"match_all\":{}},\"stored_fields\":[]}";
    if(DEBUG) printf("data string to send = %s\n",data); 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);

    //set callback funktion
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,callback);

    //set a pointer to link to *userp in callback function
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,(void *)&chunk);

    //execute the prepared curl command
    res = curl_easy_perform(curl);

    if(res != CURLE_OK){
        fprintf(STATUS_STREAM,STATUS_ERROR" curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        returncode = false;
    }else{
        //OK
        //check for succsesful execution
        struct json_object *parsed_json;
        struct json_object *error_json;
        struct json_object *hits_json;
        struct json_object *hitArray_json;
        struct json_object *doc_json;
        struct json_object *docId_json;
        struct json_object *scrollId_json;
        size_t n_hits;

        parsed_json = json_tokener_parse(chunk.memory);
        json_object_object_get_ex(parsed_json,"error", &error_json);
        json_object_object_get_ex(parsed_json,"hits", &hits_json);
        json_object_object_get_ex(parsed_json,"_scroll_id", &scrollId_json);
        char *scrollId = (char*)json_object_get_string(scrollId_json);
        json_object_object_get_ex(hits_json,"hits", &hitArray_json);
        n_hits = json_object_array_length(hitArray_json);

        if(error_json != NULL){
            //error case
            fprintf(STATUS_STREAM,STATUS_ERROR" es_get_ids()/elastic search returned error\n");
        }else{
            //ok
            if(DEBUG) fprintf(STATUS_STREAM,"scroll id = %s\n", (char*)json_object_get_string(scrollId_json));

            //process the first patch of data
            for (size_t i = 0; i < n_hits; i++){
                doc_json = json_object_array_get_idx(hitArray_json, i);
                json_object_object_get_ex(doc_json,"_id", &docId_json);
                
                char *id = (char*)json_object_get_string(docId_json);
                
                //store string in array
                expandArray(dataptr);
                dataptr->data[dataptr->size-1] = calloc(1,strlen(id)+1);
                memcpy(dataptr->data[dataptr->size-1],id,strlen(id));
            }

            //process the next patch of data until no entries left
            //end of entries is indiceated with an empty array hits[]
            while(n_hits != 0){
                // curl http://localhost:9200/_search/scroll?scroll=10m -H 'Content-Type: application/json' -d '
                // {
                // "scroll_id":"FGluY2x1ZGVfY29udGV4dF91dWlkDXF1ZXJ5QW5kRmV0Y2gBFlNFT09zQUpDVE91RDh3dGRBVGZ1bGcAAAAAAAAABRZDRFpoTjVsQlJsS01vdnFmMFRhV0lB"
                // }
                // '
                struct MemoryStruct scrollChunk;
                scrollChunk.memory = malloc(1);
                scrollChunk.size = 0;

                struct json_object *scroll_parsed_json;
                struct json_object *scroll_error_json;
                struct json_object *scroll_hits_json;
                struct json_object *scroll_hitArray_json;
                struct json_object *scroll_doc_json;
                struct json_object *scroll_docId_json;

                //build url
                struct StringBuilder *scrollUrl = newStringBuilder();
                sb_append(scrollUrl,glb_args.es_url);
                sb_append(scrollUrl,"/");
                sb_append(scrollUrl,ES_SEARCH);
                sb_append(scrollUrl,"/");
                sb_append(scrollUrl,"scroll");
                sb_append(scrollUrl,"?scroll=10m");
                if(DEBUG) printf("url for next scroll = \n%s\n",scrollUrl->string);

                //specify url
                curl_easy_setopt(curl,CURLOPT_URL,scrollUrl->string);

                //set post data / script payload
                struct StringBuilder *scrollData = newStringBuilder();
                sb_append(scrollData,"{\"scroll_id\":\"");
                sb_append(scrollData,scrollId);
                sb_append(scrollData,"\"}");
                if(DEBUG) printf("data string to send = \n%s\n",scrollData->string);

                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, scrollData->string);
                
                //set callback funktion
                curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,callback);

                //set a pointer to link to *userp in callback function
                curl_easy_setopt(curl,CURLOPT_WRITEDATA,(void *)&scrollChunk);
                
                //execute the prepared curl command
                res = curl_easy_perform(curl);

                if(res != CURLE_OK){
                    fprintf(STATUS_STREAM,STATUS_ERROR" curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
                    returncode = false;
                }else{
                    
                    scroll_parsed_json = json_tokener_parse(scrollChunk.memory);
                    json_object_object_get_ex(scroll_parsed_json,"hits", &scroll_hits_json);

                    json_object_object_get_ex(scroll_hits_json,"hits", &scroll_hitArray_json);
                    n_hits = json_object_array_length(scroll_hitArray_json);

                    //store the batch of ids
                    for (size_t i = 0; i < n_hits; i++){
                        scroll_doc_json = json_object_array_get_idx(scroll_hitArray_json, i);
                        json_object_object_get_ex(scroll_doc_json,"_id", &scroll_docId_json);
                        
                        char *id = (char*)json_object_get_string(scroll_docId_json);
                        
                        //store string in array
                        expandArray(dataptr);
                        dataptr->data[dataptr->size-1] = calloc(1,strlen(id)+1);
                        memcpy(dataptr->data[dataptr->size-1],id,strlen(id));
                    }

                }

                //scroll cleanup
                sb_free(scrollUrl);
                sb_free(scrollData);
                free(scrollChunk.memory); 
                json_object_put(scroll_parsed_json);             

            }
        }
        //cleanup
        json_object_put(parsed_json); 
    }

    //clean up and return
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    sb_free(url);
    free(chunk.memory);
    curl_slist_free_all(header);

    return true;
}

void es_set_version(char *id){
    //     curl -X POST "localhost:9200/arkime_sessions3-210902/_update/210902-bTV2B7FHkgZJnbAGWwHCXczM?pretty" -H 'Content-Type: application/json' -d'
    // {
    //   "script" : "ctx._source.AnalyzerVersion = \u0027v0.2\u0027"
    // }
    // '
    if(index == NULL){ 
        fprintf(STATUS_STREAM,STATUS_WARNING" es_set_version/index is null\n");
        return;
    }

    if(id == NULL){ 
        fprintf(STATUS_STREAM,STATUS_WARNING" es_set_version/id is null\n");
        return;
    }

    char *index = indexfromSession(id);

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/"ES_UPDATE"/");
    sb_append(url,id);

    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{\"script\" : \"ctx._source.AnalyzerVersion = \'"PROG_VERSION"\'\"}");

    struct MemoryStruct *res = es_execute(url->string,data->string);

    free(index);
    sb_free(url);
    sb_free(data);
    free(res->memory);
    free(res);
    return;
}

void es_set_rule_version(char *id){
    //     curl -X POST "localhost:9200/arkime_sessions3-210902/_update/210902-bTV2B7FHkgZJnbAGWwHCXczM?pretty" -H 'Content-Type: application/json' -d'
    // {
    //   "script" : "ctx._source.RuleVersion = \u0027 RULEVERSION \u0027"
    // }
    // '
    if(index == NULL){ 
        fprintf(STATUS_STREAM,STATUS_WARNING" es_set_rule_version/index is null\n");
        return;
    }

    if(id == NULL){ 
        fprintf(STATUS_STREAM,STATUS_WARNING" es_set_rule_version/id is null\n");
        return;
    }

    char *index = indexfromSession(id);

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/"ES_UPDATE"/");
    sb_append(url,id);

    struct StringBuilder *data = newStringBuilder();
    char version_string[50];
    sprintf( version_string, "%d", RULEVERSION );
    sb_append(data,"{\"script\" : \"ctx._source.RuleVersion = \' ");
    sb_append(data,version_string);
    sb_append(data,"\'\"}");

    struct MemoryStruct *res = es_execute(url->string,data->string);

    free(index);
    sb_free(url);
    sb_free(data);
    free(res->memory);
    free(res);
    return;
}

void es_purge_tags(char *id){
    // curl -X POST "localhost:9200/arkime_sessions3-210902/_update/210902-bTV2B7FHkgZJnbAGWwHCXczM?pretty" -H 'Content-Type: application/json' -d'
    // {
    //  "script" : "ctx._source.tags = []; ctx._source.tagsCnt = 0"
    // }
    // '

    char *index = indexfromSession(id);

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/");
    sb_append(url,index);
    sb_append(url,"/"ES_UPDATE"/");
    sb_append(url,id);

    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{ \"script\" : \"ctx._source.tags = []; ctx._source.tagsCnt = 0\" }");

    struct MemoryStruct *res =  es_execute(url->string,data->string);

    //cleanup
    sb_free(url);
    sb_free(data);
    free(index);
    free(res->memory);
    free(res);

}