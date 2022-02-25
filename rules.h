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
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "glbs.h"
#include "tools/LinkedList.h"

/*
 * rules must implement the following signature
 * void <name>(struct Session *session, struct LinkedList *tags)
 * added rules must be included in the rule_ptr array at the end of this file to be applied
 * session:
 *  struct json_object *Session::json
 *  size_t Session::nPackets
 *  Packet **Session::packets
*/

/*
example json from PROD-DB
{ 
    "_index": "sessions2-210906",
    "_type": "_doc",
    "_id": "210906-eD8vlU4FX6FKTqrqTDYRxNrV",
    "_version": 1, 
    "_seq_no": 2742, 
    "_primary_term": 1, 
    "found": true, 
    "_source": { 
        "firstPacket": 1630909874918, 
        "lastPacket": 1630909875337, 
        "length": 420, 
        "ipProtocol": 6, 
        "communityId": "1:M9i7+pTnADaqhFlqk7TkR8UF66g=", 
        "tcpflags": { 
            "syn": 0, 
            "syn-ack": 0, 
            "ack": 1, 
            "psh": 2, 
            "fin": 0, 
            "rst": 0, 
            "urg": 0, 
            "srcZero": 0, 
            "dstZero": 0 
        }, 
        "timestamp": 1630910486669, 
        "srcIp": "10.111.222.114", 
        "dstIp": "142.250.157.188", 
        "srcPort": 46554, 
        "dstPort": 443, 
        "totPackets": 3, 
        "srcPackets": 2, 
        "dstPackets": 1, 
        "totBytes": 264, 
        "srcBytes": 168, 
        "dstBytes": 96, 
        "totDataBytes": 0, 
        "srcDataBytes": 0, 
        "dstDataBytes": 0, 
        "segmentCnt": 1, 
        "node": "adsec-traffic", 
        "packetPos": [ -283, 58673492, 114, 112 ], 
        "fileId": [ 283 ], 
        "srcMacCnt": 1, 
        "srcMac": [ "58:cb:52:17:e0:06" ], 
        "dstMacCnt": 1, 
        "dstMac": [ "04:f0:21:23:21:81" ], 
        "vlanCnt": 1, 
        "vlan": [ 204 ], 
        "protocolCnt": 1, 
        "protocol": [ "tcp" ],
        "tags": [ "encrypted" ], 
        "tagsCnt": 1, 
        "AnalyzerVersion": "v0.4"
    } 
}
*/

/*
    example json from TEST-DB
{ 
    "_index": "arkime_sessions3-210904", 
    "_type": "_doc", 
    "_id": "210904-KBKmDB1HsLZBcYTVHXnO-e_-", 
    "_version": 6, 
    "_seq_no": 3561, 
    "_primary_term": 2, 
    "found": true, 
    "_source": { 
        "firstPacket": 1630782882900, 
        "lastPacket": 1630782883784, 
        "length": 885, 
        "ipProtocol": 58, 
        "@timestamp": 1630782895721, 
        "source": { 
            "ip": "fe80::3aa2:97c3:3eb6:3b70", 
            "port": 0, 
            "bytes": 300, 
            "packets": 2, 
            "mac-cnt": 1, 
            "mac": [ "52:54:00:a0:59:b7" ] 
        }, 
        "destination": { 
            "ip": "ff02::16", 
            "port": 0, 
            "bytes": 0, 
            "packets": 0, 
            "mac-cnt": 1, 
            "mac": [ "33:33:00:00:00:16" ] 
        }, 
        "network": { 
            "packets": 2, 
            "bytes": 300 
        }, 
        "client": { 
            "bytes": 176 
        }, 
        "server": { 
            "bytes": 0 
        }, 
        "totDataBytes": 176, 
        "segmentCnt": 1, 
        "node": "vm", 
        "packetPos": [ -127, 1551192, 166 ], 
        "fileId": [ 127 ], 
        "icmp": { 
            "code": [ 0 ], 
            "type": [ 143 ] 
        }, 
        "protocolCnt": 1, 
        "protocol": [ "icmp" ], 
        "srcOuiCnt": 1, 
        "srcOui": [ "Realtek (UpTech? also reported)" ], 
        "AnalyzerVersion": "v0.4", 
        "tags": [ "test-tag" ], 
        "tagsCnt": 1 
    } 
}

*/

/* definitions */
typedef void (*rule)(Session*, LinkedList*);

/* globals */
extern MatchData *matchdata;
extern Arguments glb_args;

/*******************************************************/
/*
 * add the tag encrypted if the port 433 is detected ether in source or destination
 */
void rule_encrypted(Session *session, LinkedList *tags){

    long source_port = atol(session->src_port);
    long destination_port = atol(session->dst_port);

    if(source_port == 443 || destination_port == 443){
        ll_add_string_distinct(tags,"encrypted");
    }

    return;
}
/*******************************************************/

void rule_updates(Session *session, LinkedList *tags){

    char update_mintime_string[20];
    int64_t update_mintime = session->timestamp - MAXUPDATELENGTH;
    sprintf(update_mintime_string, "%lu", update_mintime);

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/updates/_search?pretty");

    /*
    curl -XGET localhost:9200/updates/_search?pretty=true -H 'Content-Type: application/json' -d'
    {
        "sort":{ "timestamp":{"order":"desc"}},
        "size":1,
        "query": {
            "bool":{
                "filter":[
                    {"term":{ "vlan":"1234"}},
                    {"range":{
                        "timestamp":{
                            "lte":"1629732708771",
                            "gte":"1629732108771"
                        }
                    }}
                ]
            }
        }
    }'
    */
    struct StringBuilder *data_src = newStringBuilder();
    sb_append(data_src,"{\"sort\":{ \"timestamp\":{\"order\":\"desc\"}}, \
        \"size\":1,\"query\": { \"bool\":{ ");
    sb_append(data_src,"\"filter\":[ {\"term\":{ \"vlan\": \"");
    sb_append(data_src,session->vlans[0]);
    sb_append(data_src,"\"}},{\"range\":{ \
        \"timestamp\":{\"lte\":\"");
    sb_append(data_src,session->timestamp_string);
    sb_append(data_src,"\",\"gte\":\"");
    sb_append(data_src,update_mintime_string);
    sb_append(data_src,"\"}}}]}}}");

    //same as src_dst but with dst_mac
    struct StringBuilder *data_dst = newStringBuilder();
    sb_append(data_dst,"{\"sort\":{ \"timestamp\":{\"order\":\"desc\"}}, \
        \"size\":1,\"query\": { \"bool\":{ ");
    sb_append(data_dst,"\"filter\":[ {\"term\":{ \"mac\": \"");
    sb_append(data_dst,session->dst_macs[0]);
    sb_append(data_dst,"\"}},{\"range\":{ \
        \"timestamp\":{\"lte\":\"");
    sb_append(data_dst,session->timestamp_string);
    sb_append(data_dst,"\",\"gte\":\"");
    sb_append(data_dst,update_mintime_string);
    sb_append(data_dst,"\"}}}]}}}");

    struct MemoryStruct *res_src = es_execute(url->string,data_src->string);
    struct MemoryStruct *res_dst = es_execute(url->string,data_dst->string);

    //process the responses
    struct json_object *src_json;
    struct json_object *src_hits_json;
    struct json_object *src_hits_array_json;
    struct json_object *src_hit_object_json;
    struct json_object *src_source_json;
    struct json_object *src_type_json;

    src_json = json_tokener_parse(res_src->memory);
    json_object_object_get_ex(src_json,"hits",&src_hits_json);
    json_object_object_get_ex(src_hits_json,"hits",&src_hits_array_json);
    src_hit_object_json = json_object_array_get_idx(src_hits_array_json,0);
    json_object_object_get_ex(src_hit_object_json,"_source",&src_source_json);
    json_object_object_get_ex(src_source_json,"type",&src_type_json);
    json_bool src_type = json_object_get_boolean(src_type_json);

    if(src_type){
        ll_add_string_distinct(tags,"update");
    }

    struct json_object *dst_json;
    struct json_object *dst_hits_json;
    struct json_object *dst_hits_array_json;
    struct json_object *dst_hit_object_json;
    struct json_object *dst_source_json;
    struct json_object *dst_type_json;

    dst_json = json_tokener_parse(res_dst->memory);
    json_object_object_get_ex(dst_json,"hits",&dst_hits_json);
    json_object_object_get_ex(dst_hits_json,"hits",&dst_hits_array_json);
    dst_hit_object_json = json_object_array_get_idx(dst_hits_array_json,0);
    json_object_object_get_ex(dst_hit_object_json,"_source",&dst_source_json);
    json_object_object_get_ex(dst_source_json,"type",&dst_type_json);
    json_bool dst_type = json_object_get_boolean(dst_type_json);

    if(dst_type){
        ll_add_string_distinct(tags,"update");
    }

    //cleanup
    json_object_put(src_json);
    json_object_put(dst_json);
    free(res_src->memory);
    free(res_src);
    free(res_dst->memory);
    free(res_dst);
    sb_free(data_src);
    sb_free(data_dst);
    sb_free(url);
}



/*******************************************************/

/*
 *
 */
void rule_dns(Session *session, LinkedList *tags){

    struct json_object *_source_json;
    struct json_object *source_json;
    struct json_object *source_ip_json;
    struct json_object *destination_json;
    struct json_object *destination_ip_json;
    struct json_object *vlan_array_json;
    struct json_object *vlan_json;
    struct json_object *timestamp_json;

    if(PROD){
        json_object_object_get_ex(session->json,"_source",&_source_json);
        json_object_object_get_ex(_source_json,"srcIp",&source_ip_json);
        json_object_object_get_ex(_source_json,"dstIp",&destination_ip_json);
        json_object_object_get_ex(_source_json,"vlan",&vlan_array_json);
        json_object_object_get_ex(_source_json,ES_TIMESTAMP,&timestamp_json);
    }else{
        json_object_object_get_ex(session->json,"_source",&_source_json);
        json_object_object_get_ex(_source_json,ES_TIMESTAMP,&timestamp_json);
        json_object_object_get_ex(_source_json,"vlan",&vlan_array_json);
        json_object_object_get_ex(_source_json,"source",&source_json);
        json_object_object_get_ex(source_json,"ip",&source_ip_json);
        json_object_object_get_ex(_source_json,"destination",&destination_json);
        json_object_object_get_ex(destination_json,"ip",&destination_ip_json);
    }

    //process timestamps
    char timestamp_string[20];
    int64_t timestamp = session->timestamp + 60000;
    sprintf(timestamp_string, "%lu", timestamp);

    char oldest_time_string[20];
    int64_t deltatime = session->timestamp - MAXDNSTIME;
    sprintf(oldest_time_string, "%lu", deltatime);

    struct StringArray *hosts = newStringArray();
    
    struct StringBuilder *url_src = newStringBuilder();
    sb_append(url_src,glb_args.es_url);
    sb_append(url_src,"/session*/_search?pretty=true");

    /*
    {   "_source":["dns.ip","dns.host"],
        "sort":{ "timestamp":{"order":"desc"}},
        "query": {
            "bool":{
                "filter":[
                    {"term":{ "dns.ip":"8.8.8.8"}},
                    {"term":{ "vlan":"141"}},
                    {"range":{
                        "timestamp":{
                            "lte":"1636036455790",
                            "gte":"1636036454790"
                        }
                    }}
                ]
            }
        }
    }
    */
    struct StringBuilder *data_src = newStringBuilder();
    sb_append(data_src,"{");
    sb_append(data_src,"\"_source\":[\"dns.ip\",\"dns.host\"],");
    sb_append(data_src,"\"sort\":{ \"timestamp\":{\"order\":\"desc\"}},");
    sb_append(data_src,"\"query\": {");
    sb_append(data_src,"\"bool\":{");
    sb_append(data_src,"\"filter\":[");
    sb_append(data_src,"{\"term\":{ \"dns.ip\":\"");
    sb_append(data_src,session->src_ip);
    sb_append(data_src,"\"}},");
    sb_append(data_src,"{\"term\":{ \"vlan\":\"");
    sb_append(data_src,session->vlans[0]);
    sb_append(data_src,"\"}},");
    sb_append(data_src,"{\"range\":{");
    sb_append(data_src,"\"timestamp\":{");
    sb_append(data_src,"\"lte\":\"");
    sb_append(data_src,timestamp_string);
    sb_append(data_src,"\",");
    sb_append(data_src,"\"gte\":\"");
    sb_append(data_src,oldest_time_string);
    sb_append(data_src,"\"");
    sb_append(data_src,"}}}]}}}");


    struct StringBuilder *url_dst = newStringBuilder();
    sb_append(url_dst,glb_args.es_url);
    sb_append(url_dst,"/session*/_search?pretty=true");

    struct StringBuilder *data_dst = newStringBuilder();
    sb_append(data_dst,"{");
    sb_append(data_dst,"\"_source\":[\"dns.ip\",\"dns.host\"],");
    sb_append(data_dst,"\"sort\":{ \"timestamp\":{\"order\":\"desc\"}},");
    sb_append(data_dst,"\"query\": {");
    sb_append(data_dst,"\"bool\":{");
    sb_append(data_dst,"\"filter\":[");
    sb_append(data_dst,"{\"term\":{ \"dns.ip\":\"");
    sb_append(data_dst,session->dst_ip);
    sb_append(data_dst,"\"}},");
    sb_append(data_dst,"{\"term\":{ \"vlan\":\"");
    sb_append(data_dst,session->vlans[0]);
    sb_append(data_dst,"\"}},");
    sb_append(data_dst,"{\"range\":{");
    sb_append(data_dst,"\"timestamp\":{");
    sb_append(data_dst,"\"lte\":\"");
    sb_append(data_dst,timestamp_string);
    sb_append(data_dst,"\",");
    sb_append(data_dst,"\"gte\":\"");
    sb_append(data_dst,oldest_time_string);
    sb_append(data_dst,"\"");
    sb_append(data_dst,"}}}]}}}");

    struct MemoryStruct *res_src = es_execute(url_src->string,data_src->string);
    struct MemoryStruct *res_dst = es_execute(url_dst->string,data_dst->string);

    json_object *res_json;
    json_object *hits_json;
    json_object *hits_array_json;
    json_object *hits_elem_json;
    json_object *elem_source_json;
    json_object *source_dns_json;
    json_object *dns_host_array_json;
    json_object *host_elem_json;

    for (size_t res_pos = 0; res_pos < 2; res_pos++){
        if(res_pos == 0){ res_json= json_tokener_parse(res_src->memory); }
        else{ res_json= json_tokener_parse(res_dst->memory); }
        
        json_object_object_get_ex(res_json,"hits",&hits_json);
        json_object_object_get_ex(hits_json,"hits",&hits_array_json);
        size_t size = json_object_array_length(hits_array_json);

        for (size_t i = 0; i < size; i++){
            hits_elem_json = json_object_array_get_idx(hits_array_json,i);
            json_object_object_get_ex(hits_elem_json,"_source",&elem_source_json);
            json_object_object_get_ex(elem_source_json,"dns",&source_dns_json);
            json_object_object_get_ex(source_dns_json,"host",&dns_host_array_json);

            size_t num_hosts = json_object_array_length(dns_host_array_json);
            for (size_t host_pos = 0; host_pos < num_hosts; host_pos++){
                host_elem_json = json_object_array_get_idx(dns_host_array_json,host_pos);
                char *hit_string = (char*) json_object_get_string(host_elem_json);
                sa_add(hosts,hit_string);
            }            
        }

        json_object_put(res_json);
    }

    /* if requested store the found hosts in elastic search */
    if(glb_args.FLAG_STOREHOSTS){
        for (size_t i = 0; i < hosts->size; i++){
            if(glb_args.FLAG_VERBOSE){ fprintf(STATUS_STREAM,STATUS_INFO" adding host: %s\n",hosts->data[i]); }
            es_add_host(session->sessionId,hosts->data[i]);
        }
    }

    for (size_t host_pos = 0; host_pos < hosts->size; host_pos++){
        char *cur_host = hosts->data[host_pos];
        struct MatchData *cur = matchdata;

        if(DEBUG){
            fprintf(STATUS_STREAM,"host: %s\n",hosts->data[host_pos]);
        }

        while(cur != NULL){

            int match= regexec(cur->regex, cur_host, 0, NULL, 0);
            
            
            if(match == REG_NOMATCH){

                if(DEBUG){ fprintf(STATUS_STREAM,STATUS_WARNING" no match\n"); }
            }else{
                if(DEBUG){ fprintf(STATUS_STREAM,STATUS_OK" match\n"); }
                
                //add all tags
                for (size_t i = 0; i < cur->tags->size; i++){
                    ll_add_string_distinct(tags,cur->tags->data[i]);
                }
                
            }
            

            cur = cur->next;
        }


    }    


    sb_free(data_src);
    sb_free(url_src);
    sb_free(data_dst);
    sb_free(url_dst);
    freeArray(hosts);
    free(res_src->memory);
    free(res_src);
    free(res_dst->memory);
    free(res_dst);

}


/*******************************************************/
void rule_nosource(Session *session, LinkedList *tags){
    if(session->packets == NULL && glb_args.MODE_NOPCAP == false){
        ll_add_string_distinct(tags,"error-pcap");
    }
}
/*******************************************************/


/*******************************************************/
void rule_dns_error(Session *session, LinkedList *tags){
    
    json_object *source_json;
    json_object *dns_json;
    json_object *dns_ip_json;
    json_object *protocols_json;
    json_object *protocol_elem_json;
    bool isDns = false;

    json_object_object_get_ex(session->json,"_source",&source_json);
    json_object_object_get_ex(source_json,"dns",&dns_json);
    json_object_object_get_ex(dns_json,"ip",&dns_ip_json);

    json_object_object_get_ex(source_json,"protocol",&protocols_json);
    int size = json_object_array_length(protocols_json);
    for (size_t i = 0; i < size; i++){
        protocol_elem_json = json_object_array_get_idx(protocols_json,i);
        const char *proto_name = json_object_get_string(protocol_elem_json);
        if(strcmp("dns",proto_name) == 0){ isDns = true; }
    }
    

    if(dns_ip_json == NULL && isDns){
        ll_add_string_distinct(tags,"error-DNS-noIp");
    }

}
/*******************************************************/

/*******************************************************/
void rule_test(Session *session, LinkedList *tags){
    /* add test code here */   
}
/*******************************************************/

/*******************************************************/
rule rule_ptrs[] = {
    rule_encrypted,
    rule_updates,
    rule_dns,
    rule_nosource,
    rule_dns_error,
    rule_test,
};
/*******************************************************/
