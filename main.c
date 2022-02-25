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
#include <time.h>
#include <dirent.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <argp.h>
#include <regex.h>

#include "pcap.h"
#include "elasticSearch.h"
#include "glbs.h"
#include "tools/stringBuilder.h"
#include "rules.h"
#include "tools/LinkedList.h"

/*      globals     */
/* contains the regular expression and corresponding tags in a list */
MatchData *matchdata;
/* contains the parsed glb_args */
Arguments glb_args;
const char *argp_program_version = PROG_VERSION;
const char *argp_program_bug_adress = "schwingenschuh.martin@gmail.com";
static char doc[] = "Program for analyzation of elastic search db";
static char args_doc[] = "set exactly one of the scope args --all --cutoff=TIME --id=\n";
static struct argp_option options[] = {
    {"all",'a',0,0,"analyze whole database"},
    {"id",'i',"SESSIONID",0,"analyze only one session"},
    {"cutoff",'c',"CUTOFFTIME",0,"set the delta for the cutofftime in hours"},
    {"verbose",'v',0,0,"Show output"},
    {"hosts",'h',0,0,"Stores the found hosts in elasticsearch"},
    {"nopcap",'p',0,0,"Sets the nopcap mode in which the pcap files will not be extracted"},
    {"ignoreversion",'I',0,0,"Deactivates the rule version check"},
    {"esurl",'e',"URL",0,"Override the default value set by compile options"},
    {"pcapPrefix",'P',"PREFIX",0,"Override the default value set by compile options"},
    {0}
};

/*******************************************************************/

static error_t parse_opt(int key, char *arg, struct argp_state *state){
    struct arguments *glb_args = state->input;
    
    switch (key){ 
    case 'a':
        if(glb_args->FLAG_SCOPE_SET){
            argp_usage(state);
        }
        glb_args->FLAG_ALL = true;
        glb_args->FLAG_SCOPE_SET = true;
        break;
    case 'i':
        if(glb_args->FLAG_SCOPE_SET){
            argp_usage(state);
        }
        glb_args->FLAG_ID = true;
        glb_args->sessionId = arg;
        glb_args->FLAG_SCOPE_SET = true;
        break;
    case 'v':
        glb_args->FLAG_VERBOSE = true;
        break;  
    case 'c':
        if(glb_args->FLAG_SCOPE_SET){
            argp_usage(state);
        }
        glb_args->FLAG_CUTOFF = true;
        glb_args->deltaTime = atol(arg);
        glb_args->FLAG_SCOPE_SET = true;
        break;
    case 'h':
        glb_args->FLAG_STOREHOSTS = true;
        break;
    case 'p':
        glb_args->MODE_NOPCAP = true;
        break;
    case 'I':
        glb_args->FLAG_IGNOREVERSION = true;
        break;
    case 'e':
        glb_args->FLAG_ES_URL_OVERRIDE = true;
        glb_args->es_url = arg;
        break;
    case 'P':
        glb_args->FLAG_PPREFIX_OVERRIDE = true;
        glb_args->pcap_prefix = arg;
        break;
    case ARGP_KEY_INIT:
        //do nothing
        break;
    case ARGP_KEY_NO_ARGS:
        //do nothing
        break;
    case ARGP_KEY_SUCCESS: 
        //do nothing
        break;
    case ARGP_KEY_FINI:
        fprintf(STATUS_STREAM,STATUS_OK" arguments parsed succsessful\n");
        //do nothing
        break;
    case ARGP_KEY_ARG: 
        argp_usage(state);
        break;  
    case ARGP_KEY_END:
        if(!glb_args->FLAG_SCOPE_SET){
            argp_usage(state);
        }
        if(state->argc < 1)argp_usage(state);
        break;   
    default:
        argp_usage(state);
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options,parse_opt,args_doc, doc};

/*
 * Wrapper function
 */
void apply_rule(rule function,Session *session, LinkedList *tags){
    function(session,tags);
}

/*
 * Applies all rules defined in rules.h for one given session defined by session_id
 */
void analyze_session(char *session_id){

    if(glb_args.FLAG_VERBOSE){
        fprintf(STATUS_STREAM," analyzing session : %s\n",session_id);
    }

    //check if the given session id is plausible
    regex_t idreg;
    regcomp(&idreg,"^[0-9]\\{6\\}\\-.*", 0);

    if(regexec(&idreg, session_id,0, NULL, 0) == REG_NOMATCH){
        fprintf(STATUS_STREAM,STATUS_WARNING" given session-id is not valid not analyzing id: %s\n",session_id);
        return;
    }

    regfree(&idreg);

    Session *session = newSession();
    session->sessionId = calloc(1,strlen(session_id) + 1);
    strcpy(session->sessionId,session_id);
    es_get_session(session_id,session);

    // if the nopcap mode is active we skip 
    // the pcap part. Rules have to check for NULL array
    if(!glb_args.MODE_NOPCAP){
        session->packets = pcap_get_packets(
            session->pcap_filename,
            session->pcap_positions,
            session->pcap_count);
    }

    if(glb_args.FLAG_VERBOSE){
        printSession(session);
    }

    // some sessions have no vlan object
    // in that case dont analyze session
    if(session->vlans == NULL){
        es_add_tag(session_id,"error-no-vlan");
        es_set_version(session_id);
        freeSession(session);
        return;
    }

    // only analyze session if the current ruleset is 
    // newer than the stored one
    if(glb_args.FLAG_IGNOREVERSION || RULEVERSION > session->rule_version){
        //delete old hosts
        es_purge_hosts(session_id);
        //delete old tags
        es_purge_tags(session_id);

        //  apply all the rules defined in the file rules.h
        //  and collect the produced tags
        LinkedList *tags = newLinkedList();
        for (size_t i = 0; i < NELEMS(rule_ptrs); i++){
            apply_rule(rule_ptrs[i],session,tags); 
        }

        //add tags to elastic search
        for(size_t i = 0; i < tags->size; i++){
            char *tag = ll_get_string(tags,i);

            if(glb_args.FLAG_VERBOSE){
                fprintf(STATUS_STREAM,STATUS_INFO" adding tag: %s\n",tag);
            }

            es_add_tag(session_id,tag);
        }

        //set the program version and the rule version
        es_set_version(session_id);
        es_set_rule_version(session_id);

        //cleanup
        ll_free(&tags);

        if(glb_args.FLAG_ID){
            fprintf(STATUS_STREAM,STATUS_OK" session analyzed\n");
        }
    }else{
       if(glb_args.FLAG_VERBOSE){ 
           fprintf(STATUS_STREAM,STATUS_INFO" session skiped (ruleversion)\n");
       }
    }

    freeSession(session);
    return;
}

/*
 * Set the scope to the cutofftime and call for each session analyze_session
 */
void analyze_block(char *cutoffTime_string){
    
    //curl command
    // curl -XGET http://localhost:9200/_all/_search?scroll=1m -H 'Content-Type: application/json' -d'
    // {"query":{"range":{"@timestamp":{"gte":1629810337000}}}}''
    //alternative:
    // curl -XGET http://localhost:9200/_all/_search?scroll=1m -H 'Content-Type: application/json' -d'
    // {"query":{"bool":{"must":{"match_all":{}},"filter":{"range":{"@timestamp":{"gte":1629792978000}}}}}}
    StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/"ES_INDEXPREFIX"*""/"ES_SEARCH"?scroll=10m;pretty=true");
    if(DEBUG){ printf("url for cutoff call = %s\n",url->string); }
    
    StringBuilder *data = newStringBuilder();
    sb_append(data,"{\"size\":1000,\
    \"sort\":{\""ES_TIMESTAMP"\":{\"order\" : \"asc\"}}, \
    \"query\":{\"bool\":{\"must\":{\"match_all\":{}},\"filter\":{\"range\":{\""ES_TIMESTAMP"\":{\"gte\":");
    sb_append(data,cutoffTime_string);
    sb_append(data,"}}}}}}");
    if(DEBUG){ printf("data for cutoff call = %s\n",data->string); }

    MemoryStruct *ret = es_execute(url->string,data->string);
    if(DEBUG){ printf("response from elastic search = \n%s\n",ret->memory); }

    struct json_object *parsed_json;
    struct json_object *error_json;
    struct json_object *hits_json;
    struct json_object *hitArray_json;
    struct json_object *doc_json;
    struct json_object *docId_json;
    struct json_object *scrollId_json;
    size_t n_hits;

    // fill json structs
    parsed_json = json_tokener_parse(ret->memory);
    json_object_object_get_ex(parsed_json,"error", &error_json);
    json_object_object_get_ex(parsed_json,"hits", &hits_json);
    json_object_object_get_ex(parsed_json,"_scroll_id", &scrollId_json);
    char *scrollIdDup = (char*)json_object_get_string(scrollId_json);
    char *scrollId = malloc(strlen(scrollIdDup)+1);
    strcpy(scrollId,scrollIdDup);
    json_object_object_get_ex(hits_json,"hits", &hitArray_json);
    n_hits = json_object_array_length(hitArray_json);


    // if a error is thrown in the first query print status and 
    // terminate the program
    if(error_json != NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" elastic search returnes error in optionhandler_cutoff elastic error message:\n");
        fprintf(STATUS_STREAM,"%s",ret->memory);
        exit(EXIT_FAILURE);
    }

    do {
        //handle a batch of sessions
        for (size_t i = 0; i < n_hits; i++){

            //get the session id
            struct json_object *sessionId_json;
            struct json_object *session_json = json_object_array_get_idx(hitArray_json,i);
            json_object_object_get_ex(session_json,"_id", &sessionId_json);
            char *sessionId = (char*)json_object_get_string(sessionId_json);

            analyze_session(sessionId); 
        }

        StringBuilder *scrollUrl = newStringBuilder();
        sb_append(scrollUrl,glb_args.es_url);
        sb_append(scrollUrl,"/");
        sb_append(scrollUrl,ES_SEARCH);
        sb_append(scrollUrl,"/");
        sb_append(scrollUrl,"scroll");
        sb_append(scrollUrl,"?scroll=10m");

        StringBuilder *scrollData = newStringBuilder();
        sb_append(scrollData,"{\"scroll_id\":\"");
        sb_append(scrollData,scrollId);
        sb_append(scrollData,"\"}");

        free(ret->memory);
        free(ret);
        ret = es_execute(scrollUrl->string,scrollData->string);
        sb_free(scrollUrl);
        sb_free(scrollData);

        //if error occours print error message but do not exit
        if(error_json != NULL){
            fprintf(STATUS_STREAM,STATUS_ERROR" elastic search returnes error in optionhandler_cutoff/scroll elastic error message:\n");
            fprintf(STATUS_STREAM,"%s",ret->memory);
            fprintf(STATUS_STREAM,"\n");
        }

        //fill json structs
        json_object_put(parsed_json);
        parsed_json = json_tokener_parse(ret->memory);
        json_object_object_get_ex(parsed_json,"error", &error_json);
        json_object_object_get_ex(parsed_json,"hits", &hits_json);
        json_object_object_get_ex(parsed_json,"_scroll_id", &scrollId_json);
        char *scrollId = (char*)json_object_get_string(scrollId_json);
        json_object_object_get_ex(hits_json,"hits", &hitArray_json);
        n_hits = json_object_array_length(hitArray_json);

    } while (n_hits > 0);

    //cleanup
    json_object_put(parsed_json);
    sb_free(url);
    sb_free(data);
    free(ret->memory);
    free(ret);
    free(scrollId);

    return;
}

/*
 * extracts the matchdata from the index ES_TAGPATTERS and returns them in
 * a list
 */
MatchData* get_match_data(){

    struct MatchData *retval = NULL;
    struct MatchData *cur = NULL;

    struct StringBuilder *url = newStringBuilder();
    sb_append(url,"localhost:9200/tagpatterns/_search?scroll=10m");

    /* { "query":{"bool":{"must":{"match_all":{}}}} } */
    struct StringBuilder *data = newStringBuilder();
    sb_append(data,"{\"query\":{\"bool\":{\"must\":{\"match_all\":{}}}}}");

    struct MemoryStruct *res = es_execute(url->string,data->string);
        
    json_object *res_json;
    json_object *scroll_id_json;
    json_object *hits_json;
    json_object *hits_array_json;
    json_object *hit_elem_json;
    json_object *hit_source_json;
    json_object *regex_json;
    json_object *tags_array_json;
    json_object *tag_json;

    res_json = json_tokener_parse(res->memory);
    json_object_object_get_ex(res_json,"_scroll_id",&scroll_id_json);
    char *scroll_id = (char*) json_object_get_string(scroll_id_json);
    json_object_object_get_ex(res_json,"hits",&hits_json);
    json_object_object_get_ex(hits_json,"hits",&hits_array_json);
    size_t batchsize = json_object_array_length(hits_array_json);
    
    while(batchsize != 0){

        //process one batch of data
        for (size_t i = 0; i < batchsize; i++){
            hit_elem_json =  json_object_array_get_idx(hits_array_json,i);
            json_object_object_get_ex(hit_elem_json,"_source",&hit_source_json);
            json_object_object_get_ex(hit_source_json,"regex",&regex_json);
            json_object_object_get_ex(hit_source_json,"tags",&tags_array_json);
            int tagsize = json_object_array_length(tags_array_json);

            //process tags
            struct StringArray *tags = newStringArray();

            for (size_t tag_pos = 0; tag_pos < tagsize; tag_pos++){
                tag_json = json_object_array_get_idx(tags_array_json,tag_pos);
                sa_add(tags,(char*) json_object_get_string(tag_json));
            }

            //process regular expression
            regex_t *regex = calloc(1,(sizeof(regex_t)));
            char *regex_string = (char*) json_object_get_string(regex_json);
            int regcsuc = regcomp(regex, regex_string, 0);
            
            if(regcsuc != 0){
                fprintf(STATUS_STREAM,STATUS_WARNING" compilation of regular expression failed: %s\n",regex_string);
                regfree(regex);
            }else{
                //if compilation was succsessful add the matchdata to the list
                struct MatchData *mdata = newMatchData();
                mdata->regex = regex;
                mdata->tags = tags;
                mdata->next = NULL;

                if(retval == NULL){
                    retval = mdata;
                    cur = retval;
                }else{
                    cur->next = mdata;
                    cur = mdata;
                }
            }

        }

        /*
            ES_url/es_search/scroll?scroll=10
            {
                "scroll_id":"Scroll_ID"
            }
        */
        //get the next batch of data
        struct StringBuilder *scrollurl = newStringBuilder();
        sb_append(scrollurl,glb_args.es_url);
        sb_append(scrollurl,"/"ES_SEARCH"/scroll?scroll=1m");
        
        struct StringBuilder *scrolldata = newStringBuilder();
        sb_append(scrolldata,"{\"scroll_id\":\"");
        sb_append(scrolldata,scroll_id);
        sb_append(scrolldata,"\"}");

        free(res->memory);
        free(res);
        res = es_execute(scrollurl->string,scrolldata->string);

        sb_free(scrollurl);
        sb_free(scrolldata);

        json_object_put(res_json);
        res_json = json_tokener_parse(res->memory);
        json_object_object_get_ex(res_json,"_scroll_id",&scroll_id_json);
        char *scroll_id = (char*) json_object_get_string(scroll_id_json);
        json_object_object_get_ex(res_json,"hits",&hits_json);
        json_object_object_get_ex(hits_json,"hits",&hits_array_json);
        batchsize = json_object_array_length(hits_array_json);

    }

    json_object_put(res_json);
    free(res->memory);
    free(res);
    sb_free(url);
    sb_free(data);

    return retval;

}

/*
 * checks dependencies in elastic search (if indices exist)
 * if some dependency is not met this function stops the execution
 */
void checkDependencies(){

    //check index update
    struct StringBuilder *url = newStringBuilder();
    sb_append(url,glb_args.es_url);
    sb_append(url,"/_cat/indices");

    struct MemoryStruct *res = es_execute(url->string,NULL);

    //check index updates
    regex_t update_reg;
    regcomp(&update_reg, ".*"ES_UPDATES".*", 0);
    if(regexec(&update_reg,res->memory,0,NULL,0) == REG_NOMATCH){
        fprintf(STATUS_STREAM,STATUS_ERROR" index: "ES_UPDATES" not found, check elastic search\n");
        exit(EXIT_FAILURE);
    }

    //check index tagpatterns
    regex_t tagpatterns_reg;
    regcomp(&tagpatterns_reg, ".*"ES_TAGPATTERNS".*", 0);
    if(regexec(&tagpatterns_reg,res->memory,0,NULL,0) == REG_NOMATCH){
        fprintf(STATUS_STREAM,STATUS_ERROR" index: "ES_UPDATES" not found, check elastic search\n");
        exit(EXIT_FAILURE);
    }

    fprintf(STATUS_STREAM,STATUS_OK" dependencies checked\n");

    /* cleanup */
    regfree(&update_reg);
    regfree(&tagpatterns_reg);
    free(res->memory);
    free(res);
    sb_free(url);
}

int main(int argc, char **argv){

    /***************************************************************/
    // parse glb_args
    /***************************************************************/    
    glb_args.deltaTime = 0;
    glb_args.sessionId = "-";
    argp_parse(&argp,argc,argv,0,0,&glb_args);

    //use default values if no overrides selected
    if(!glb_args.FLAG_ES_URL_OVERRIDE){
        glb_args.es_url = ES_URL;
    }

    if(!glb_args.FLAG_PPREFIX_OVERRIDE){
        glb_args.pcap_prefix = PCAPPREFIX;
    }

    /***************************************************************/

    //measure time for report
    time_t programStart,programStop;
    double executionTime;
    time (&programStart);

    /***************************************************************/
    // check dependencies
    /***************************************************************/
    checkDependencies();

    /***************************************************************/
    //get the regex patterns from elastic search and store them in memory
    matchdata = get_match_data();

    if(matchdata != NULL){
        fprintf(STATUS_STREAM,STATUS_OK" extracting of matchdata succsessful\n");
    }else{
        fprintf(STATUS_STREAM,STATUS_ERROR" empty matchdata check es index: "ES_TAGPATTERNS"\n");
    }

    /***************************************************************/
    // call the right handler function
    if(glb_args.FLAG_ID){
        analyze_session(glb_args.sessionId);
    }else if(glb_args.FLAG_ALL){
        // start time of 0 means every entry is analyzed
        analyze_block("0");
        
    }else if(glb_args.FLAG_CUTOFF){
        //time in milliseconds
        long cutoffTime = (programStart - glb_args.deltaTime * 3600) * 1000;
        char *cutoffTime_string = ltos(cutoffTime);
        
        analyze_block(cutoffTime_string);

        free(cutoffTime_string);
    }

    //clean up
    freeMatchData(&matchdata);

    //measure time for report
    time (&programStop);
    executionTime = difftime (programStop,programStart);
    fprintf (STATUS_STREAM,STATUS_INFO" execution time: %.2lf seconds\n", executionTime );
    
    exit(EXIT_SUCCESS);
}