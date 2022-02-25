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
#include <string.h>
#include <json-c/json.h>
#include <regex.h>

#include "glbs.h"
#include "tools/LinkedList.h"

/*******************************************************/
// StringArray
/*******************************************************/

struct StringArray* newStringArray(){
    struct StringArray *tmp = calloc(1,sizeof(struct StringArray));
    tmp->size = 0;
}

//expand the given array by one string
void expandArray(struct StringArray* toExpand){

    toExpand->size++;

    char** tmp;

    if(toExpand->size == 1){
        tmp = malloc(sizeof(char*));
    }else{
        char **old_ptr = toExpand->data;
        tmp = realloc(toExpand->data,sizeof(char*) * toExpand->size);        
    }
        
    if(!tmp){
        fprintf(STATUS_STREAM,STATUS_ERROR" out of memory (realloc returned NULL)\n");
        return;
    }

    toExpand->data = tmp;
}

int sa_add(struct StringArray *sa,char* toAdd){
    
    if(sa == NULL || toAdd == NULL){ return SA_ERROR; }

    //check if the string is already in the array
    for (size_t i = 0; i < sa->size; i++){
        if(strcmp(sa->data[i],toAdd) == 0){ return SA_FAIL; }
    }
    
    //expand array and insert new string
    expandArray(sa);
    sa->data[sa->size - 1] = calloc(1,strlen(toAdd) + 1);
    memcpy(sa->data[sa->size - 1],toAdd,strlen(toAdd) + 1);
    return SA_SUCC;
}

int sa_delete(struct StringArray *sa, char *toDelete){

    if(sa == NULL || toDelete == NULL){ return SA_ERROR; }

    for (size_t i = 0; i < sa->size; i++){
        if(strcmp(sa->data[i],toDelete) == 0){
            free(sa->data[i]);
            for (size_t j = 0; j < sa->size; j++){
                sa->data[i] = sa->data[j];
            }
            free(sa->data[sa->size-1]);
            sa->size--;

            return SA_SUCC;
        }
    }

    return SA_FAIL;
}

void sa_print(struct StringArray *sa){
    for (size_t i = 0; i < sa->size; i++){
        printf("%s\n",sa->data[i]);
    }    
}

//free the strings of the given array 
int freeArray(struct StringArray* toFree){
    
    for(int i=0;i<toFree->size;i++){
        free(toFree->data[i]);
    }

    free(toFree->data);
    free(toFree);

    return 0;
}

/*******************************************************/
// Session
/*******************************************************/
struct Session* newSession(){
    struct Session *object = calloc(1,sizeof(struct Session));
}

void freeSession(struct Session* toFree){
    if(toFree == NULL){
        return;
    }

    if(toFree->json != NULL){
        json_object_put(toFree->json);
    }

    if(toFree->nPackets != 0 && toFree->packets != NULL){
        for (size_t i = 0; i < toFree->nPackets; i++){
            if(toFree->packets[i] != NULL)
                freePacket(toFree->packets[i]);
        }
        free(toFree->packets);
    }

    if(toFree->sessionId != NULL){ free(toFree->sessionId); }
    
    //src_macs
    if(toFree->src_macs_count != 0){
        for (size_t i = 0; i < toFree->src_macs_count; i++){
            free(toFree->src_macs[i]);
        }
        free(toFree->src_macs);
    }

    //dst_macs
    if(toFree->dst_macs_count != 0){
        for (size_t i = 0; i < toFree->dst_macs_count; i++){
            free(toFree->dst_macs[i]);
        }
        free(toFree->dst_macs);
    }

    //vlans
    if(toFree->vlan_count != 0){
        for (size_t i = 0; i < toFree->vlan_count; i++){
            free(toFree->vlans[i]);
        }
        free(toFree->vlans);
    }

    //pcap positions
    if(toFree->pcap_positions != NULL){ free(toFree->pcap_positions); }

    //pcap filename
    if(toFree->pcap_filename != NULL){ free(toFree->pcap_filename); }

    free(toFree);
}

void printSession(struct Session *session){
    printf("json: \n%s\n", json_object_get_string(session->json)); 
    for (size_t packet = 0; packet < session->nPackets; packet++){
        printf("packet no: %lu\n",packet);

        if(session->packets == NULL){
            printf("packet = NULL\n");
        }else{
            for (int i = 0; i < session->packets[packet]->datasize; i++){
                printf("%02x",*(session->packets[packet]->data + i));
            }
            printf("\n");
        }
    }
}

/*******************************************************/
// MatchData
/*******************************************************/
struct MatchData* newMatchData(){
    struct MatchData *tmp = malloc(sizeof(struct MatchData));
    if(!tmp){
        fprintf(STATUS_STREAM,STATUS_ERROR" newMatchData() out of memory\n");
    }

    return tmp;
}

void freeMatchData(struct MatchData **toFree){
    if(*toFree == NULL){ return; }
    if((*toFree)->tags != NULL){ freeArray((*toFree)->tags); }
    if((*toFree)->regex != NULL){ 
        regfree((*toFree)->regex); 
        free((*toFree)->regex);
    }
    if((*toFree)->next != NULL){ freeMatchData(&(*toFree)->next); }
    free((*toFree));
    toFree = NULL;
}

/*******************************************************/
// helpers
/*******************************************************/
char* ltos(long number){
    
    char *retVal = calloc(20,sizeof(char));

    int digit = 0;
    int pos = 0;

    while(number != 0){
        digit = number % 10;
        number = number / 10;
        retVal[pos] = digit + 48;
        pos++;
    }
    pos--;
    //reverse string
    char tmp;
    for (size_t i = 0; i < pos/2; i++){
        tmp = retVal[i];
        retVal[i] = retVal[pos-i];
        retVal[pos-i] = tmp;
    }

    return retVal;
}

char* indexfromSession(char *session_id){
    //extract index from id
    #if PROD
    char *index = calloc(1,17);
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+10,session_id,6);
    return index;
    #else
    char *index = calloc(1,24);
    strcpy(index,ES_INDEXPREFIX);
    memcpy(index+17,session_id,6);
    return index;
    #endif

}

/*******************************************************/