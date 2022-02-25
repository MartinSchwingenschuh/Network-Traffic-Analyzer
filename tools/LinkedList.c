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
#include "LinkedList.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../glbs.h"

struct ListNode* newListNode(enum NodeType type){
    struct ListNode *tmp = calloc(1,sizeof(struct ListNode));
    if(tmp == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" newMemoryNode() out of memory\n");
        exit(EXIT_FAILURE);
    }

    tmp->type = type;

    return tmp;
}

void free_ListNode(struct ListNode **toFree){
    if(*toFree == NULL){ return; }

    //pointer
    if((*toFree)->data != NULL && (*toFree)->type == PONITER){ 
        free((*toFree)->data);
    }

    //in_addr
    if((*toFree)->data != NULL && (*toFree)->type == IN_ADDR){ 
        free((*toFree)->data);
    }

    //String
    if((*toFree)->data != NULL && (*toFree)->type == STRING){ 
        free((*toFree)->data); 
    }

    free(*toFree);
    *toFree = NULL;
}

/************************************************************************/

struct LinkedList* newLinkedList(){
    struct LinkedList *tmp = calloc(1,sizeof(struct LinkedList));
    if(tmp == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" newMemoryList() out of memory\n");
        exit(EXIT_FAILURE);
    }

    tmp->lock = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(tmp->lock,PTHREAD_MUTEX_DEFAULT);

    return tmp;
}

void ll_free(struct LinkedList **toFree){
    if(*toFree == NULL){ return; }
    
    struct ListNode *cur;
    struct ListNode *next;

    cur = (*toFree)->head;

    while(cur != NULL){
        next = cur->next;
        free_ListNode(&cur);
        cur = next;
    }

    pthread_mutex_destroy((*toFree)->lock);
    free((*toFree)->lock);

    free(*toFree);
    *toFree = NULL;
}

void ll_add(struct LinkedList* list, struct ListNode *node){
    if(list == NULL){ return; }
    if(node == NULL){ return; }
    

    if(list->head == NULL){ 
        list->head = node;
        list->tail = node;
    }else{
        list->tail->next = node;
        list->tail = node;
    }

    list->size++;
    
}

int ll_add_string(struct LinkedList *list, char *string){

    if(list == NULL || string == NULL){ return LL_ERROR; }

    struct ListNode *node = newListNode(STRING);
    node->data = calloc(1,strlen(string)+1);
    strcpy(node->data,string);

    ll_add(list,node);
    return LL_OK;
}

int ll_add_string_distinct(struct LinkedList *list, char *string){
    if(list == NULL || string == NULL){ return LL_ERROR; }

    struct ListNode *q = list->head;

    while (q != NULL){
        if(q->type != STRING){
            return LL_MIXEDDATA;
        }

        if(strcmp((char*) q->data,string) == 0){
            return LL_DUPLICATE;
        }

        q = q->next;
    }

    ll_add_string(list,string);
    return LL_OK;
}

int ll_delete_string(struct LinkedList *list, char *toDelete){

    if(list == NULL || toDelete == NULL){ return LL_ERROR; }


    struct ListNode *p = NULL;
    struct ListNode *q = list->head;

    while (q != NULL){
        if(q->type == STRING && strcmp((char*) q->data,toDelete) == 0){
            if(p == NULL){ 
                list->head = q->next;   
            }else{
                p->next = q->next; 
            }
            free_ListNode(&q);
            list->size--;
            return LL_OK;
        }

        p=q;
        q = q->next;
    }
    return LL_ERROR;
}

char* ll_get_string(struct LinkedList *list, int pos){

    if(list == NULL){ return LL_ERROR; }

    struct ListNode *q = list->head;

    for (size_t i = 0; i < list->size -1; i++){
        if(q->next == NULL){ return NULL; }
        q = q->next;
    }
    
    return (char*) q->data;
}
