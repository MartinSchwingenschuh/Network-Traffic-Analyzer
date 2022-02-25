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
#ifndef HEADER_MemoryList
#define HEADER_MemoryList

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

enum NodeType{
    LOOKUPDATA,
    STRING,
    PONITER,
    IN_ADDR,
    IN_ADDR6,
    MATCHDATA
};

struct ListNode{
    enum NodeType type;
    void *data;
    struct ListNode *next;
};

struct ListNode* newListNode(enum NodeType type);

void free_ListNode(struct ListNode **toFree);

/************************************************************************/

#define LL_OK 1
#define LL_ERROR 0
#define LL_MIXEDDATA -1
#define LL_DUPLICATE -2

typedef struct LinkedList LinkedList;

struct LinkedList{
    size_t size;
    struct ListNode *head;
    struct ListNode *tail;
    pthread_mutex_t *lock;
};

/*
 * Constructor for a MemoryList
 */
struct LinkedList* newLinkedList();

/*
 * Frees the MemoryList object with the stored contend
 */
void ll_free(struct LinkedList **toFree);

/*
 * Adds a block to free if the adress is not already stored in the list
 */
void ll_add(struct LinkedList *list, struct ListNode *node);

/*
 * adds the given string to the list
 */
int ll_add_string(struct LinkedList *list, char *string);

/*
 * only adds the given string to the list if 
 * the string is not already in it
 */
int ll_add_string_distinct(struct LinkedList *list, char *string);

/*
 * search the list for the given string and
 * delete the entry
 */
int ll_delete_string(struct LinkedList *list, char *toDelete);

/*
 * returns a pointer to the string at position 
 * pos
 */
char* ll_get_string(struct LinkedList *list, int pos);

#endif