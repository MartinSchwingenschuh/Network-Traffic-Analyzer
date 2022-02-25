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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../glbs.h"
#include "stringBuilder.h"


void sb_init(struct StringBuilder *sb){
    sb->length = 0;
    sb->string = NULL;
}

struct StringBuilder* newStringBuilder(){
    struct StringBuilder *ptr = NULL;
    ptr = calloc(1,sizeof(struct StringBuilder));
    return ptr;
}

void sb_append(struct StringBuilder *sb,char *toAppend){

    if(toAppend == NULL){
        //too many status prints slow the system down
        // fprintf(STATUS_STREAM,STATUS_WARNING" sb_append:toAppend is NULL returning\n");
        return;
    } 

    if(sb->length == 0){
        //string empty
        sb->string = calloc(1,strlen(toAppend) + 1);
        memcpy(sb->string,toAppend,strlen(toAppend) + 1);
        sb->length = strlen(toAppend);
    }else{
        //string not empty
        char *tmp = realloc(sb->string,sb->length + strlen(toAppend) + 1);
        if(!tmp){
            //out of memory
            fprintf(STATUS_STREAM,STATUS_ERROR" out of memory in StringBuilder");
        }else if(tmp != sb->string){
            //new block
            memcpy(tmp+sb->length,toAppend,strlen(toAppend)+1);
            sb->string = tmp;
            sb->length += strlen(toAppend);
        }else{
            //tmp = old block
            memcpy(sb->string+sb->length,toAppend,strlen(toAppend)+1);
            sb->length += strlen(toAppend);
        }
    }
}

char* sb_getCopy(struct StringBuilder *sb){
    if(sb->length == 0){
        return NULL;
    }else{
        char *tmp = malloc(sb->length+1);
        memcpy(tmp,sb->string,sb->length+1);
        return tmp;
    }
}

void sb_free(struct StringBuilder *sb){
    if(sb == NULL) return;
    if(sb->string != NULL) free(sb->string);
    free(sb);
}
