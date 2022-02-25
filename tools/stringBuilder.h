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
typedef struct StringBuilder StringBuilder;

struct StringBuilder{
    //pointer to stored combined string
    char *string;
    //character count without \\0
    int length;
};

StringBuilder* newStringBuilder();

void sb_init(StringBuilder *sb);

void sb_append(StringBuilder *sb,char *toAppend);

char* sb_getCopy(StringBuilder *sb);

void sb_free(StringBuilder *sb);