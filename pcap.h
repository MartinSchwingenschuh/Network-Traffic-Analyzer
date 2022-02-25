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
#ifndef HEADER_PCAPP
#define HEADER_PCAPP

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct{
    unsigned int magicNumber;
    unsigned short majorVersion;
    unsigned short minorVersion;
    unsigned int reserved1;
    unsigned int reserved2;
    unsigned int snapLen;
    unsigned short fcs;
    unsigned short linkType;
}PcapHeader;

typedef struct{
    uint32_t timestampPrimary;
    uint32_t timestampSecondary;
    uint32_t capturedPacketLength;
    uint32_t originalPacketLength;
}PacketHeader;

typedef struct{
    PacketHeader *header;
    unsigned int datasize;
    unsigned char *data;
}Packet;

void freePacket(Packet* toFree);

void printPacket(Packet *packet);

/*
 *filename needs the path included
*/
void pcap_print_file(const char* filename);

Packet* pcap_search_packet(const char* filename, long timestamp);
Packet* pcap_get_packet(const char* filename, int64_t pos);
Packet** pcap_get_packets(const char *filename, int64_t *offsets, int size);

/*
 *returns the number of packets contained in the given file
 */
int pcap_get_length(const char* filename);

void pcap_get_array(const char* filename, Packet* arr, int* length);

#endif