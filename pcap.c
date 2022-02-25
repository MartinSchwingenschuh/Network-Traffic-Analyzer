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
#include "pcap.h"

#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>

#include "glbs.h"

/*      globals     */
extern struct arguments glb_args;

void pcap_print_file(const char* filename){
    FILE *fp;
    FILE *wfp;

    PcapHeader *header = malloc(sizeof(PcapHeader));
    PacketHeader *p_header = malloc(sizeof(PacketHeader));

    //read pcap fileheader
    fp = fopen(filename, "r");  
    wfp = fopen("capture", "w");  
    fread( header, 1, sizeof(PcapHeader), fp );

    int noPacket = 0;
    int read = 0;

    //read all packet header and packet in file
    read = fread( p_header, 1, sizeof(PacketHeader), fp );
    noPacket++;

    while(read){

        //make space for data
        Packet *packet = malloc(sizeof(Packet));
        packet->datasize = p_header->capturedPacketLength;
        packet->data = malloc(p_header->capturedPacketLength);
        read = fread( packet->data, 1, packet->datasize, fp );
        packet->header = p_header;

        fprintf(wfp,"\n");
        fprintf(wfp,"packet no: %i timestamp: %i\n", noPacket,packet->header->timestampPrimary);
        for (int i = 0; i < packet->datasize; i++){
            fprintf(wfp,"%02x",*(packet->data + i));
        }
        fprintf(wfp,"\n");     

        free(packet->data);
        free(packet);
        packet = NULL;

        read = fread( p_header, 1, sizeof(PacketHeader), fp );
        if(read) noPacket++;
    }
    
    printf("packets: %i\n", noPacket);

    fclose(fp);
    fclose(wfp);
}

int pcap_get_length(const char* filename){
    FILE *fp;
    PcapHeader *header = malloc(sizeof(PcapHeader));
    PacketHeader *p_header = malloc(sizeof(PacketHeader));
    Packet *packet = malloc(sizeof(Packet));

    int pos = 0;
    int read = 0;

    //read pcap fileheader
    fp = fopen(filename, "r");    
    read = fread( header, 1, sizeof(PcapHeader), fp );
    
    //when empty file return 0
    if(!read){ 
        free(packet);
        free(p_header);
        free(header);
        return 0; 
    }
    
    //read first packet header
    read = fread( p_header, 1, sizeof(PacketHeader), fp );
    if(read) pos++;

    while(read){

        //read and store the packet data
        packet->datasize = p_header->capturedPacketLength;
        packet->data = malloc(p_header->capturedPacketLength);
        read = fread( packet->data, 1, packet->datasize, fp );
        packet->header = p_header;

        //clean up
        free(packet->data);
        packet->data = NULL;

        //read next packet header
        read = fread( p_header, 1, sizeof(PacketHeader), fp );
        if(read) pos++;
    }

    //clean up
    fclose(fp);
    free(packet->data);
    free(packet);
    free(p_header);
    free(header);

    return pos;    
}

Packet* pcap_get_packet(const char *filename, int64_t offset){
    FILE *fp;
    PacketHeader *p_header = malloc(sizeof(PacketHeader));
    Packet *packet = malloc(sizeof(Packet));
    int read = 0;

    fp = fopen(filename, "r");   

    //read over offset
    fseek(fp,offset,SEEK_CUR);

    //read packet
    read = fread( p_header, 1, sizeof(PacketHeader), fp );
    packet->datasize = p_header->capturedPacketLength;
    packet->data = malloc(p_header->capturedPacketLength);
    read = fread( packet->data, 1, packet->datasize, fp );
    packet->header = p_header;

    fclose(fp);
    return packet;
}

Packet** pcap_get_packets(const char *filename, int64_t *offsets, int size){

    if (filename == NULL){
        printf(RED"[ERROR]"NC" filename null");
        return NULL;
    }

    if(offsets == NULL){
        printf(RED"[ERROR]"NC" offset array null");
        return NULL;
    }

    if(size == 0){
        printf(RED"[ERROR]"NC" size is 0");
        return NULL;
    }

    //open pcap file and perform a check
    FILE *fp;
    fp = fopen(filename, "r"); 

    if(fp == NULL){
        fprintf(STATUS_STREAM,STATUS_ERROR" pcap file does not exist or permission denied\n \t filename: %s\n",filename);
        fprintf(STATUS_STREAM,STATUS_INFO" entering NOPCAP-Mode\n");
        glb_args.MODE_NOPCAP = true;
        fclose(fp);
        return NULL;
    }

    //get space for Objects
    Packet **retVal = malloc(sizeof(Packet*) * size);
    int64_t read = 0;
    int64_t old_packet_length = 0;

    //read Packets
    for (int i = 0; i < size; i++){
        //get space for a packet
        Packet *packet = calloc(1,sizeof(Packet));
        packet->header = calloc(1,sizeof(PacketHeader));

        // read over offset
        // 0 has not the same meaning as other numbers in offsets
        if(offsets[i] != 0){
            int err = fseek(fp,*(offsets+i) - old_packet_length,SEEK_CUR);
            if(err){
                fprintf(STATUS_STREAM,STATUS_ERROR" could not read offset, check filesize\n");
                return NULL;
            }
        }        

        //read packet
        read = fread( packet->header, 1, sizeof(PacketHeader), fp );
        packet->datasize = packet->header->capturedPacketLength;
        
        packet->data = calloc(1,packet->header->capturedPacketLength);
        read = fread( packet->data, 1, packet->datasize, fp );

        //packet length + packet header
        old_packet_length = packet->datasize + sizeof(PacketHeader);        

        if(read != packet->datasize){
            fprintf(STATUS_STREAM,STATUS_WARNING" could not read packet, check filesize\n");
            fclose(fp);

            //free the stored packets
            for (size_t pos = 0; pos < i; pos++){
                freePacket(retVal[pos]);
            }
            
            return NULL;
        }

        *(retVal+i) = packet;
    }

    fclose(fp);

    return retVal;
}

void freePacket(Packet *toFree){
    if(toFree == NULL) return;
    if(toFree->data != NULL) free(toFree->data);
    if(toFree->header != NULL) free(toFree->header);
    free(toFree);
}

void printPacket(Packet *packet){
    printf("packet:\n");
    printf("\tpacket.data = %s\n",packet->data);
    printf("\tpacket.datasize = %u\n",packet->datasize);
    printf("\tpacket.header.packetLength = %u\n",packet->header->capturedPacketLength);
    printf("\tpacket.header.originalPacketLength = %u\n",packet->header->originalPacketLength);
    printf("\tpacket.header.timestampPrimary = %u\n",packet->header->timestampPrimary);
    printf("\tpacket.header.timestampSecondary = %u\n",packet->header->timestampSecondary);
    if(packet->data != NULL){
        printf("/tpacket.data =\n");
        for (size_t i = 0; i < packet->datasize; i++){
            printf("%02x",packet->data[i]);
        }
        printf("\n");
    }else{
        printf("/tpacket.data = NULL");
    }
}