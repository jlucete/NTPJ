/*
   client.c -- a stream socket client demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include <arpa/inet.h>

#define MAXDATASIZE 10 // max number of bytes we can send at once 
#define MAXINPUTSIZE 1000000 // max bytes we can get at once

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char hostname[100];
	char PORT[5];
	char method[2];
	srand(time(NULL));

	if (argc != 7) {
		fprintf(stderr,"usage: client hostname port method\n");
		exit(1);
	}
	if ((strcmp("-h",argv[1]) | strcmp("-p",argv[3]) | strcmp("-m",argv[5])) != 0 ) {
		printf("usage : command error\n");
		return 1;
	}
	strcpy(hostname,argv[2]);
	strcpy(PORT,argv[4]);
	strcpy(method,argv[6]);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(hostname, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	//phase 1
	char op[3], proto[3], checksum[5], trans_id[9];
	int op_i, proto_i, checksum_i, trans_id_i;

	strcpy(op, "00");

	if (strcmp(method, "1") == 0) {
		strcpy(proto, "01");
	}
	else if(strcmp(method, "2") == 0) {
		strcpy(proto, "02");
	}
	else {
		printf("usage : not available protocol\n");
		return -1;
	}

	//trans_id generater to make checksum max transid = 65533
	trans_id_i = rand()/(float)RAND_MAX*65533;
	sprintf(trans_id, "%08X", trans_id_i);

	//calc checksum
	proto_i = strtol(proto,NULL,10);
	checksum_i = 65535-trans_id_i-proto_i;
	sprintf(checksum, "%04X", checksum_i);

	strcat(op, proto);
	strcat(op, checksum);
	strcat(op, trans_id);

	if ((send(sockfd, op, 16, 0)) == -1) {
		perror("send");
		return -1;
	}

	if ((numbytes = recv(sockfd, buf, 16, 0)) == -1) {
		perror("recv");
		return -1;
	}

	buf[numbytes] = '\0';
	printf("client: successfully connected\n");

	//phase 2-1
	if (proto_i == 1) {
		char msg[MAXINPUTSIZE+2]; // 2 for terminator
		char send_msg[MAXDATASIZE];
		while(scanf("%s",msg) != EOF) {
			strcat(msg,"\\0");
			//sending
			for (int i = 0; i < strlen(msg); i = i + MAXDATASIZE) {
				if (strlen(msg) <= MAXDATASIZE) {
					send(sockfd, msg, strlen(msg), MSG_NOSIGNAL);
				}
				else {
					if ((strlen(msg)-i)<MAXDATASIZE) {
						strncpy(send_msg, msg+i, strlen(msg)-i+1);
					}
					else {
						strncpy(send_msg, msg+i, MAXDATASIZE);
					}
					printf("%s\n",send_msg);
					send(sockfd, send_msg, strlen(send_msg), 0);
				}
			}
			memset(msg,'\0',strlen(msg));
                        while(strstr(msg,"\\0") == NULL) {
				recv(sockfd, send_msg, MAXDATASIZE, 0);
				strcat(msg, send_msg);
			}
			printf("client : server sends %s\n",msg);
		}

	}

	close(sockfd);

	return 0;
}
