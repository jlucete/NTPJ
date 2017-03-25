/*
Server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define BACKLOG 10     // how many pending connections queue will hold
#define MAXDATASIZE 10 // max number of bytes of msg from client at one
#define MAXINPUTDATASIZE 1000000 // max bytes of total msg

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// redundancy remover of string
char* redundancy_remove(char* strin)
{
	int len = strlen(strin), cnt=0;
	char strout[len],temp[2];
	strout[0] = '\0';
	temp[1] = '\0';
	for(int i = 0 ; i < len-2; i++) {
		temp[0] = strin[i];
		if(!strstr(strout,temp)) {
			strout[cnt] = temp[0];
			cnt++;
		}
	}
	strout[cnt] = '\0';
	memset(strin,'\0',strlen(strin));
	strcpy(strin,strout);
	return strin;
}



int main(int argc, char* argv[]) // argv[1] command , argv[2] for port
{
    int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr; // connector's address information
    socklen_t sin_size;
    struct sigaction sa;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
    int rv;
	char PORT[5];

	//dealing with argv
	if (argc != 3) {
		printf("usage : port error\n");
		return 1;
	}
	if (strcmp("-p",argv[1]) != 0) {
		printf("usage : command error\n");
		return 1;
	}
	strcpy(PORT,argv[2]);
	printf("%s\n",PORT);


    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo); // all done with this structure

    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);

        if (!fork()) { // this is the child process
            close(sockfd); // child doesn't need the listener
		//phase 1
		char negotiation[17];
		char  op[3], proto[3], checksum[5], trans_id[9],trans_id_check[5],op_proto[5];
		int op_proto_i,checksum_i,trans_id_i;
		int  numbytes;
		if ((numbytes = recv(new_fd, negotiation, 16, 0)) == -1) {
			perror("recv");
			exit(1);
		}
		negotiation[numbytes] = '\0';
		op[2] = '\0';
		proto[2] = '\0';
		checksum[4] = '\0';
		trans_id[8] = '\0';
		op_proto[4] = '\0';
		trans_id_check[4] = '\0';
		strncpy(op,negotiation,2);
		strncpy(proto,negotiation+2,2);
		strncpy(checksum,negotiation+4,4);
		strncpy(trans_id,negotiation+8,8);
		strncpy(op_proto,negotiation,4);
		strncpy(trans_id_check,negotiation+12,4);

		//convert hex string to int
		op_proto_i = strtol(op_proto,NULL,16);
		checksum_i = strtol(checksum,NULL,16);
		trans_id_i = strtol(trans_id_check,NULL,16);

		//recv msg checksum check
		if ((op_proto_i+checksum_i+trans_id_i) != 0xffff) {
			printf("usage : checksum error\n");
			exit(1);
		}
		
		//calc send msg checksum
		strcpy(op,"01");
		sprintf(checksum,"%X",checksum_i-256);		

		//send to client
		strcat(op,proto);
		strcat(op,checksum);
		strcat(op,trans_id);
		op[16] = '\0';
		if (send(new_fd, op, 16, 0) == -1) {
			perror("send");
			exit(1);
		}

		//phase 2-1
		char client_msg_temp[MAXDATASIZE];
		char client_msg[MAXINPUTDATASIZE];
			//recv client msg
		while(1) { 
			if(recv(new_fd, client_msg, MAXDATASIZE, 0) == 0) break; // socket closed
			while(strstr(client_msg,"\\0") == NULL) {
				recv(new_fd, client_msg_temp, MAXDATASIZE, 0);
				strcat(client_msg, client_msg_temp);
			}
			printf("server : %s sends %s\n",s,client_msg);
			redundancy_remove(client_msg);
			printf("after client_msg : %s\n",client_msg);
			printf("len : %d\n",strlen(client_msg));
                        strcat(client_msg,"\\0");
                        //sending
                        for (int i = 0; i < strlen(client_msg); i = i + MAXDATASIZE) {
                                if (strlen(client_msg) <= MAXDATASIZE) {
                                        send(new_fd, client_msg, strlen(client_msg), MSG_NOSIGNAL);
                                }
                                else {
                                        if ((strlen(client_msg)-i)<MAXDATASIZE) {
                                                strncpy(client_msg_temp, client_msg+i, strlen(client_msg)-i+1);
                                        }
                                        else {
                                                strncpy(client_msg_temp, client_msg+i, MAXDATASIZE);
                                        }
                                        send(new_fd, client_msg_temp, strlen(client_msg_temp), 0);
                                }
                        }
			memset(client_msg,'\0',sizeof client_msg);
		}
		printf("server: lost connection to %s\n",s);
		close(new_fd);
		exit(0);
	}
        close(new_fd);  // parent doesn't need this
    }

    return 0;
}
