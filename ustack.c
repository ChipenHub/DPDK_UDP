#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>




#define UDP_APP_RECV_BUFFER_SIZE	128


int main(int argc, char *argvp[]) {

	int connfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (connfd == -1) {
		printf("socketfd failed\n");
		return -1;
	}

	struct sockaddr_in localaddr, clientaddr;
	memset(&localaddr, 0, sizeof (struct sockaddr_in));
	


	localaddr.sin_port = htons(8081);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.3.128");

	bind(connfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr_in));


	char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };

	socklen_t addrlen = sizeof (clientaddr);
	
	while (1) {

		if (recvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
			(struct sockaddr *)&clientaddr, &addrlen) < 0) {

			continue;
		} else {

			printf("reccv from %s:%d, content: %s\n", inet_ntoa(clientaddr.sin_addr),
				htons(clientaddr.sin_port), buffer);

			sendto(connfd, buffer, strlen(buffer), 0,
				(struct sockaddr *)&clientaddr, sizeof (clientaddr));	
		
		}

	}


	close(connfd);
	
}
