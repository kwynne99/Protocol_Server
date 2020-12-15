#include <WinSock2.h>
#include <stdio.h>
#include <WS2tcpip.h>
#include <iostream>
#include <ctime>

#pragma comment(lib, "Ws2_32.lib")

#define PORT "8080"
#define CONTROL_BUFFER_SIZE 40
#define MAX_BUFFER_SIZE 80

struct tcp_header {
	unsigned int max_bufsize;
	unsigned int tcph_seqnum;
	unsigned int tcph_acknum;
	unsigned int
		tcph_fin : 1,
		tcph_syn : 1,
		tcph_rst : 1,
		tcph_psh : 1,
		tcph_ack : 1,
		tcph_urg : 1;
	unsigned short int tcph_checksum;
	char data[];
};

void clearFlags(struct tcp_header * header) {
	header->tcph_fin = 0, header->tcph_syn = 0, header->tcph_rst = 0, header->tcph_psh = 0, header->tcph_ack = 0, header->tcph_urg = 0;
}

unsigned int payloadSize(unsigned int bufferSize) {
	return (bufferSize - sizeof(tcp_header));
}

unsigned short int chksum(struct tcp_header* header) {
	short int sum = 0;
	sum += header->tcph_seqnum;
	sum += header->tcph_acknum;
	sum += atoi(header->data);
	sum += header->tcph_fin;
	sum += header->tcph_syn;
	sum += header->tcph_rst;
	sum += header->tcph_psh;
	sum += header->tcph_ack;
	sum += header->tcph_urg;
	return sum;
}

void freeBuffers(struct tcp_header* send, struct tcp_header* recv) {
	delete (send);
	delete (recv);
}

int main() {
	WSADATA wsaData;
	int iResult;
	int totalReceived = 0, totalSent = 0;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup Failed: %d\n", iResult);
		return 1;
	}

	struct addrinfo* result = NULL, * ptr = NULL, hints;
	
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM; // Stream socket (TCP)
	hints.ai_protocol = IPPROTO_TCP; // Specifies TCP protocol
	hints.ai_flags = AI_PASSIVE; // Return socket address structure in call to bind

	iResult = getaddrinfo("127.0.0.1", PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	SOCKET ListenSocket = INVALID_SOCKET;
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

	if (ListenSocket == INVALID_SOCKET) {
		printf("Error at socket(), %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("Bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	freeaddrinfo(result); // No longer needed

	if (listen(ListenSocket, 4) == SOCKET_ERROR) {
		printf("Listen failed with error: %ld\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	SOCKET ClientSocket; // Temporary socket used to accept connections.
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("Accept failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	
	int timeout = 15000; // 10 seconds
	iResult = setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
	if (iResult == SOCKET_ERROR) {
		printf("setsockopt for timeout failed: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}
	else
		printf("setsockopt: Timeout was set for: %d ms\n", timeout);
	
	// Set socket to non-blocking: Then I can use my own timeouts for receiving...
	u_long mode = 1;
	//ioctlsocket(ClientSocket, FIONBIO, &mode);
	// Send a receive buffers:
	struct tcp_header* recvbuf = new tcp_header;
	struct tcp_header* sendbuf = new tcp_header;
	int iSendResult;
	int nextSeq;
	unsigned int clientBufSize;
	unsigned int bufferSize = MAX_BUFFER_SIZE;
	time_t start;
	// TCP Handshake Process:
	// Receive SYN from Client:
	printf("Waiting for SYN...\n");
	iResult = recv(ClientSocket, (char*)recvbuf, CONTROL_BUFFER_SIZE, 0);
	if (iResult == SOCKET_ERROR) {
		printf("recv() failed with error code: %d\n", WSAGetLastError());
		WSACleanup();
		freeBuffers(sendbuf, recvbuf);
		return 1;
	}
	else if (recvbuf->tcph_syn == 1) {
		clientBufSize = recvbuf->max_bufsize;
		printf("Received SYN from Client.\nClient SN: %d\n", recvbuf->tcph_seqnum);
	}
	else {
		printf("SYN not received. Reject.\n");
		freeBuffers(sendbuf, recvbuf);
		WSACleanup();
		return 1;
	}
	sendbuf->tcph_syn = 1;
	sendbuf->tcph_ack = 1;
	sendbuf->tcph_seqnum = 1;
	sendbuf->tcph_acknum = recvbuf->tcph_seqnum + 1, nextSeq = 2;
	printf("Sending: syn flag: %d, ack flag: %d, seqnum: %d, acknum: %d\n", sendbuf->tcph_syn, sendbuf->tcph_ack,
		sendbuf->tcph_seqnum, sendbuf->tcph_acknum);
	iSendResult = send(ClientSocket, (char*)sendbuf, CONTROL_BUFFER_SIZE, 0);
	if (iSendResult == SOCKET_ERROR) {
		printf("send() failed with error code: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		freeBuffers(sendbuf, recvbuf);
		WSACleanup();
		return 1;
	}
	else
		printf("Sent SYN-ACK to Client.\n");
	// Receive ACK from Server and authenticate it:
	printf("Waiting for ACK from Client...\n");
	time(&start);
	for (;;) {
		iResult = recv(ClientSocket, (char*)recvbuf, CONTROL_BUFFER_SIZE, 0);
		if (time(NULL) > start + 10) {
			printf("10s receive timeout waiting for ACK (3way handshake)\n");
			closesocket(ClientSocket);
			freeBuffers(recvbuf, sendbuf);
			WSACleanup();
			return 1;
		}
		if (iResult == SOCKET_ERROR) {
			printf("recv() failed with error code: %d\n", WSAGetLastError());
			WSACleanup();
			freeBuffers(sendbuf, recvbuf);
			return 1;
		}
		else if (recvbuf->tcph_ack == 1 && recvbuf->tcph_syn == 0 && recvbuf->tcph_acknum == nextSeq) {
			printf("Received ACK from Client.\nConnection Established.\n");
			break;
		}
		else {
			printf("Incorrect ACK received. Rejecting connection...");
			closesocket(ClientSocket);
			WSACleanup();
			freeBuffers(sendbuf, recvbuf);
			return 1;
		}
	}
	// Evaluate and set new buffer size
	if (clientBufSize < MAX_BUFFER_SIZE)
		bufferSize = clientBufSize;
	else 
		bufferSize = MAX_BUFFER_SIZE;

	// Max payload size: (Size of my character array)
	int payload = payloadSize(bufferSize);
	printf("My payload size is: %ld\n", payload);
	// Receive data until peer closes connection:
	do {
		printf("Waiting for message...\n");
		time(&start);
		for (;;) {
			iResult = recv(ClientSocket, (char*)recvbuf, bufferSize, 0);
			if (time(NULL) > start + 10) {
				printf("10s Receive timeout waiting for message!\nClosing connection...\n");
				closesocket(ClientSocket);
				freeBuffers(sendbuf, recvbuf);
				WSACleanup();
				return 1;
			}
			break;
		}
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);
			//printf("Message received: %s\nSN received: %d\n", recvbuf->data, recvbuf->tcph_seqnum);
			std::cout << "Message received: " << recvbuf->data << std::endl;
			totalReceived += iResult;
			// Confirm Checksum, then send ACK.
			if (recvbuf->tcph_checksum == chksum(recvbuf)) {
				printf("Checksum matches.\n");
				clearFlags(sendbuf);
				sendbuf->tcph_ack = 1;
				sendbuf->tcph_acknum = recvbuf->tcph_seqnum + 1;
				printf("Sending ACKnum: %d\n", sendbuf->tcph_acknum);
				send(ClientSocket, (char*)sendbuf, bufferSize, 0);
			}
			else {
				while (recvbuf->tcph_checksum != chksum(recvbuf)) {
					printf("Checksum does not match.\nRetransmit packet.\n");
					recv(ClientSocket, (char*)recvbuf, bufferSize, 0);
				}
				printf("Checksum matches after retransmission.\n");
			}
		}
	} while (iResult > 0);

	// Disconnect the Server:
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("Shutdown of send failed: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		freeBuffers(sendbuf, recvbuf);
		WSACleanup();
		return 1;
	}
	printf("Total bytes received: %ld\n", totalReceived);
	printf("Total bytes sent: %ld\n", totalSent);
	closesocket(ClientSocket);
	freeBuffers(sendbuf, recvbuf);
	WSACleanup();

	return 0;

}
