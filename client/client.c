#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>
#include <strings.h>


#define ANSWER_BUFFER_SIZE 10000
#define PROTO_HELLO_SUPPORTED_VERSION 0x01

// PROTOCOL CODES
#define VALID_USER                        0x00
#define INVALID_USER                      0x01
#define VERSION_NOT_SUPPORTED             0x02
#define INTERNAL_ERROR                    0x03

void printMenu();
int sendHelloAndRequest(int option);

char usr [255] = {0};
char pass [255] = {0};    
int portno;
char hostName [255] = {0};
char newBufferSize [255] = {0};

int main (int argc, char ** argv) {
    uint8_t option;

    if(argc == 2 && strcmp(argv[1], "-h") == 0) {
        printMenu();
        return 0;
    }

    if(argc != 6 && argc != 7) {
        printf("Invalid number of arguments.\n");
        printMenu();
        exit(EXIT_FAILURE);
    }
        

    portno = atoi(argv[1]);
    strcpy(hostName, argv[2]);
    strcpy(usr, argv[3]);
    strcpy(pass, argv[4]);
    option = argv[5][0];

    switch(option) {
        case '1':
            sendHelloAndRequest(1);
            break;
        case '2':
            sendHelloAndRequest(2);
            break;
        case '3':
            sendHelloAndRequest(3);
            break;
        case '4':
            if(argc != 7)
                exit(EXIT_FAILURE);
            strcpy(newBufferSize, argv[6]);
            sendHelloAndRequest(4);
            break;
        default:
            printf("Invalid option\n");
            break;        
    }
}    

int sendHelloAndRequest(int option){
    struct hostent *server;

    server = gethostbyname(hostName);
    if (server == NULL) {
        fprintf(stderr,"No such host\n");
        exit(EXIT_FAILURE);
    }

    size_t i = 0;
    uint8_t* hello = malloc(3 + strlen(usr) + strlen(pass));
    
    hello[i++] = PROTO_HELLO_SUPPORTED_VERSION;
    hello[i++] = strlen(usr);
    for(; i < strlen(usr) + 2; i++)
        hello[i] = usr[i - 2];
    hello[i++] = strlen(pass);
    for(; i < strlen(usr) + 3 + strlen(pass); i++)
        hello[i] = pass[i - 3 - strlen(usr)];

    int sockfd;
    struct sockaddr_in serv_addr;
    int n;

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(EXIT_FAILURE);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr_list[0], (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    /* Now connect to the server */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(EXIT_FAILURE);
    }

    uint8_t answer_buffer[ANSWER_BUFFER_SIZE];

    /* Send hello to the server */
    n = write(sockfd, hello, i);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(EXIT_FAILURE);
    }

    /* Now read server hello response */
    bzero(answer_buffer, ANSWER_BUFFER_SIZE);
    n = read(sockfd, answer_buffer, ANSWER_BUFFER_SIZE);

    if (n < 0) {
        perror("ERROR reading from socket");
        exit(EXIT_FAILURE);
    }

    if(answer_buffer[0] == PROTO_HELLO_SUPPORTED_VERSION && answer_buffer[1] == INVALID_USER) {
        printf("Invalid username or password\n");
        exit(EXIT_FAILURE);
    }

    if(answer_buffer[0] == PROTO_HELLO_SUPPORTED_VERSION && answer_buffer[1] == VERSION_NOT_SUPPORTED) {
        printf("Unsupported version\n");
        exit(EXIT_FAILURE);
    }

    if(answer_buffer[0] == PROTO_HELLO_SUPPORTED_VERSION && answer_buffer[1] == INTERNAL_ERROR) {
        printf("Internal server error\n");
        exit(EXIT_FAILURE);
    }


    /* Send request to the server */
    uint8_t *request = NULL;
    switch(option) {
    case 1:
        //request = {0x00, 0x00};
        request = malloc(2);
        request[0] = 0x00;
        request[1] = 0x00;
        n = write(sockfd, request, 2);
        break;
    case 2:
        request = malloc(2);
        request[0] = 0x01;
        request[1] = 0x00;
        n = write(sockfd, request, 2);
        break;
    case 3:
        request = malloc(2);
        request[0] = 0x02;
        request[1] = 0x00;
        n = write(sockfd, request, 2);
        break;
    case 4:
        i = 0;
        request = malloc(3 + strlen(newBufferSize));
        request[i++] = 0x03;
        request[i++] = 0x01;
        request[i++] = strlen(newBufferSize);
        for(; i < strlen(newBufferSize) + 3; i++)
            request[i] = newBufferSize[i - 3];
        n = write(sockfd, request, i);
        break;
    default:
        exit(EXIT_FAILURE);
    }

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(EXIT_FAILURE);
    }

    /* Now read server response */
    bzero(answer_buffer, ANSWER_BUFFER_SIZE);
    n = read(sockfd, answer_buffer, ANSWER_BUFFER_SIZE);

    if(n < 0) {
        perror("ERROR reading from socket");
        exit(EXIT_FAILURE);
    }

    if(answer_buffer[0] == 0xFF) 
        printf("Invalid request\n");
    else if(answer_buffer[0] == 0xFE)
        printf("Server error\n");
        
    printf("Response: ");
    for(i = 2; (int)i < answer_buffer[1] + 2; i++)
        printf("%c", answer_buffer[i]);
    printf("\n");

    // free resources
    if(hello != NULL) {
        free(hello);
    }
    if(request != NULL) {
        free(request);
    }

    close(sockfd);
    
    return 0;
}

void printMenu() {
    printf("Usage: ./<executable_name> <port_number> <hostname> <username> <password> <option> (<option_params>)\n\n");
    
    printf("Options:\n");
    printf("1. Get hystorical number of connections\n");
    printf("2. Get concurrent connections\n");
    printf("3. Get bytes transfered\n");
    printf("4. Set new buffer size. Param: <new_buffer_size>\n\n");
    
    printf("To print help menu: ./<executable_name> -h\n");
}

