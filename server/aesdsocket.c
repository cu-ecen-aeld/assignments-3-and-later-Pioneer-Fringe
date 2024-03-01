#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

static char fileName[] = "/var/tmp/aesdsocketdata";
static int socketFd = -1;

void handle_sigint_sigterm(int sig)
{
    if ((SIGINT == sig) || (SIGTERM == sig))
    {
        syslog(LOG_INFO, "Caught signal, exiting");
        if (socketFd != -1)
        {
            close(socketFd);
            socketFd = -1;
        }

        if (remove(fileName) != 0)
        {
            syslog(LOG_ERR, "Deleting %s Failed!", fileName);
            closelog();
            exit(-1);
        }
        
        closelog();
        exit(0);
    }
}

int main(int argc, char *argv[])
{
    FILE *pFileToWrite = NULL;
    struct addrinfo hints;
    struct addrinfo *result, *opAddrInfo;
    int acceptedFd = -1;
    struct sockaddr peerAddr;
    socklen_t peerAddrSize;
    
    char *dataBuffer = NULL;
    
    openlog(NULL, 0, LOG_USER);

    if ((signal(SIGINT, handle_sigint_sigterm) == SIG_ERR) ||(signal(SIGTERM, handle_sigint_sigterm) == SIG_ERR))
    {
        syslog(LOG_ERR, "Register signal SIGINT & SIGTERM Failed!");
        closelog();
        exit(-1);
    }
  
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, "9000", &hints, &result) != 0)
    {
        syslog(LOG_ERR, "Getting Address Info Failed!");
        closelog();
        exit(-1);
    }
    
    opAddrInfo = result;
    while (opAddrInfo != NULL)
    {
        socketFd = socket(opAddrInfo->ai_family, opAddrInfo->ai_socktype, opAddrInfo->ai_protocol);
        if (socketFd == -1)
            opAddrInfo = opAddrInfo->ai_next;
        else
            break;
    }

    if (socketFd == -1)
    {
        syslog(LOG_ERR, "Creating Socket Failed!");
        freeaddrinfo(result);
        closelog();
        exit(-1);
    }
    
    if (setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        syslog(LOG_ERR, "Set Socket Option Failed!");
        freeaddrinfo(result);
        close(socketFd);
        socketFd = -1;
        closelog();
        exit(-1);
    }

    if (bind(socketFd, opAddrInfo->ai_addr, opAddrInfo->ai_addrlen) != 0)
    {
        syslog(LOG_ERR, "Binding to Socket Failed!");
        freeaddrinfo(result);
        close(socketFd);
        socketFd = -1;
        closelog();
        exit(-1);
    }
    freeaddrinfo(result);

    //daemon handling after binding
    if ((argc == 2) && !strcmp(argv[1], "-d"))
    {
        daemon(0, 0);
    }

    if (listen(socketFd, 20) != 0)
    {
        syslog(LOG_ERR, "Setting Listen to Socket Failed!");
        close(socketFd);
        socketFd = -1;
        closelog();
        exit(-1);
    }

    while (1)
    {
        peerAddrSize = sizeof(peerAddr);
        acceptedFd = accept(socketFd, (struct sockaddr *)&peerAddr, &peerAddrSize);
        if (acceptedFd == -1)
        {
            syslog(LOG_ERR, "Accepting Socket Connection Failed!");
        }
        else
        {
            syslog(LOG_INFO, "Accepted connection from %s", peerAddr.sa_data);
            
            pFileToWrite = fopen(fileName, "a");
            if (pFileToWrite == NULL)
            {
                syslog(LOG_ERR, "Open File %s Failed!", fileName);
                close(acceptedFd);
                close(socketFd);
                socketFd = -1;
                closelog();
                exit(-1);
            }
            
            dataBuffer = (char *)malloc(BUFFER_SIZE);
            if (dataBuffer == NULL)
            {
                syslog(LOG_ERR, "Malloc operating Buffer Failed!");
                close(acceptedFd);
                close(socketFd);
                socketFd = -1;
                closelog();
                exit(-1);
            }
            
            unsigned char exitLoop = 0;
            ssize_t numRecvdBytes;
            while (!exitLoop)
            {
                memset(dataBuffer, 0, BUFFER_SIZE);
                numRecvdBytes = recv(acceptedFd, dataBuffer, sizeof(dataBuffer), 0);
                if ((numRecvdBytes <= 0) || (strchr(dataBuffer, '\n') != NULL))
                {
                    exitLoop = 1;
                }
                
                if (numRecvdBytes > 0)
                {
                    if (fwrite(dataBuffer, 1, numRecvdBytes, pFileToWrite) != numRecvdBytes)
                    {
                        syslog(LOG_ERR, "Write to File Failed!");
                        fclose(pFileToWrite);
                        free(dataBuffer);
                        close(acceptedFd);
                        close(socketFd);
                        socketFd = -1;
                        closelog();
                        exit(-1);
                    }
                }
            }
            fclose(pFileToWrite);
            free(dataBuffer);
            
            pFileToWrite = fopen(fileName, "r");
            if (pFileToWrite == NULL)
            {
                syslog(LOG_ERR, "Open File %s Failed!", fileName);
                close(acceptedFd);
                close(socketFd);
                socketFd = -1;
                closelog();
                exit(-1);
            }
            
            dataBuffer = (char *)malloc(BUFFER_SIZE);
            if (dataBuffer == NULL)
            {
                syslog(LOG_ERR, "Malloc operating Buffer Failed!");
                close(acceptedFd);
                close(socketFd);
                socketFd = -1;
                closelog();
                exit(-1);
            }
            
            exitLoop = 0;
            size_t numReadBytes;
            while (!exitLoop)
            {
                numReadBytes = fread(dataBuffer, 1, sizeof(dataBuffer), pFileToWrite);
                if ((numReadBytes == 0) || (numReadBytes < sizeof(dataBuffer)))
                {
                    exitLoop = 1;
                }
                
                if (numReadBytes > 0)
                {
                    if (send(acceptedFd, dataBuffer, numReadBytes, 0) != numReadBytes)
                    {
                        syslog(LOG_ERR, "Send to Socket Failed!");
                        fclose(pFileToWrite);
                        free(dataBuffer);
                        close(acceptedFd);
                        close(socketFd);
                        socketFd = -1;
                        closelog();
                        exit(-1);
                    }
                }
            }
            fclose(pFileToWrite);
            free(dataBuffer);
            
            close(acceptedFd);
            syslog(LOG_INFO, "Closed connection from %s", peerAddr.sa_data);
        }
    }

    return 0;
}
