#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>
#include <time.h>
#include <stdint.h>

#define BUFFER_SIZE 1024
#define TIMESTAMP_INT 10

#define USE_AESD_CHAR_DEVICE 1

//BUILD FLAG
#if (USE_AESD_CHAR_DEVICE)
    static char fileName[] = "/dev/aesdchar";
#else
    static char fileName[] = "/var/tmp/aesdsocketdata";
    pthread_mutex_t fileMutex;
#endif
//BUILD FLAG

static int socketFd = -1;
timer_t timerId = 0;

struct connHandlerData_s
{
    int connClosed;
    int connFd;
    char *peer_sa_data;
};

struct connEntry
{
    pthread_t threadId;
    struct connHandlerData_s* pConnData;
    SLIST_ENTRY(connEntry) connEntries;
};

SLIST_HEAD(slisthead_conn, connEntry);
static struct slisthead_conn head_conn;

void handle_sigint_sigterm(int sig)
{
    int rtnVal;
    struct connEntry *tempEntry = NULL;

    if ((SIGINT == sig) || (SIGTERM == sig))
    {
        syslog(LOG_INFO, "Caught signal, exiting\n");
        while(!SLIST_EMPTY(&head_conn))
        {
            tempEntry = SLIST_FIRST(&head_conn);
            if (tempEntry->pConnData->connClosed == 0)
            {
                rtnVal = pthread_cancel(tempEntry->threadId);
                if (rtnVal != 0)
                {
                    syslog(LOG_ERR, "pthread_cancel Failed with error%d!\n", rtnVal);
                    closelog();
                    exit(-1);
                }
            }
            if (pthread_join(tempEntry->threadId, NULL) != 0)
            {
                syslog(LOG_ERR, "pthread_join Failed!\n");
                closelog();
                exit(-1);
            }
            SLIST_REMOVE_HEAD(&head_conn, connEntries);
            free(tempEntry->pConnData);
            free(tempEntry);
        }

        if (socketFd != -1)
        {
            close(socketFd);
            socketFd = -1;
        }

//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
        if (remove(fileName) != 0)
        {
            syslog(LOG_ERR, "Deleting %s Failed!\n", fileName);
            closelog();
            exit(-1);
        }
#endif
//BUILD FLAG   
        if (timer_delete(timerId) != 0)
        {
            syslog(LOG_ERR, "timer_delete Failed!\n");
            closelog();
            exit(-1);
        }
        
        closelog();
        exit(0);
    }
}

void handle_timestamp(int sig, siginfo_t *si, void *uc)
{
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
    char timestampStr[128] = { 0 };
    time_t timerPtr;
    struct tm *timeInfo;
    FILE *pFileToWrite = NULL;
    int rtnVal;

    if (SIGRTMIN == sig)
    {
        rtnVal = pthread_mutex_lock(&fileMutex);
        if (rtnVal != 0)
        {
            syslog(LOG_ERR, "pthread_mutex_lock failed with error %d!\n", rtnVal);
            closelog();
            exit(-1);
        }
        else
        {
            pFileToWrite = fopen(fileName, "a");
            if (pFileToWrite == NULL)
            {
                syslog(LOG_ERR, "Open File %s Failed!\n", fileName);
                closelog();
                exit(-1);
            }
        
            timerPtr = time(NULL);
            timeInfo = localtime(&timerPtr);
            if (timeInfo == NULL)
            {
                syslog(LOG_ERR, "localtime\n");
                fclose(pFileToWrite);
                closelog();
                exit(-1);
            }
            
            if (strftime(timestampStr, sizeof(timestampStr), "timestamp:%Y-%m-%d %H:%M:%S\n", timeInfo) == 0)
            {
                syslog(LOG_ERR, "strftime returned 0");
                fclose(pFileToWrite);
                closelog();
                exit(-1);
            }
            
            fprintf(pFileToWrite, "%s", timestampStr);
            
            fclose(pFileToWrite);
            rtnVal = pthread_mutex_unlock(&fileMutex);
        }
    }
#endif
//BUILD FLAG   
}

void* connHandler(void* connHandlerParams)
{
    struct connHandlerData_s* connHandlerArgs = (struct connHandlerData_s *) connHandlerParams;
    char *dataBuffer = NULL;
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
    int rtnVal;
#endif
//BUILD FLAG
    FILE *pFileToWrite = NULL;
    unsigned char exitLoop;
    
    syslog(LOG_INFO, "Accepted connection from %s\n", connHandlerArgs->peer_sa_data);
    
    //Disable Cancellation Until connection is properly closed
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) != 0)
    {
        syslog(LOG_ERR, "pthread_setcancelstate(DISABLE) failed with error!\n");
        close(connHandlerArgs->connFd);
        connHandlerArgs->connClosed = -1;
        return connHandlerParams;
    }
    
    //Read Connection and Write to File
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
    rtnVal = pthread_mutex_lock(&fileMutex);
    if (rtnVal != 0)
    {
        syslog(LOG_ERR, "pthread_mutex_lock failed with error %d!\n", rtnVal);
        close(connHandlerArgs->connFd);
        connHandlerArgs->connClosed = -1;
        return connHandlerParams;
    }
    else
#endif
//BUILD FLAG
    {
        pFileToWrite = fopen(fileName, "a");
        if (pFileToWrite == NULL)
        {
            syslog(LOG_ERR, "Open File %s Failed!\n", fileName);
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
        }
        
        dataBuffer = (char *)malloc(BUFFER_SIZE);
        if (dataBuffer == NULL)
        {
            syslog(LOG_ERR, "Malloc operating Buffer Failed!\n");
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
        }
        
        exitLoop = 0;
        ssize_t numRecvdBytes;
        while (!exitLoop)
        {
            memset(dataBuffer, 0, BUFFER_SIZE);
            numRecvdBytes = recv(connHandlerArgs->connFd, dataBuffer, sizeof(dataBuffer), 0);
            if ((numRecvdBytes <= 0) || (strchr(dataBuffer, '\n') != NULL))
            {
                exitLoop = 1;
            }
            
            if (numRecvdBytes > 0)
            {
                if (fwrite(dataBuffer, 1, numRecvdBytes, pFileToWrite) != numRecvdBytes)
                {
                    syslog(LOG_ERR, "Write to File Failed!\n");
                    fclose(pFileToWrite);
                    free(dataBuffer);
                    close(connHandlerArgs->connFd);
                    connHandlerArgs->connClosed = -1;
                    return connHandlerParams;
                }
            }
        }
        fclose(pFileToWrite);
        free(dataBuffer);
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)        
        rtnVal = pthread_mutex_unlock(&fileMutex);
        if (rtnVal != 0)
        {
            syslog(LOG_ERR, "pthread_mutex_unlock failed with error %d!\n", rtnVal);
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
        }
#endif
//BUILD FLAG
    }
    
    //Read File and Write to Connection
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE) 
    rtnVal = pthread_mutex_lock(&fileMutex);
    if (rtnVal != 0)
    {
        syslog(LOG_ERR, "pthread_mutex_lock failed with error %d!\n", rtnVal);
        close(connHandlerArgs->connFd);
        connHandlerArgs->connClosed = -1;
        return connHandlerParams;
    }
    else
#endif
//BUILD FLAG
    {
        pFileToWrite = fopen(fileName, "r");
        if (pFileToWrite == NULL)
        {
            syslog(LOG_ERR, "Open File %s Failed!\n", fileName);
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
        }
            
        dataBuffer = (char *)malloc(BUFFER_SIZE);
        if (dataBuffer == NULL)
        {
            syslog(LOG_ERR, "Malloc operating Buffer Failed!\n");
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
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
                if (send(connHandlerArgs->connFd, dataBuffer, numReadBytes, 0) != numReadBytes)
                {
                    syslog(LOG_ERR, "Send to Socket Failed!\n");
                    fclose(pFileToWrite);
                    free(dataBuffer);
                    close(connHandlerArgs->connFd);
                    connHandlerArgs->connClosed = -1;
                    return connHandlerParams;
                }
            }
        }
        fclose(pFileToWrite);
        free(dataBuffer);
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
        rtnVal = pthread_mutex_unlock(&fileMutex);
        if (rtnVal != 0)
        {
            syslog(LOG_ERR, "pthread_mutex_unlock failed with error %d!\n", rtnVal);
            close(connHandlerArgs->connFd);
            connHandlerArgs->connClosed = -1;
            return connHandlerParams;
        }
#endif
//BUILD FLAG
    }
    
    close(connHandlerArgs->connFd);
    connHandlerArgs->connClosed = 1;
    syslog(LOG_INFO, "Closed connection from %s\n", connHandlerArgs->peer_sa_data);
    
    //Enable Cancellation
    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
    {
        syslog(LOG_ERR, "pthread_setcancelstate(ENABLE) failed with error!\n");
        close(connHandlerArgs->connFd);
        connHandlerArgs->connClosed = -1;
        return connHandlerParams;
    }
    
    return connHandlerParams;
}

int main(int argc, char *argv[])
{
    struct addrinfo hints;
    struct addrinfo *result, *opAddrInfo;
    struct sockaddr peerAddr;
    socklen_t peerAddrSize;
    int rtnVal;
    pthread_t threadId;
    int connFd = -1;
    struct connEntry *tempEntry = NULL;
//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
    struct sigevent sev;
    struct sigaction sa;
    struct itimerspec its;
#endif
//BUILD FLAG
    int closedConnFound;
    //sigset_t set, oldSet;
    
    if ((signal(SIGINT, handle_sigint_sigterm) == SIG_ERR) ||(signal(SIGTERM, handle_sigint_sigterm) == SIG_ERR))
    {
        syslog(LOG_ERR, "Register signal SIGINT & SIGTERM Failed!\n");
        closelog();
        exit(-1);
    }
  
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, "9000", &hints, &result) != 0)
    {
        syslog(LOG_ERR, "Getting Address Info Failed!\n");
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
        syslog(LOG_ERR, "Creating Socket Failed!\n");
        freeaddrinfo(result);
        closelog();
        exit(-1);
    }
    
    if (setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0)
    {
        syslog(LOG_ERR, "Set Socket Option Failed!\n");
        freeaddrinfo(result);
        close(socketFd);
        socketFd = -1;
        closelog();
        exit(-1);
    }

    if (bind(socketFd, opAddrInfo->ai_addr, opAddrInfo->ai_addrlen) != 0)
    {
        syslog(LOG_ERR, "Binding to Socket Failed!\n");
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
    
    SLIST_INIT(&head_conn);
    
    openlog(NULL, 0, LOG_USER);

//BUILD FLAG
#if (!USE_AESD_CHAR_DEVICE)
    //Setup timer
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    sev.sigev_value.sival_ptr = &timerId;
    
    rtnVal = timer_create(CLOCK_REALTIME, &sev, &timerId);
    if (rtnVal != 0)
    {
        syslog(LOG_ERR, "time_create for Timestamp Failed!\n");
        closelog();
        exit(-1);
    }

    //Establish handler for timer signal
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handle_timestamp;
    
    //Init signal
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGRTMIN, &sa, NULL) == -1)
    {
        syslog(LOG_ERR, "Sigaction for Timestamp Failed!\n");
        closelog();
        exit(-1);
    }

    //Start timer
    its.it_value.tv_sec = TIMESTAMP_INT;
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = TIMESTAMP_INT;
    its.it_interval.tv_nsec = 0;
    rtnVal = timer_settime(timerId, 0, &its, NULL);
    if (rtnVal != 0)
    {
        syslog(LOG_ERR, "timer_settime for Timestamp Failed!\n");
        closelog();
        exit(-1);
    }
#endif
//BUILD FLAG
    if (listen(socketFd, 20) != 0)
    {
        syslog(LOG_ERR, "Setting Listen to Socket Failed!\n");
        close(socketFd);
        socketFd = -1;
        closelog();
        exit(-1);
    }

    while (1)
    {
        //attempt accept connection
        peerAddrSize = sizeof(peerAddr);
        connFd = accept(socketFd, (struct sockaddr *)&peerAddr, &peerAddrSize);
        if (connFd == -1)
        {
            syslog(LOG_ERR, "Accepting Socket Connection Failed!\n");
        }
        else
        {
            struct connHandlerData_s* connData = malloc(sizeof(struct connHandlerData_s));
            connData->connClosed = 0;
            connData->connFd = connFd;
            connData->peer_sa_data = peerAddr.sa_data;
            
            //sigemptyset(&set);
            //sigaddset(&set, SIGINT);
            //sigaddset(&set, SIGTERM);
            //pthread_sigmask(SIG_BLOCK, &set, &oldSet);
            rtnVal = pthread_create(&threadId, NULL, connHandler, connData);
            if (rtnVal != 0)
            {
                syslog(LOG_ERR, "pthread_create failed with error %d creating thread %lu!\n", rtnVal, threadId);
                close(socketFd);
                socketFd = -1;
                closelog();
                exit(-1);
            }
            else
            {
                tempEntry = malloc(sizeof(struct connEntry));
                tempEntry->threadId = threadId;
                tempEntry->pConnData = connData;
                SLIST_INSERT_HEAD(&head_conn, tempEntry, connEntries);
            }
            //pthread_sigmask(SIG_SETMASK, &oldSet, NULL);
        }
        
        //traverse all live threads, join if ended.
        if (!SLIST_EMPTY(&head_conn))
        {
            tempEntry = SLIST_FIRST(&head_conn);
            if ((tempEntry->pConnData->connClosed == -1) || (tempEntry->pConnData->connClosed == 1))
            {
                if (tempEntry->pConnData->connClosed == -1) syslog(LOG_ERR, "Thread %lu Connection closed with Error!\n", tempEntry->threadId);
                pthread_join(tempEntry->threadId, NULL);
                SLIST_REMOVE_HEAD(&head_conn, connEntries);
                free(tempEntry->pConnData);
                free(tempEntry);
            }
            
            closedConnFound = 0;
            SLIST_FOREACH(tempEntry, &head_conn, connEntries)
            {
                if (tempEntry->pConnData->connClosed != 0)
                {
                    closedConnFound = 1;
                    break;
                }
            }
            if (closedConnFound == 1)
            {
                if ((tempEntry->pConnData->connClosed == -1) || (tempEntry->pConnData->connClosed == 1))
                {
                    if (tempEntry->pConnData->connClosed == -1) syslog(LOG_ERR, "Thread %lu Connection closed with Error!\n", tempEntry->threadId);
                    pthread_join(tempEntry->threadId, NULL);
                    SLIST_REMOVE(&head_conn, tempEntry, connEntry, connEntries);
                    free(tempEntry->pConnData);
                    free(tempEntry);
                }
            }
        }
    }

    return 0;
}
