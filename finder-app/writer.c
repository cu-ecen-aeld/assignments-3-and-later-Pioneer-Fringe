#include <stdio.h>
#include <syslog.h>

int main(int argc, char *argv[])
{
    FILE *pFileToWrite = NULL;

    openlog(NULL, 0, LOG_USER);
    if (argc != 3)
    {
    	printf("Error: expect 2 parameters, getting %d\n", argc - 1);
        syslog(LOG_ERR, "Error: expect 2 parameters, getting %d", argc - 1);
        return 1;
    }
    else
    {
        pFileToWrite = fopen(argv[1], "w");
        if (NULL == pFileToWrite)
        {
        	printf("Error: file could not be opened\n");
            syslog(LOG_ERR, "Error: file could not be opened");
            return 1;
        }
        else
        {
            fprintf(pFileToWrite, "%s", argv[2]);
            //printf("Writing %s to %s\n", argv[2], argv[1]);
            syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
        }
        fclose(pFileToWrite);
    }
    closelog();
    
    return 0;
}
