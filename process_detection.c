#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>

// External commands
#define COMMAND "ps --no-header -p %i o pid"
// we are looking for session ID one by one
#define SESSION "ps --no-header -s %i o sess"
// We are looking for group ID one by one
#define PGID "ps --no-header -eL o pgid"
// We are looking for all processes even threads
#define THREADS "ps --no-header -eL o lwp"

// Masks for the checks to do in checkps()
#define PS_PROC         0x00000001
#define PS_THREAD       0x00000002
#define PS_MORE         0x00000004

int  checkps(int tmppid, int checks) ;
void printbadpid (int tmppid) ;
void brute(int maxpid, int check);
char * find_hidden_process_name(int hiddenPID);
long int findSize(char file_name[]);
int counter = 0;

int main(int argc, char *argv[])
{
	printf("==== Start hidden process detection app ====\n");
    // first parameter should be your system's max PID, 
	// found at /proc/sys/kernel/pid_max
	// 0 for a second check (leave it as 0)
	brute(131072, 0);
	printf("==== Exit hidden process detection app ====\n");
	return 0;
}

/*
 *  Brute force the pid space via vfork. All PIDs which
 *  can't be obtained are checked against ps output
 */
void brute(int maxpid, int check) 
{
    int i=0;
    int allpids[maxpid] ;
    int allpids2[maxpid] ;
    int x;
    int y;
    int z;

    printf("==== Brute force PID scan with fork() range 301 to %d ====\n\n", maxpid);

    // PID under 301 are reserved for kernel
	// fill them up with zeros
    for(x=0; x < 301; x++) 
    {
        allpids[x] = 0 ;
        allpids2[x] = 0 ;
    }

    for(z=301; z < maxpid; z++) 
    {
        allpids[z] = z ;
        allpids2[z] = z ;
    }

    for (i=301; i < maxpid; i++) 
    {
        int vpid;
        int status;

        errno= 0 ;

        if ((vpid = vfork()) == 0) 
        {
            _exit(0);
        }

        if (0 == errno) 
        {
            allpids[vpid] =  0;
            waitpid(vpid, &status, 0);
        }
    }

    if(0 == check)   // Do the scan a second time
    {
    //    printf("DOING double check ...\n") ;
        for (i=301; i < maxpid; i++) 
        {
            int vpid;
            int status;
            errno= 0 ;

            if ((vpid = vfork()) == 0) 
            {
                _exit(0);
            }

            if (0 == errno) 
            {
                allpids2[vpid] =  0;
                waitpid(vpid, &status, 0);
            }
        }
    }

   /* processes that quit at this point in time create false positives */
   for(y=0; y < maxpid; y++) 
   {
        if ((allpids[y] != 0) && ((0 == check) || (allpids2[y] != 0))) 
        {
            //printf("Check PID : %d\n", y);
            if(!checkps(allpids[y],PS_PROC | PS_THREAD | PS_MORE) ) 
            {
                printbadpid(allpids[y]);
            }
        }
   }

   	if (counter == 0) 
	{
		printf("Result: No hidden processes found.\n\n");
	}
	else
	{
		printf("Result: %d hidden process(es) found.\n\n", counter);
	}

}

void printbadpid(int badPid)
{
	char * processName = "err";
	processName = find_hidden_process_name(badPid);
	if(processName != "fail" && processName != "nonExist")
	{
		printf("Suspicious PID [%d]: %s\n", badPid, processName);
		counter++;
	}
	else
	{
		//printf("process name is %s", processName); //debug
	}
		
}

// head the PIDs maps file and read the last part, output to HPN.txt and return the string.
// if there are no errors (file exists), procNameErr will be cleared
char * find_hidden_process_name(int hiddenPID){
	char command[1024];
	snprintf(command, sizeof(command), "head -1 /proc/%d/maps 2> procNameErr.txt | rev | cut -d ' ' -f 1 | rev  > HPN.txt",hiddenPID);
	// printf("command is: %s \n",command); //debug print the command executed
	system(command);
	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("HPN.txt", "r");
    if (fp == NULL){
		printf("HPN.txt file is empty");
        return "empty";
	}
	if (findSize("procNameErr.txt") > 1){
		return "nonExist";
	}
    while ((read = getline(&line, &len, fp)) != -1){
        if(line == NULL){
            return "NULL";
        }
        return line;
    }
	//if fail
	return "fail";
}

long int findSize(char file_name[]) 
{ 
	// opening the file in read mode 
	FILE* fp = fopen(file_name, "r"); 
	// checking if the file exist or not 
	if (fp == NULL) { 
		printf("File Not Found!\n"); 
		return -1; 
	}
	fseek(fp, 0L, SEEK_END); 
	// calculating the size of the file 
	long int res = ftell(fp); 
	// closing the file 
	fclose(fp); 
	return res; 
} 

// verify if ps sees the pid
int checkps(int tmppid, int checks) 
{

	int ok = 0;
	char pids[30];

	char compare[100];
	char command[60];

	FILE *fich_tmp ;

	// The compare string is the same for all test
	sprintf(compare,"%i\n",tmppid);

	if (PS_PROC == (checks & PS_PROC)) 
	{
		sprintf(command,COMMAND,tmppid) ;

		fich_tmp=popen (command, "r") ;
		if (fich_tmp == NULL) 
		{
			return(0);
		}

		{
			char* tmp_pids = pids;

			if (NULL != fgets(pids, 30, fich_tmp)) 
			{
				pids[29] = 0;

				while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
				{
				tmp_pids++;
				}

				if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
			}
		}

		if (NULL != fich_tmp){
			pclose(fich_tmp);
		}	

		if (1 == ok) return(ok) ;   // pid is found, no need to go further
	}

	if (PS_THREAD == (checks & PS_THREAD)) 
	{
		FILE *fich_thread ;

		fich_thread=popen (THREADS, "r") ;
		if (NULL == fich_thread) 
		{
			return(0);
		}

		while ((NULL != fgets(pids, 30, fich_thread)) && ok == 0) 
		{
			char* tmp_pids = pids;

			pids[29] = 0;

			while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
			{
				tmp_pids++;
			}

			if (strncmp(tmp_pids, compare, 30) == 0) {ok = 1;}
		}
		if (fich_thread != NULL)
			pclose(fich_thread);

		if (1 == ok) return(ok) ;   // thread is found, no need to go further
	}

	if (PS_MORE == (checks & PS_MORE)) 
	{

		FILE *fich_session ;

		sprintf(command,SESSION,tmppid) ;

		fich_session=popen (command, "r") ;
		if (fich_session == NULL) 
		{
			return(0);
		}

		while ((NULL != fgets(pids, 30, fich_session)) && ok == 0) 
		{
			char* tmp_pids = pids;

			pids[29] = 0;

			while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
			{
				tmp_pids++;
			}

			if (strncmp(tmp_pids, compare, 30) == 0) 
			{
				ok = 1;
			}
		}

		pclose(fich_session);

		if (1 == ok) 
			return(ok) ;   // session is found, no need to go further

		FILE *fich_pgid ;

		fich_pgid=popen (PGID, "r") ;
		if (NULL == fich_pgid) 
		{
			return(0);
		}

		while ((NULL != fgets(pids, 30, fich_pgid)) && ok == 0) 
		{
			char* tmp_pids = pids;

			pids[29] = 0;

			while( *tmp_pids == ' ' && tmp_pids <= pids+29) 
			{
				tmp_pids++;
			}

			if (strncmp(tmp_pids, compare, 30) == 0) 
			{
				ok = 1;
			}
		}

		pclose(fich_pgid);

	}
	return ok;
}
