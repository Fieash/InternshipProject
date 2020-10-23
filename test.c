// 23/10/2020 4:52pm working brute force of /proc/<pid> and add to array within selected range
// test.c to test out the program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int per_process_check_proc(int processID);
long int findSize(char file_name[]);
void hidden_process_check(void);
void make_ls_command(void);
char * find_hidden_process_name(int hiddenPID);




int main(int argc, char *argv[])
{
	printf("==== rootkit detection start (test.c)\n");
	make_ls_command();
	hidden_process_check();
	

	//per_process_check(24241); //should fail
	//per_process_check_proc(24240); //hidden dir
	
	return 0;
}

// loop to check all modules
void hidden_process_check(void)
{
	printf("==== hidden module check. \n");
	
	//int min = 24238;			// min PID to check from
	//int max = 24248; 			//system's max PID	
	int min = 20000;			// min PID to check from
	int max = 30000; 			//system's max PID	
	int count = min; 			//counter for adding and iterating arrays
	int proc_pid_array[max+10]; //generated with brute force, NOT tampered by rootkit
	int ls_pid_array[max+10]; 	//generated with ls command, IS tampered by rootkit
	int hiding_pid_array[max+10];

	while (count < max){
		proc_pid_array[count] = per_process_check_proc(count);
		//printf("count = %d\n", count);
		count++;
	}

	count = min; //reset counter
	// printf("===== pids from /proc (range %d to %d)\n=====\n", count, max);
	// while (count < max){
	// 	if (proc_pid_array[count] == 1){
	// 		printf("pid %d exists!\n", count);
	// 	}
	// 	count++;
	// }
	
	//read the file and generate the array with LS
	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("tmpls.txt", "r");
    if (fp == NULL){
		printf("tmpls.txt file is empty");
	}
    while ((read = getline(&line, &len, fp)) != -1){
        //printf("Retrieved line of length %zu:\n", read);
        // printf("%s", line);
		int num = atoi(line);
		if(num > max){
			//do nothing if num too large (prevents segfaults)
			// printf("PID is exceeding max\n");
		}else {
			// printf("%d\n",num);
			ls_pid_array[num] = 1; //1 to represent that it exists
		}
    }
	count = min; //reset counter
	// iterate the array fill the empty indexes with 2
	while(count < max){
		if(ls_pid_array[count] != 1){
			ls_pid_array[count] = 2; // 2 to represent that it is invalid
		}
		count++;
	}
    fclose(fp);
    if (line){
        free(line);
	}

	count = min; //reset counter
	int hideCount = 0;
	printf("===== pids from ls (range %d to %d)\n=====\n", count, max);
	while (count < max){
		// if ls is 2(miss) and proc is 1(exist), pid is hiding
		if(ls_pid_array[count] == 2 &&proc_pid_array[count] == 1){
			
			hiding_pid_array[hideCount] = count;
			hideCount++;
		}
		count++;
	}

	char * processName = "err";
	for(int i=0;i<hideCount;i++){
		processName = find_hidden_process_name(hiding_pid_array[i]);
		printf("PID %d hiding, process name is %s\n", hiding_pid_array[i], processName);
	}



}

//open a file and retunr the size of it
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

//checking existence of each process in PROC
int per_process_check_proc(int processID)
{
	char command[1024];
	snprintf(command, sizeof(command), "cat /proc/%d/maps > tmpproc.txt 2> /dev/null", processID);
	// printf("command is: %s \n",command); //debug print the command executed
	system(command);

	long int tmpSize = findSize("tmpproc.txt");
	if(tmpSize > 10.0)
	{
		//command passed, file exists
		//printf("size MORE than 10\n");
		return 1; //return 1 to the array, representing existing PID
	} else {
		return 2; //return 2 to the array, representing invalid PID
	} 


	//Found hidden PID: 24239 with name: reptile_shell
	//Found hidden PID: 24240 with name: bash

}

//make the ls command with grep and pipe to file
void make_ls_command(void)
{
	char command[1024];
	//ls the /proc directory and get all directories that include an int
	snprintf(command, sizeof(command), "ls /proc | grep [0-9] > tmpls.txt");
	// printf("command is: %s \n",command); //debug print the command executed
	system(command);
}

char * find_hidden_process_name(int hiddenPID){
	char command[1024];
	//ls the /proc directory and get all directories that include an int
	snprintf(command, sizeof(command), "head -1 /proc/%d/maps | rev | cut -d ' ' -f 1 | rev  > HPN.txt",hiddenPID);
	// printf("command is: %s \n",command); //debug print the command executed
	system(command);
	FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen("HPN.txt", "r");
    if (fp == NULL){
		printf("HPN.txt file is empty");
	}
    while ((read = getline(&line, &len, fp)) != -1){
        return line;
    }
	//if fail
	return "fail";
}



