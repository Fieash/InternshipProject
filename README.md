# InternshipProject

Rootkit detection program targeted at detecting Reptile rootkit by f0rb1dd3n
https://github.com/f0rb1dd3n/Reptile

The Main.c program is a Loadable Kernel Module that outputs the results to the system log,
and hidden_process_detection.c is a C program that outputs the hiding PIDs to the console.

It is currently able to detect the reptile module when it is hiding from the system
The method of detection is adapted from the Tyton rootkit hunter. 
https://github.com/nbulischeck/tyton

With hidden_process_detection.c, we are able to detect processes that are
attempting to hide from the system.

With syscall_detection.c, we can also detect syscalls that are being hidden from the system.


## Installation

### Hidden module detection
```
git clone https://github.com/Fieash/InternshipProject.git
make
sudo insmod main.ko
sudo rmmod main.ko
dmesg 
```
An alternative to watch the output is to use tail -f /var/log/syslog

### Hidden process detection

At line 46, modify the program according to your system's max PID found in 
the /proc/sys/kernel/pid_max file.
```
40    int main(int argc, char *argv[])
41    {
42        printf("==== rootkit detection start (hidden_process_detection.c)\n");
43        // first parameter should be your system's max PID, 
44        // found at /proc/sys/kernel/pid_max
45        // 0 for a second check (leave it as 0)
46        brute(131072, 0);
47        return 0;
48    }
```
Then compile it as a regular C program and run it with sudo.
```
gcc hidden_process_detection.c
sudo ./a.out
```

### Syscall hook detection
```
make
sudo insmod syscall_detection.ko
sudo rmmod syscall_detection.ko
dmesg
```