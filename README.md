# InternshipProject

Rootkit detection program targeted at detecting Reptile rootkit by f0rb1dd3n
https://github.com/f0rb1dd3n/Reptile and Diamoprhine rootkit by wazuh https://github.com/wazuh/Diamorphine.

main.c program is a Loadable Kernel Module that outputs the results to the system log,
and hidden_process_detection.c is a C program that outputs hidden PIDs to the console.

It is currently able to detect the reptile module when it is hiding from the system
The method of detection is adapted from the Tyton rootkit hunter. 
https://github.com/nbulischeck/tyton

With hidden_process_detection.c, we are able to detect processes that are
attempting to hide from the system.

syscall_detection.c is a Loadable Kernel Module that detects syscalls that have been hooked,
displaying their names and numbers in the output.

interrupt_detection.c is a Loadable Kernel Module that detects interrupts that have been hooked.


## Installation
```
git clone https://github.com/Fieash/InternshipProject.git
make
```

### Hidden module detection
```
sudo insmod module_detection.ko
sudo rmmod module_detection.ko
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
gcc process_detection.c
sudo ./a.out
```

### Syscall hook detection
```
sudo insmod syscall_detection.ko
sudo rmmod syscall_detection.ko
dmesg
```

### Interrupt hook detection
```
sudo insmod interrupt_detection.ko
sudo rmmod interrupt_detection.ko
dmesg
```
