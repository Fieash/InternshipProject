# InternshipProject

rootkit detection program targeted at detecting Reptile rootkit by f0rb1dd3n
https://github.com/f0rb1dd3n/Reptile

The program is a Loadable Kernel Module that outputs the results to the system log

It is currently able to detect the reptile module when it is hiding from the system
The method of detection is adapted from the Tyton rootkit hunter 
https://github.com/nbulischeck/tyton

I am currenlty working on detecting the processes hidden by the reptile rootkit

## Installation

```
git clone https://github.com/Fieash/InternshipProject.git
make
sudo insmod main.ko
sudo rmmod main.ko
dmesg (check the output)
```
An alternative is to use tail -f /var/log/syslog
