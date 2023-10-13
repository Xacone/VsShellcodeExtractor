# Visual Studio Shellcode Extractor
Time-saving tool for extracting and formatting shellcode extracted from visual studio (and more).

<b>Suppose you have the following content in a file named decompiled.txt : </b>
```asm
40 53                push        rbx  
48 83 EC 30          sub         rsp,30h  
65 48 8B 04 25 60 00 00 00 mov         rax,qword ptr gs:[60h]  
33 DB                xor         ebx,ebx  
48 8B 48 18          mov         rcx,qword ptr [rax+18h]

...... blah blah

8B D0                mov         edx,eax  
41 0F B7 04 53       movzx       eax,word ptr [r11+rdx*2]  
```
<b>

<b>The program extracts the shellcode and formats it in a C way : </b>

```shell
>> python3 .\scextract.py .\decompiled.txt
unsigned char shellcode[] =
"\x40\x53\x48\x83\xEC\x30\x65\x48\x8B\x04\x25\x60\x00\x00\x00"
"\x33\xDB\x48\x8B\x48\x18\x48\x8B\x41\x20\x48\x8B\x08\x48\x8B"
"\x01\x4C\x8B\x40\x20\x49\x63\x40\x3C\x42\x8B\x8C\x00\x......";

```
